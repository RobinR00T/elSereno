package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Verifier is the per-deployment auth verifier. Created once at
// serve startup, shared across all middleware. Thread-safe.
type Verifier struct {
	cfg   ValidatorConfig
	cache *JWKSCache
	// Now is a test seam. Defaults to time.Now().UTC().
	Now func() time.Time
}

// NewVerifier wires the JWKS cache + validator config. When
// jwksURL is empty → Verifier is in "back-compat" mode: every
// validation returns nil claims, callers fall through to
// X-Operator.
func NewVerifier(issuer, audience, jwksURL string) *Verifier {
	v := &Verifier{
		cfg: ValidatorConfig{
			Issuer:    issuer,
			Audience:  audience,
			ClockSkew: 60 * time.Second,
		},
	}
	if jwksURL != "" {
		v.cache = NewJWKSCache(jwksURL, 0)
	}
	return v
}

// Enabled reports whether OIDC enforcement is active. False
// means the middleware passes through.
func (v *Verifier) Enabled() bool {
	return v.cache != nil
}

// VerifyToken parses + validates a bearer token. Returns the
// Claims or an error suitable for the middleware to translate
// into 401.
func (v *Verifier) VerifyToken(ctx context.Context, token string) (*Claims, error) {
	if v.cache == nil {
		return nil, errors.New("auth: verifier not configured (jwks URL missing)")
	}
	keys, err := v.cache.Keys(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: jwks: %w", err)
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now()
	}
	claims, err := Validate(token, keys, v.cfg, now)
	if err == nil {
		return claims, nil
	}
	// Unknown KID may mean the IdP rotated keys after the
	// cache last refreshed — force a refresh + retry once.
	if errors.Is(err, ErrJWTUnknownKey) {
		keys, refreshErr := v.cache.Refresh(ctx)
		if refreshErr != nil {
			return nil, fmt.Errorf("auth: jwks refresh after unknown kid: %w", refreshErr)
		}
		return Validate(token, keys, v.cfg, now)
	}
	return nil, err
}

// ctxKey unexported so external code can't shadow.
type ctxKey int

const (
	ctxClaims ctxKey = iota
	ctxRole
	ctxOperator
)

// WithClaims stashes Claims into ctx for downstream handlers.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxClaims, c)
}

// ClaimsFromContext retrieves the bound claims, or nil if
// missing (back-compat / dev mode).
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxClaims).(*Claims)
	return c
}

// WithRole stashes the resolved role into ctx.
func WithRole(ctx context.Context, r Role) context.Context {
	return context.WithValue(ctx, ctxRole, r)
}

// RoleFromContext retrieves the bound role; RoleUnknown if
// missing.
func RoleFromContext(ctx context.Context) Role {
	r, _ := ctx.Value(ctxRole).(Role)
	return r
}

// WithOperator stashes the resolved operator identity (email or
// sub) into ctx.
func WithOperator(ctx context.Context, op string) context.Context {
	return context.WithValue(ctx, ctxOperator, op)
}

// OperatorFromContext returns the stashed operator string, or
// empty.
func OperatorFromContext(ctx context.Context) string {
	op, _ := ctx.Value(ctxOperator).(string)
	return op
}

// RequireRole wraps a handler with bearer-token validation +
// role check. When the Verifier is not enabled (back-compat),
// requests pass through with role = RoleUnknown — downstream
// can fall back to X-Operator.
//
// On enforcement:
//   - Missing/malformed Authorization header → 401.
//   - Token invalid (sig/exp/iss/aud) → 401.
//   - Role insufficient → 403.
//   - OK → handler invoked with ctx carrying Claims + Role +
//     Operator.
func (v *Verifier) RequireRole(required Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Back-compat: no JWKS → no enforcement.
		if !v.Enabled() {
			next.ServeHTTP(w, r)
			return
		}
		token := extractBearerToken(r)
		if token == "" {
			writeAuthError(w, http.StatusUnauthorized,
				"missing bearer token")
			return
		}
		claims, err := v.VerifyToken(r.Context(), token)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized,
				"token validation failed: "+err.Error())
			return
		}
		role := resolveRole(claims)
		if !role.Implies(required) {
			writeAuthError(w, http.StatusForbidden,
				fmt.Sprintf("role %s insufficient; required %s", role, required))
			return
		}
		ctx := WithClaims(r.Context(), claims)
		ctx = WithRole(ctx, role)
		ctx = WithOperator(ctx, pickOperator(claims))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractBearerToken pulls the token from the standard
// `Authorization: Bearer <token>` header. Returns empty when
// missing or malformed.
func extractBearerToken(r *http.Request) string {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(hdr, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(hdr, prefix))
}

// resolveRole walks all role-bearing claims + returns the
// highest rank.
func resolveRole(c *Claims) Role {
	all := make([]string, 0, len(c.Roles)+len(c.Groups)+len(c.NamespacedRoles)+len(c.NamespacedGroups))
	all = append(all, c.Roles...)
	all = append(all, c.Groups...)
	all = append(all, c.NamespacedRoles...)
	all = append(all, c.NamespacedGroups...)
	return HighestRoleFromClaims(all)
}

// pickOperator picks email > sub for the operator-identity
// stash. Used by audit chain entries instead of X-Operator
// when OIDC is enforced.
func pickOperator(c *Claims) string {
	if c.Email != "" {
		return c.Email
	}
	return c.Sub
}

// writeAuthError writes a stable JSON error envelope so the
// dashboard can render a friendly message + the API gives a
// predictable shape. json.Marshal handles all escaping —
// preferred over Sprintf to keep gosec G705 happy and to
// guarantee a valid JSON shape even if `msg` ever included
// quotes / control chars.
func writeAuthError(w http.ResponseWriter, status int, msg string) {
	body, mErr := json.Marshal(map[string]any{
		"error":  msg,
		"status": status,
	})
	if mErr != nil {
		body = []byte(`{"error":"internal","status":500}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
	_, _ = w.Write([]byte("\n"))
}
