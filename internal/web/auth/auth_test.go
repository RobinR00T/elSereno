package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/web/auth"
)

// genKey + sign helpers — produce RS256-signed JWTs we can
// validate against a synthesised JWKS in the same test.

func genKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	return k, "kid-test-1"
}

func b64u(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// signRS256 builds a JWT signed with the provided private key.
// header.alg = RS256, header.kid = kid.
func signRS256(t *testing.T, k *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdrBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payBytes, _ := json.Marshal(claims)
	signingInput := b64u(hdrBytes) + "." + b64u(payBytes)
	h := sha256.New()
	h.Write([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + b64u(sig)
}

// jwksHandler serves a JWKS with the given kid + public key.
func jwksHandler(k *rsa.PublicKey, kid string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": kid,
					"n":   b64u(k.N.Bytes()),
					"e":   b64u(big.NewInt(int64(k.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
}

// ----- Role tests -----

func TestParseRole_Variants(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want auth.Role
	}{
		{"admin", auth.RoleAdmin},
		{"ADMIN", auth.RoleAdmin},
		{"administrator", auth.RoleAdmin},
		{"  operator  ", auth.RoleOperator},
		{"scanner", auth.RoleOperator},
		{"reader", auth.RoleViewer},
		{"random-junk", auth.RoleUnknown},
		{"", auth.RoleUnknown},
	} {
		if got := auth.ParseRole(tc.in); got != tc.want {
			t.Errorf("ParseRole(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestRoleImplies(t *testing.T) {
	if !auth.RoleAdmin.Implies(auth.RoleViewer) {
		t.Error("admin should imply viewer")
	}
	if !auth.RoleAdmin.Implies(auth.RoleAdmin) {
		t.Error("admin should imply admin (self)")
	}
	if auth.RoleViewer.Implies(auth.RoleAdmin) {
		t.Error("viewer should NOT imply admin")
	}
}

func TestHighestRoleFromClaims(t *testing.T) {
	got := auth.HighestRoleFromClaims([]string{"viewer", "admin", "operator"})
	if got != auth.RoleAdmin {
		t.Errorf("highest = %v, want admin", got)
	}
}

// ----- JWT validation tests -----

func TestValidate_HappyPath(t *testing.T) {
	k, kid := genKey(t)
	claims := map[string]any{
		"iss":   "https://idp.example",
		"aud":   "elsereno",
		"sub":   "alice@example",
		"email": "alice@example",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"roles": []string{"operator"},
	}
	tok := signRS256(t, k, kid, claims)
	keys := map[string]any{kid: &k.PublicKey}
	cfg := auth.ValidatorConfig{Issuer: "https://idp.example", Audience: "elsereno"}
	got, err := auth.Validate(tok, keys, cfg, time.Now())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.Sub != "alice@example" {
		t.Errorf("sub = %q", got.Sub)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "operator" {
		t.Errorf("roles = %v", got.Roles)
	}
}

func TestValidate_RejectsExpired(t *testing.T) {
	k, kid := genKey(t)
	claims := map[string]any{
		"iss": "https://idp.example",
		"aud": "elsereno",
		"exp": time.Now().Add(-time.Hour).Unix(), // 1h ago
	}
	tok := signRS256(t, k, kid, claims)
	keys := map[string]any{kid: &k.PublicKey}
	cfg := auth.ValidatorConfig{Issuer: "https://idp.example", Audience: "elsereno"}
	_, err := auth.Validate(tok, keys, cfg, time.Now())
	if !errors.Is(err, auth.ErrJWTExpired) {
		t.Errorf("err = %v, want ErrJWTExpired", err)
	}
}

func TestValidate_RejectsAudMismatch(t *testing.T) {
	k, kid := genKey(t)
	claims := map[string]any{
		"iss": "https://idp.example",
		"aud": "OTHER",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := signRS256(t, k, kid, claims)
	keys := map[string]any{kid: &k.PublicKey}
	cfg := auth.ValidatorConfig{Issuer: "https://idp.example", Audience: "elsereno"}
	_, err := auth.Validate(tok, keys, cfg, time.Now())
	if !errors.Is(err, auth.ErrJWTAudienceMissing) {
		t.Errorf("err = %v, want ErrJWTAudienceMissing", err)
	}
}

func TestValidate_RejectsAlgNone(t *testing.T) {
	// Manually craft a `none`-alg token.
	hdr := b64u([]byte(`{"alg":"none","kid":"x"}`))
	pay := b64u([]byte(`{"sub":"alice","exp":9999999999}`))
	tok := hdr + "." + pay + "."
	_, err := auth.Validate(tok, map[string]any{}, auth.ValidatorConfig{}, time.Now())
	if !errors.Is(err, auth.ErrJWTUnsupportedAlg) {
		t.Errorf("err = %v, want ErrJWTUnsupportedAlg", err)
	}
}

func TestValidate_RejectsBadSignature(t *testing.T) {
	k, kid := genKey(t)
	tok := signRS256(t, k, kid, map[string]any{
		"iss": "https://idp.example",
		"aud": "elsereno",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	// Generate a DIFFERENT key for verification.
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]any{kid: &k2.PublicKey}
	cfg := auth.ValidatorConfig{Issuer: "https://idp.example", Audience: "elsereno"}
	_, err := auth.Validate(tok, keys, cfg, time.Now())
	if !errors.Is(err, auth.ErrJWTBadSignature) {
		t.Errorf("err = %v, want ErrJWTBadSignature", err)
	}
}

// ----- JWKS cache tests -----

func TestJWKSCache_Fetches(t *testing.T) {
	k, _ := genKey(t)
	srv := httptest.NewServer(jwksHandler(&k.PublicKey, "test-kid"))
	defer srv.Close()
	cache := auth.NewJWKSCache(srv.URL, time.Minute)
	keys, err := cache.Keys(context.Background())
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if _, ok := keys["test-kid"]; !ok {
		t.Errorf("missing test-kid in fetched keys: %v", keys)
	}
}

func TestJWKSCache_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cache := auth.NewJWKSCache(srv.URL, time.Minute)
	_, err := cache.Keys(context.Background())
	if err == nil || !strings.Contains(err.Error(), "jwks") {
		t.Errorf("err = %v, want JWKS fetch error", err)
	}
}

// ----- Middleware integration test -----

func TestVerifier_RequireRole_BackCompatMode(t *testing.T) {
	// No JWKS URL → enforcement disabled → all requests pass.
	v := auth.NewVerifier("", "", "")
	called := false
	handler := v.RequireRole(auth.RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if !called {
		t.Error("downstream handler not invoked in back-compat mode")
	}
}

func TestVerifier_RequireRole_HappyPath(t *testing.T) {
	k, kid := genKey(t)
	srv := httptest.NewServer(jwksHandler(&k.PublicKey, kid))
	defer srv.Close()
	v := auth.NewVerifier("https://idp.example", "elsereno", srv.URL)
	tok := signRS256(t, k, kid, map[string]any{
		"iss":   "https://idp.example",
		"aud":   "elsereno",
		"sub":   "alice@example",
		"email": "alice@example",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"roles": []string{"operator"},
	})
	called := false
	var gotRole auth.Role
	var gotOp string
	handler := v.RequireRole(auth.RoleOperator, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		gotRole = auth.RoleFromContext(r.Context())
		gotOp = auth.OperatorFromContext(r.Context())
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if !called {
		t.Error("handler not invoked despite valid token")
	}
	if gotRole != auth.RoleOperator {
		t.Errorf("role = %v, want operator", gotRole)
	}
	if gotOp != "alice@example" {
		t.Errorf("operator = %q, want alice@example", gotOp)
	}
}

func TestVerifier_RequireRole_InsufficientRole(t *testing.T) {
	k, kid := genKey(t)
	srv := httptest.NewServer(jwksHandler(&k.PublicKey, kid))
	defer srv.Close()
	v := auth.NewVerifier("https://idp.example", "elsereno", srv.URL)
	tok := signRS256(t, k, kid, map[string]any{
		"iss":   "https://idp.example",
		"aud":   "elsereno",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"roles": []string{"viewer"},
	})
	handler := v.RequireRole(auth.RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestVerifier_RequireRole_MissingToken(t *testing.T) {
	k, kid := genKey(t)
	srv := httptest.NewServer(jwksHandler(&k.PublicKey, kid))
	defer srv.Close()
	v := auth.NewVerifier("https://idp.example", "elsereno", srv.URL)
	handler := v.RequireRole(auth.RoleViewer, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// Silence "unused" warnings for stdlib err sentinel imports in
// case Go version differs.
var _ = fmt.Sprintf
