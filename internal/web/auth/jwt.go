package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Stdlib-only JWT (RFC 7519) validator. Supports:
//
//   - RS256 / RS384 / RS512 (RSA + SHA-256/384/512).
//   - ES256 / ES384 / ES512 (ECDSA + same hashes).
//
// Symmetric (HS*) algorithms are deliberately NOT supported —
// they require a shared secret on the resource server, which is
// not the OIDC bearer-token model.

// JWT-validation errors.
var (
	ErrJWTMalformed       = errors.New("auth: jwt malformed")
	ErrJWTUnsupportedAlg  = errors.New("auth: jwt unsupported algorithm")
	ErrJWTMissingKID      = errors.New("auth: jwt header missing kid")
	ErrJWTUnknownKey      = errors.New("auth: jwks lacks kid referenced by jwt")
	ErrJWTBadSignature    = errors.New("auth: jwt signature invalid")
	ErrJWTExpired         = errors.New("auth: jwt expired")
	ErrJWTNotYetValid     = errors.New("auth: jwt not yet valid (nbf in future)")
	ErrJWTMissingExp      = errors.New("auth: jwt missing exp claim")
	ErrJWTIssuerMismatch  = errors.New("auth: jwt issuer mismatch")
	ErrJWTAudienceMissing = errors.New("auth: jwt audience missing")
)

// Header is the JOSE header. We only consume alg + kid.
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Claims is the subset of registered + namespaced claims we
// care about. Decoding is lenient — extra fields are ignored.
type Claims struct {
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Aud   AudClaim `json:"aud"`
	Exp   int64    `json:"exp"`
	Nbf   int64    `json:"nbf"`
	Iat   int64    `json:"iat"`
	Email string   `json:"email"`
	// Roles claim variants. Different IdPs use different fields;
	// we union them all + take the highest-rank role found.
	Roles                []string `json:"roles"`
	Groups               []string `json:"groups"`
	NamespacedRoles      []string `json:"https://elsereno/roles"`
	NamespacedGroups     []string `json:"https://elsereno/groups"`
	RawClaimsForFallback any      `json:"-"` // populated by Validate when needed
}

// AudClaim normalises the spec's "string or string array" aud
// claim. JSON tolerates both shapes; downstream sees a slice.
type AudClaim []string

// UnmarshalJSON accepts either `"foo"` or `["foo","bar"]`.
func (a *AudClaim) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*a = []string{s}
		return nil
	}
	var s []string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*a = s
	return nil
}

// Validate parses the JWT, looks up the signing key in `keys`,
// verifies the signature, and enforces standard claim checks
// (exp/nbf/iss/aud) against `cfg`.
//
// `now` is a test seam; pass time.Now().UTC() in production.
// `cfg.ClockSkew` defaults to 60s when zero.
func Validate(tok string, keys map[string]any, cfg ValidatorConfig, now time.Time) (*Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 parts, got %d", ErrJWTMalformed, len(parts))
	}
	hdrBytes, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header decode: %w", ErrJWTMalformed, err)
	}
	var hdr Header
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header parse: %w", ErrJWTMalformed, err)
	}
	if hdr.Alg == "none" || hdr.Alg == "" {
		return nil, fmt.Errorf("%w: alg=%q", ErrJWTUnsupportedAlg, hdr.Alg)
	}
	if hdr.Kid == "" {
		return nil, ErrJWTMissingKID
	}
	key, ok := keys[hdr.Kid]
	if !ok {
		return nil, fmt.Errorf("%w: kid=%q", ErrJWTUnknownKey, hdr.Kid)
	}
	// Signature material is the literal header + "." + payload
	// from the original token (no re-encoding).
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature decode: %w", ErrJWTMalformed, err)
	}
	if err := verifySignature(hdr.Alg, key, []byte(signingInput), sigBytes); err != nil {
		return nil, err
	}
	// Signature good — decode + check claims.
	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload decode: %w", ErrJWTMalformed, err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload parse: %w", ErrJWTMalformed, err)
	}
	if err := checkClaims(&claims, cfg, now); err != nil {
		return nil, err
	}
	return &claims, nil
}

// decodeSegment unbases64-urls a JWT segment. RFC 7515 says
// raw-unpadded but real-world tokens sometimes include padding;
// we handle both via base64.RawURLEncoding + a manual padding
// strip.
func decodeSegment(s string) ([]byte, error) {
	// Trim '=' padding if any (RawURLEncoding wants none).
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// verifySignature dispatches based on header alg. Returns nil
// when the signature checks out.
func verifySignature(alg string, key any, signingInput, sig []byte) error {
	switch alg {
	case "RS256":
		return verifyRSA(key, crypto.SHA256, signingInput, sig)
	case "RS384":
		return verifyRSA(key, crypto.SHA384, signingInput, sig)
	case "RS512":
		return verifyRSA(key, crypto.SHA512, signingInput, sig)
	case "ES256":
		return verifyECDSA(key, crypto.SHA256, signingInput, sig)
	case "ES384":
		return verifyECDSA(key, crypto.SHA384, signingInput, sig)
	case "ES512":
		return verifyECDSA(key, crypto.SHA512, signingInput, sig)
	default:
		return fmt.Errorf("%w: alg=%q", ErrJWTUnsupportedAlg, alg)
	}
}

func verifyRSA(key any, hash crypto.Hash, signingInput, sig []byte) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: kid points to non-RSA key", ErrJWTBadSignature)
	}
	h := newHasher(hash)
	h.Write(signingInput)
	if err := rsa.VerifyPKCS1v15(pub, hash, h.Sum(nil), sig); err != nil {
		return fmt.Errorf("%w: %w", ErrJWTBadSignature, err)
	}
	return nil
}

func verifyECDSA(key any, hash crypto.Hash, signingInput, sig []byte) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: kid points to non-ECDSA key", ErrJWTBadSignature)
	}
	if len(sig)%2 != 0 || len(sig) < 64 {
		return fmt.Errorf("%w: ecdsa signature wrong length %d", ErrJWTBadSignature, len(sig))
	}
	r := new(big.Int).SetBytes(sig[:len(sig)/2])
	s := new(big.Int).SetBytes(sig[len(sig)/2:])
	h := newHasher(hash)
	h.Write(signingInput)
	if !ecdsa.Verify(pub, h.Sum(nil), r, s) {
		return ErrJWTBadSignature
	}
	return nil
}

// hasher wraps a crypto.Hash to keep the verify* functions
// readable.
type hasher struct {
	h crypto.Hash
	d interface {
		Write(p []byte) (int, error)
		Sum(b []byte) []byte
	}
}

func newHasher(h crypto.Hash) *hasher {
	var d interface {
		Write(p []byte) (int, error)
		Sum(b []byte) []byte
	}
	switch h { //nolint:exhaustive // covered subset; others rejected by verifySignature dispatch.
	case crypto.SHA256:
		d = sha256.New()
	case crypto.SHA384:
		d = sha512.New384()
	case crypto.SHA512:
		d = sha512.New()
	}
	return &hasher{h: h, d: d}
}

func (h *hasher) Write(p []byte)      { _, _ = h.d.Write(p) }
func (h *hasher) Sum(b []byte) []byte { return h.d.Sum(b) }

// checkClaims enforces the standard claim invariants.
// cfg.SkipExp and similar fields are NOT exposed — production
// validators always check exp. Test seams pass via `now`.
func checkClaims(c *Claims, cfg ValidatorConfig, now time.Time) error {
	if cfg.Issuer != "" && c.Iss != cfg.Issuer {
		return fmt.Errorf("%w: got %q want %q", ErrJWTIssuerMismatch, c.Iss, cfg.Issuer)
	}
	if cfg.Audience != "" {
		found := false
		for _, a := range c.Aud {
			if a == cfg.Audience {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: want %q", ErrJWTAudienceMissing, cfg.Audience)
		}
	}
	if c.Exp == 0 {
		return ErrJWTMissingExp
	}
	skew := cfg.ClockSkew
	if skew == 0 {
		skew = 60 * time.Second
	}
	expT := time.Unix(c.Exp, 0)
	if now.After(expT.Add(skew)) {
		return ErrJWTExpired
	}
	if c.Nbf != 0 {
		nbfT := time.Unix(c.Nbf, 0)
		if now.Before(nbfT.Add(-skew)) {
			return ErrJWTNotYetValid
		}
	}
	return nil
}

// ValidatorConfig is the cross-call config passed to Validate.
type ValidatorConfig struct {
	Issuer    string
	Audience  string
	ClockSkew time.Duration
}
