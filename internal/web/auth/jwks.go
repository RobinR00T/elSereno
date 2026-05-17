package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWKS-fetch errors.
var (
	ErrJWKSFetch          = errors.New("auth: jwks fetch failed")
	ErrJWKSDecode         = errors.New("auth: jwks decode failed")
	ErrJWKSUnsupportedKty = errors.New("auth: jwks key type unsupported")
	ErrJWKSBadParams      = errors.New("auth: jwks key parameter invalid")
)

// JWKSCache caches parsed JWKS keys with a TTL. Concurrency-
// safe. Refresh on demand (next request after expiry triggers
// the re-fetch).
type JWKSCache struct {
	URL    string
	TTL    time.Duration
	Client *http.Client

	mu       sync.RWMutex
	keys     map[string]any
	loadedAt time.Time
}

// DefaultJWKSCacheTTL is 15 minutes — a balance between key-
// rotation freshness + not hammering the IdP's JWKS endpoint.
const DefaultJWKSCacheTTL = 15 * time.Minute

// NewJWKSCache constructs a cache. ttl=0 → DefaultJWKSCacheTTL.
// client=nil → http.DefaultClient with 5s timeout.
func NewJWKSCache(url string, ttl time.Duration) *JWKSCache {
	if ttl == 0 {
		ttl = DefaultJWKSCacheTTL
	}
	return &JWKSCache{
		URL:    url,
		TTL:    ttl,
		Client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Keys returns the kid → public-key map, refreshing if the
// cache has expired. Concurrent callers during refresh: the
// first wins; others get the just-refreshed map.
func (c *JWKSCache) Keys(ctx context.Context) (map[string]any, error) {
	c.mu.RLock()
	if c.keys != nil && time.Since(c.loadedAt) < c.TTL {
		out := c.keys
		c.mu.RUnlock()
		return out, nil
	}
	c.mu.RUnlock()
	return c.refresh(ctx)
}

// Refresh forces an immediate fetch — useful when a JWT
// validation fails with ErrJWTUnknownKey (IdP may have rotated
// keys mid-cache-window).
func (c *JWKSCache) Refresh(ctx context.Context) (map[string]any, error) {
	return c.refresh(ctx)
}

func (c *JWKSCache) refresh(ctx context.Context) (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check after lock — another goroutine may have
	// refreshed while we waited.
	if c.keys != nil && time.Since(c.loadedAt) < c.TTL {
		return c.keys, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrJWKSFetch, err)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrJWKSFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrJWKSFetch, err)
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return nil, err
	}
	c.keys = keys
	c.loadedAt = time.Now()
	return keys, nil
}

// ParseJWKS decodes a JSON Web Key Set body into a kid →
// public-key map. Supports RSA (kty=RSA) + EC (kty=EC; P-256 /
// P-384 / P-521 curves).
func ParseJWKS(body []byte) (map[string]any, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSDecode, err)
	}
	out := make(map[string]any, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kid == "" {
			continue // skip unkid keys; we need kid for lookup
		}
		switch k.Kty {
		case "RSA":
			pub, err := parseRSAJWK(k.N, k.E)
			if err != nil {
				return nil, fmt.Errorf("%w: kid=%q: %w", ErrJWKSBadParams, k.Kid, err)
			}
			out[k.Kid] = pub
		case "EC":
			pub, err := parseECJWK(k.Crv, k.X, k.Y)
			if err != nil {
				return nil, fmt.Errorf("%w: kid=%q: %w", ErrJWKSBadParams, k.Kid, err)
			}
			out[k.Kid] = pub
		default:
			return nil, fmt.Errorf("%w: kid=%q kty=%q", ErrJWKSUnsupportedKty, k.Kid, k.Kty)
		}
	}
	return out, nil
}

func parseRSAJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("n decode: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("e decode: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("e exceeds int64")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func parseECJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q", crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("x decode: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("y decode: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
