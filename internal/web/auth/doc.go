// Package auth implements OIDC bearer-token validation with
// roles-based access control for the v2.38+ web layer.
//
// Design overview:
//
//   - Stdlib-only: no third-party JWT/OIDC library. crypto/rsa
//
//   - crypto/ecdsa + encoding/base64 + encoding/json are
//     enough for RS256 / ES256 signature verification + claim
//     parsing. We deliberately don't support symmetric (HS*)
//     algorithms — bearer tokens minted by an IdP must be
//     verifiable without a shared secret on the resource server.
//
//   - JWKS fetched + cached with a TTL. New keys discovered
//     automatically on cache miss. Stale keys never used.
//
//   - 3-role model (viewer < operator < admin) mapped from
//     either:
//
//   - a `roles` claim (string array) in the JWT, or
//
//   - a `groups` claim if the IdP uses LDAP-style groups, or
//
//   - an `https://elsereno/roles` namespaced claim
//     (Auth0 / Okta convention for non-standard claims).
//
//   - Back-compat: when no OIDC issuer is configured, the
//     middleware falls through to the v1.58 X-Operator header.
//     This preserves dev-mode workflows + the existing test
//     suite.
//
//   - Middleware composes via http.Handler wrapping. Each
//     endpoint declares its minimum role via RequireRole(); the
//     middleware short-circuits with 401 (missing/invalid
//     token) or 403 (insufficient role).
//
// Defensive defaults:
//
//   - Reject `none` alg unconditionally.
//   - Reject tokens with no `exp` claim.
//   - Reject tokens whose `aud` doesn't match the configured
//     audience.
//   - Reject tokens whose `iss` doesn't match the configured
//     issuer.
//   - Clock skew tolerance is 60 seconds; configurable per
//     deployment if needed.
//
// Not implemented in v2.38:
//   - Refresh-token flow. The resource server only validates.
//     Code/refresh flow lives in the IdP + the dashboard UI
//     (vNext).
//   - Token revocation lists. RFC 7009 deferred.
//   - mTLS or DPoP. The bearer-token model is enough for the
//     OT-network use case (intranet + IdP-issued tokens).
package auth
