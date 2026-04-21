// Package httpctx centralises the request-scoped values shared
// between middleware and handlers. Keeping the keys private to a
// single package prevents accidental collisions and makes each
// value's lifecycle explicit.
package httpctx

import "context"

// cspNonceKey is the unexported context key used to ferry the
// per-request CSP nonce from the middleware (which generates it +
// emits the Content-Security-Policy header) down to handlers or
// templates that need to embed inline <script nonce=...> tags.
type cspNonceKey struct{}

// WithCSPNonce returns ctx annotated with the given CSP nonce.
// Callers of CSPNonce will receive this value on hit.
func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	if nonce == "" {
		return ctx
	}
	return context.WithValue(ctx, cspNonceKey{}, nonce)
}

// CSPNonce returns the nonce previously installed by
// WithCSPNonce, or "" if none. Handlers that omit the nonce simply
// won't be able to run inline scripts/styles — exactly the safe
// default behaviour we want.
func CSPNonce(ctx context.Context) string {
	v, _ := ctx.Value(cspNonceKey{}).(string)
	return v
}
