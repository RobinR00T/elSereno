// Package httpclient builds the HTTP client the input providers
// (Shodan, Censys, FOFA, ZoomEye, ONYPHE, BinaryEdge, InternetDB)
// share. They send their API key in a header or query, and Go's client
// strips only a few sensitive headers (Authorization, Cookie, Cookie2,
// WWW-Authenticate) on a cross-host redirect, never a provider's own
// X-Key or API-KEY: a 302 to another host (from the provider or a
// hijacked DNS answer), or a downgrade to http on the same host, would
// resend the key. This client refuses a redirect that changes the host,
// the port or the scheme, so the key never leaves the authority the
// operator configured, nor its TLS (PITF-097).
package httpclient

import (
	"fmt"
	"net/http"
	"time"
)

// New returns an *http.Client with the given timeout that refuses a
// redirect whose host, port or scheme differs from the first request. A
// redirect that keeps all three is followed, up to the usual 10 hops.
func New(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: refuseHostChange,
	}
}

func refuseHostChange(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if req.URL.Host != via[0].URL.Host {
		return fmt.Errorf("input: refusing redirect to another host %q (the API key would follow)", req.URL.Host)
	}
	if req.URL.Scheme != via[0].URL.Scheme {
		return fmt.Errorf("input: refusing redirect that changes scheme to %q (the API key would travel in clear)", req.URL.Scheme)
	}
	if len(via) >= 10 {
		return http.ErrUseLastResponse
	}
	return nil
}
