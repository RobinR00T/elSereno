//go:build offensive

package harvest

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPBasicProber walks RFC 7617 (HTTP Basic Authentication) against
// a given URL. If the first unauthenticated GET returns 401 with a
// `WWW-Authenticate: Basic` header, it tries each credential until
// one produces a non-401 response.
type HTTPBasicProber struct {
	Path        string // URL path to probe; default "/"
	DialTimeout time.Duration
	IOTimeout   time.Duration
	Scheme      string // "http" or "https"; default "http"
}

// NewHTTPBasic returns a prober with "/" + http + conservative
// timeouts.
func NewHTTPBasic() *HTTPBasicProber {
	return &HTTPBasicProber{
		Path:        "/",
		Scheme:      "http",
		DialTimeout: 5 * time.Second,
		IOTimeout:   3 * time.Second,
	}
}

// Name implements Prober.
func (h *HTTPBasicProber) Name() string { return "http-basic" }

// DefaultPort implements Prober.
func (h *HTTPBasicProber) DefaultPort() uint16 { return 80 }

// Probe implements Prober.
func (h *HTTPBasicProber) Probe(ctx context.Context, target string, creds []Credential) (*Result, error) {
	base := fmt.Sprintf("%s://%s%s", h.Scheme, target, h.Path)
	client := &http.Client{Timeout: h.DialTimeout + h.IOTimeout}
	// Probe once without credentials to confirm Basic is expected.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		// No auth challenge; nothing to harvest.
		return nil, ErrNoHit
	}
	www := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(strings.ToLower(www), "basic") {
		return nil, ErrNoHit
	}
	// Try each credential.
	for _, c := range creds {
		if c.Username == "" {
			continue
		}
		ok, err := h.attempt(ctx, client, base, c)
		if err != nil {
			continue
		}
		if ok {
			return &Result{
				Protocol:   h.Name(),
				Target:     target,
				Credential: c,
				Banner:     www,
				At:         time.Now().UTC().Truncate(time.Microsecond),
			}, nil
		}
	}
	return nil, ErrNoHit
}

func (h *HTTPBasicProber) attempt(ctx context.Context, client *http.Client, url string, c Credential) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400, nil
}
