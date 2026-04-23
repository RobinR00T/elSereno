package zoomeye

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/time/rate"

	"local/elsereno/internal/core"
)

// DefaultBaseURL is the ZoomEye API endpoint. Override via
// Client.BaseURL for tests (httptest.NewServer).
const DefaultBaseURL = "https://api.zoomeye.org"

// ErrNoAPIKey is returned when APIKey is empty. Unlike FOFA,
// ZoomEye only needs one credential (the API key / JWT token).
// CLI surfaces this with a hint pointing at `elsereno creds
// store zoomeye`.
var ErrNoAPIKey = errors.New("zoomeye: no API key configured")

// Client is a minimal ZoomEye REST client for the host-search
// endpoint. Scope matches the Shodan / FOFA clients — (ip,
// port) tuples only.
type Client struct {
	APIKey  string
	BaseURL string
	HTTP    *http.Client
	Limiter *rate.Limiter
}

// New constructs a Client from an API key. ratePerSec of 0
// disables rate limiting. ZoomEye's free tier is limited to a
// few thousand credits per month; callers SHOULD cap their
// request rate to avoid burning the monthly quota in a single
// scan.
func New(apiKey string, ratePerSec int) (*Client, error) {
	if apiKey == "" {
		return nil, ErrNoAPIKey
	}
	c := &Client{
		APIKey:  apiKey,
		BaseURL: DefaultBaseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
	if ratePerSec > 0 {
		c.Limiter = rate.NewLimiter(rate.Limit(ratePerSec), ratePerSec)
	}
	return c, nil
}

// PortInfo is the nested object inside each host-search match.
// ZoomEye nests the port there (not as a top-level field).
type PortInfo struct {
	Port int `json:"port"`
}

// SearchMatch is the subset of `matches[]` fields the scanner
// consumes. ZoomEye returns much more (app, os, banner, geoinfo,
// ssl) that we can surface in higher-level UX later.
type SearchMatch struct {
	IP       string   `json:"ip"`
	PortInfo PortInfo `json:"portinfo"`
}

// SearchResponse is the envelope.
type SearchResponse struct {
	Total   int           `json:"total"`
	Matches []SearchMatch `json:"matches"`
}

// Search calls /host/search and returns up to `size` parsed
// hits. `page` is 1-based (ZoomEye convention). Callers wanting
// multiple pages make repeated calls with page=1, 2, 3…
func (c *Client) Search(ctx context.Context, query string, page int) ([]core.Target, error) {
	if c.Limiter != nil {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if page <= 0 {
		page = 1
	}
	q := url.Values{}
	q.Set("query", query)
	q.Set("page", strconv.Itoa(page))

	u := fmt.Sprintf("%s/host/search?%s", c.BaseURL, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("zoomeye: request: %w", err)
	}
	// ZoomEye accepts both `API-KEY: <k>` (personal key) and
	// `Authorization: JWT <token>` (OAuth flow). We use the
	// simpler personal-key header — operators who want JWT can
	// override via Client.HTTP.Transport.
	req.Header.Set("API-KEY", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zoomeye: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zoomeye: status %d", resp.StatusCode)
	}

	var parsed SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("zoomeye: decode: %w", err)
	}
	return mapMatches(parsed.Matches), nil
}

// mapMatches converts ZoomEye matches to core.Target values.
// Matches whose IP or port is unparseable are skipped silently.
func mapMatches(matches []SearchMatch) []core.Target {
	out := make([]core.Target, 0, len(matches))
	for _, m := range matches {
		addr, err := netip.ParseAddr(m.IP)
		if err != nil {
			continue
		}
		port, err := core.NewPort(m.PortInfo.Port)
		if err != nil {
			continue
		}
		out = append(out, core.Target{Address: addr, Port: port})
	}
	return out
}
