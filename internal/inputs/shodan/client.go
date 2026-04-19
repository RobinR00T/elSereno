package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"golang.org/x/time/rate"

	"local/elsereno/internal/core"
)

// DefaultBaseURL is the Shodan API endpoint. Override via
// Client.BaseURL for tests.
const DefaultBaseURL = "https://api.shodan.io"

// ErrNoAPIKey is returned by New when APIKey is empty. The CLI
// surfaces this with a hint pointing at `elsereno creds store shodan`.
var ErrNoAPIKey = errors.New("shodan: no API key configured")

// Client is a minimal Shodan REST client for the search API. Scope is
// limited to what F1 chunk 2 needs (host search); advanced endpoints
// arrive when the CLI verbs are wired.
type Client struct {
	APIKey  string
	BaseURL string
	HTTP    *http.Client
	Limiter *rate.Limiter
}

// New constructs a Client from an API key and an optional per-second
// rate limit (0 means no limit). Shodan's paid tier allows 1 rps by
// default; calling code SHOULD set a reasonable limit to avoid 429s.
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

// SearchHit is the subset of /shodan/host/search response fields we
// consume. Shodan returns much more; we keep the surface tight so
// future schema drift is a PR, not a silent bug.
type SearchHit struct {
	IP   string `json:"ip_str"`
	Port int    `json:"port"`
	ASN  string `json:"asn,omitempty"`
}

// SearchResponse is the full response envelope.
type SearchResponse struct {
	Total   int         `json:"total"`
	Matches []SearchHit `json:"matches"`
}

// Search calls /shodan/host/search and returns up to `limit` parsed
// hits. The API key is passed as a query parameter, which Shodan
// mandates; the secure transport is HTTPS so the value is encrypted
// on the wire (PITF-016 applies to argv/shell, not to TLS-protected
// query strings).
func (c *Client) Search(ctx context.Context, query string, limit int) ([]core.Target, error) {
	if c.Limiter != nil {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if limit <= 0 {
		limit = 100
	}
	q := url.Values{}
	q.Set("key", c.APIKey)
	q.Set("query", query)
	q.Set("limit", fmt.Sprintf("%d", limit))

	u := fmt.Sprintf("%s/shodan/host/search?%s", c.BaseURL, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("shodan: request: %w", err)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan: status %d", resp.StatusCode)
	}

	var parsed SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("shodan: decode: %w", err)
	}

	return mapHits(parsed.Matches), nil
}

// mapHits converts Shodan hits to core.Target values, skipping
// entries whose IP or port cannot be parsed.
func mapHits(hits []SearchHit) []core.Target {
	out := make([]core.Target, 0, len(hits))
	for _, h := range hits {
		addr, err := netip.ParseAddr(h.IP)
		if err != nil {
			continue
		}
		port, err := core.NewPort(h.Port)
		if err != nil {
			continue
		}
		out = append(out, core.Target{Address: addr, Port: port})
	}
	return out
}
