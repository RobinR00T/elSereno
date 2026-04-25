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
	if limit <= 0 {
		limit = 100
	}
	return c.searchPage(ctx, query, 1, limit)
}

// SearchPaged calls /shodan/host/search repeatedly, accumulating up
// to totalLimit hits across multiple pages. v1.12 chunk 8 closes
// the v1.10 carry-over. Stops when:
//
//   - totalLimit hits accumulated, OR
//   - a page returns 0 matches (Shodan exhausted), OR
//   - ctx is cancelled / errors.
//
// totalLimit ≤ 0 defaults to 100 (single-page Search). Each page
// fetches 100 hits (Shodan's max per request); the rate limiter
// throttles across pages.
func (c *Client) SearchPaged(ctx context.Context, query string, totalLimit int) ([]core.Target, error) {
	if totalLimit <= 0 {
		totalLimit = 100
	}
	const perPage = 100
	out := make([]core.Target, 0, totalLimit)
	for page := 1; len(out) < totalLimit; page++ {
		hits, err := c.searchPage(ctx, query, page, perPage)
		if err != nil {
			return out, err
		}
		if len(hits) == 0 {
			break
		}
		out = append(out, hits...)
		if len(hits) < perPage {
			// Shodan returned a partial page → no more results.
			break
		}
	}
	if len(out) > totalLimit {
		out = out[:totalLimit]
	}
	return out, nil
}

// searchPage issues one /shodan/host/search call for a specific
// page. Shared by Search (page 1) and SearchPaged (loop).
func (c *Client) searchPage(ctx context.Context, query string, page, limit int) ([]core.Target, error) {
	if c.Limiter != nil {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	q := url.Values{}
	q.Set("key", c.APIKey)
	q.Set("query", query)
	q.Set("limit", fmt.Sprintf("%d", limit))
	if page > 1 {
		q.Set("page", fmt.Sprintf("%d", page))
	}

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
