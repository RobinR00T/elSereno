package onyphe

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

// DefaultBaseURL is the ONYPHE API base URL. Override via
// Client.BaseURL for tests (httptest.NewServer).
const DefaultBaseURL = "https://www.onyphe.io"

// ErrNoAPIKey is returned when APIKey is empty. The CLI
// surfaces this with a hint pointing at `elsereno creds store
// onyphe` (v1.10+) or the YAML `--api-creds-file` (v1.9).
var ErrNoAPIKey = errors.New("onyphe: no API key configured")

// Client is a minimal ONYPHE REST client for the search API.
// Same shape as shodan / censys / fofa / zoomeye clients —
// returns (ip, port) tuples only.
type Client struct {
	APIKey  string
	BaseURL string
	HTTP    *http.Client
	Limiter *rate.Limiter
}

// New constructs a Client. ratePerSec of 0 disables rate
// limiting. ONYPHE's free tier is credit-based and cached
// queries count per call, so callers SHOULD default to 1 rps
// to avoid burning credits on redundant paginations.
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

// SearchMatch is the subset of `results[]` fields the scanner
// needs. ONYPHE returns dozens of fields per match (asn,
// country, os, tls, etc.) — the client intentionally parses
// only ip + port to keep the surface tight.
//
// The `port` field is returned as a string by ONYPHE (even
// though it's numeric) so we parse it ourselves.
type SearchMatch struct {
	IP   string `json:"ip"`
	Port string `json:"port"`
}

// SearchResponse is the envelope ONYPHE returns.
type SearchResponse struct {
	Status  string        `json:"status"`
	Error   int           `json:"error"`
	Text    string        `json:"text,omitempty"`
	Count   int           `json:"count,omitempty"`
	Total   int           `json:"total,omitempty"`
	Results []SearchMatch `json:"results,omitempty"`
}

// SearchPaged calls /api/v2/search/<query> repeatedly,
// accumulating up to totalLimit matches across pages. v1.12
// chunk 8 closes the v1.10 "page 1 only" carry-over. Stops when
// totalLimit is reached, a page returns 0 results, or ctx errors.
func (c *Client) SearchPaged(ctx context.Context, query string, totalLimit int) ([]core.Target, error) {
	if totalLimit <= 0 {
		totalLimit = 100
	}
	out := make([]core.Target, 0, totalLimit)
	for page := 1; len(out) < totalLimit; page++ {
		hits, err := c.Search(ctx, query, page)
		if err != nil {
			return out, err
		}
		if len(hits) == 0 {
			break
		}
		out = append(out, hits...)
	}
	if len(out) > totalLimit {
		out = out[:totalLimit]
	}
	return out, nil
}

// Search calls /api/v2/search/<query> and returns up to one
// page of parsed matches. `query` is ONYPHE Query Language
// (OQL) — e.g. `category:datascan product:freepbx`.
//
// ONYPHE embeds the query in the URL path (not a query
// parameter), which means operators should URL-encode
// characters like `:` + `/` + space. The client does that for
// them.
func (c *Client) Search(ctx context.Context, query string, page int) ([]core.Target, error) {
	if c.Limiter != nil {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if page <= 0 {
		page = 1
	}
	// ONYPHE expects the query percent-encoded in the path
	// segment (spaces → %20, etc.).
	encQuery := url.PathEscape(query)

	q := url.Values{}
	q.Set("page", strconv.Itoa(page))

	u := fmt.Sprintf("%s/api/v2/search/%s?%s", c.BaseURL, encQuery, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("onyphe: request: %w", err)
	}
	// ONYPHE uses bearer-token auth in a lower-cased `bearer`
	// scheme. Case is actually insignificant per RFC 6750 but
	// their docs show lowercase, so we mirror that for log
	// friendliness.
	req.Header.Set("Authorization", "bearer "+c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("onyphe: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("onyphe: status %d", resp.StatusCode)
	}

	var parsed SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("onyphe: decode: %w", err)
	}
	if parsed.Error != 0 {
		return nil, fmt.Errorf("onyphe: API error %d: %s", parsed.Error, parsed.Text)
	}
	return mapResults(parsed.Results), nil
}

// mapResults converts ONYPHE match rows to core.Target values.
// Unparseable IPs or ports are dropped silently — ONYPHE
// returns "hostname" rows + port = "N/A" for incomplete scans
// that aren't useful for our downstream probes.
func mapResults(matches []SearchMatch) []core.Target {
	out := make([]core.Target, 0, len(matches))
	for _, m := range matches {
		addr, err := netip.ParseAddr(m.IP)
		if err != nil {
			continue
		}
		p, err := strconv.Atoi(m.Port)
		if err != nil {
			continue
		}
		port, err := core.NewPort(p)
		if err != nil {
			continue
		}
		out = append(out, core.Target{Address: addr, Port: port})
	}
	return out
}
