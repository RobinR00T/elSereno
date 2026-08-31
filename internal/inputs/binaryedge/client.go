package binaryedge

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

// DefaultBaseURL is the BinaryEdge API base URL. Override via
// Client.BaseURL for tests (httptest.NewServer).
const DefaultBaseURL = "https://api.binaryedge.io"

// ErrNoAPIKey is returned when APIKey is empty. The CLI surfaces this
// with a hint pointing at `elsereno creds store binaryedge` or the
// YAML `--api-creds-file`.
var ErrNoAPIKey = errors.New("binaryedge: no API key configured")

// Client is a minimal BinaryEdge REST client for the search API.
type Client struct {
	APIKey  string
	BaseURL string
	HTTP    *http.Client
	Limiter *rate.Limiter
}

// New constructs a Client. ratePerSec of 0 disables rate limiting.
// BinaryEdge's free tier is credit-metered per request, so callers
// SHOULD default to 1 rps to avoid burning credits on paginations.
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

// eventTarget is the (ip, port) tuple inside each search event. The
// client parses only these two fields; BinaryEdge returns an origin +
// a rich result blob per event that the scanner doesn't need.
type eventTarget struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type searchEvent struct {
	Target eventTarget `json:"target"`
}

// searchResponse is the envelope /v2/query/search returns.
type searchResponse struct {
	Page     int           `json:"page"`
	PageSize int           `json:"pagesize"`
	Total    int           `json:"total"`
	Events   []searchEvent `json:"events"`
}

// SearchPaged calls /v2/query/search repeatedly, accumulating up to
// totalLimit matches across pages. Stops when totalLimit is reached, a
// page returns 0 events, or ctx errors.
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

// Search calls /v2/query/search?query=<q>&page=<n> and returns up to
// one page of parsed matches. `query` is a BinaryEdge search
// expression (e.g. `type:service product:"OpenSSH" port:22`).
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

	u := fmt.Sprintf("%s/v2/query/search?%s", c.BaseURL, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("binaryedge: request: %w", err)
	}
	req.Header.Set("X-Key", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("binaryedge: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("binaryedge: status %d", resp.StatusCode)
	}

	var parsed searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("binaryedge: decode: %w", err)
	}
	return mapEvents(parsed.Events), nil
}

// mapEvents converts BinaryEdge events to core.Target values.
// Unparseable IPs or out-of-range ports are dropped silently.
func mapEvents(events []searchEvent) []core.Target {
	out := make([]core.Target, 0, len(events))
	for _, e := range events {
		addr, err := netip.ParseAddr(e.Target.IP)
		if err != nil {
			continue
		}
		port, err := core.NewPort(e.Target.Port)
		if err != nil {
			continue
		}
		out = append(out, core.Target{Address: addr, Port: port})
	}
	return out
}
