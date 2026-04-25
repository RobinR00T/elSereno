package censys

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

// DefaultBaseURL is the Censys Search v2 base URL.
const DefaultBaseURL = "https://search.censys.io"

// ErrNoAPICreds is returned by New when either APIID or APISecret is
// empty. The CLI surfaces this with a hint pointing at `elsereno
// creds store censys`.
var ErrNoAPICreds = errors.New("censys: missing API ID or secret")

// Client is a minimal Censys search client (hosts v2).
type Client struct {
	APIID     string
	APISecret string
	BaseURL   string
	HTTP      *http.Client
	Limiter   *rate.Limiter
}

// New constructs a Client. ratePerSec bounds request rate; 0 disables.
func New(apiID, apiSecret string, ratePerSec int) (*Client, error) {
	if apiID == "" || apiSecret == "" {
		return nil, ErrNoAPICreds
	}
	c := &Client{
		APIID:     apiID,
		APISecret: apiSecret,
		BaseURL:   DefaultBaseURL,
		HTTP:      &http.Client{Timeout: 30 * time.Second},
	}
	if ratePerSec > 0 {
		c.Limiter = rate.NewLimiter(rate.Limit(ratePerSec), ratePerSec)
	}
	return c, nil
}

// ServiceV2 is a single service entry inside a host hit.
type ServiceV2 struct {
	Port int `json:"port"`
}

// HitV2 is the subset of the Censys v2 host hit we consume.
type HitV2 struct {
	IP       string      `json:"ip"`
	Services []ServiceV2 `json:"services"`
}

// SearchResponseV2 is the envelope.
type SearchResponseV2 struct {
	Result struct {
		Hits  []HitV2 `json:"hits"`
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
	} `json:"result"`
}

// Search calls /api/v2/hosts/search and returns up to `perPage` hits
// as core.Target values. v1.12 chunk 8 keeps Search single-shot for
// backwards compatibility; use SearchPaged to iterate the cursor.
func (c *Client) Search(ctx context.Context, query string, perPage int) ([]core.Target, error) {
	if perPage <= 0 {
		perPage = 100
	}
	hits, _, err := c.searchPage(ctx, query, perPage, "")
	return hits, err
}

// SearchPaged iterates Censys v2's cursor pagination until
// totalLimit hits are accumulated, the cursor goes empty, or
// ctx errors. v1.12 chunk 8 closes the v1.10 "first cursor only"
// carry-over.
func (c *Client) SearchPaged(ctx context.Context, query string, totalLimit int) ([]core.Target, error) {
	if totalLimit <= 0 {
		totalLimit = 100
	}
	const perPage = 100
	out := make([]core.Target, 0, totalLimit)
	cursor := ""
	for len(out) < totalLimit {
		hits, next, err := c.searchPage(ctx, query, perPage, cursor)
		if err != nil {
			return out, err
		}
		out = append(out, hits...)
		if next == "" || len(hits) == 0 {
			break
		}
		cursor = next
	}
	if len(out) > totalLimit {
		out = out[:totalLimit]
	}
	return out, nil
}

// searchPage issues one /api/v2/hosts/search call, optionally
// honouring a cursor. Returns the hits + the next-page cursor
// (empty string when exhausted).
func (c *Client) searchPage(ctx context.Context, query string, perPage int, cursor string) ([]core.Target, string, error) {
	if c.Limiter != nil {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, "", err
		}
	}

	q := url.Values{}
	q.Set("q", query)
	q.Set("per_page", fmt.Sprintf("%d", perPage))
	if cursor != "" {
		q.Set("cursor", cursor)
	}

	u := fmt.Sprintf("%s/api/v2/hosts/search?%s", c.BaseURL, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", fmt.Errorf("censys: request: %w", err)
	}
	req.SetBasicAuth(c.APIID, c.APISecret)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("censys: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("censys: status %d", resp.StatusCode)
	}

	var parsed SearchResponseV2
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, "", fmt.Errorf("censys: decode: %w", err)
	}
	return mapHits(parsed.Result.Hits), parsed.Result.Links.Next, nil
}

func mapHits(hits []HitV2) []core.Target {
	var out []core.Target
	for _, h := range hits {
		addr, err := netip.ParseAddr(h.IP)
		if err != nil {
			continue
		}
		for _, svc := range h.Services {
			p, err := core.NewPort(svc.Port)
			if err != nil {
				continue
			}
			out = append(out, core.Target{Address: addr, Port: p})
		}
	}
	return out
}
