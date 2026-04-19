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
		Hits []HitV2 `json:"hits"`
	} `json:"result"`
}

// Search calls /api/v2/hosts/search and returns up to `perPage` hits
// as core.Target values.
func (c *Client) Search(ctx context.Context, query string, perPage int) ([]core.Target, error) {
	if c.Limiter != nil {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if perPage <= 0 {
		perPage = 100
	}

	q := url.Values{}
	q.Set("q", query)
	q.Set("per_page", fmt.Sprintf("%d", perPage))

	u := fmt.Sprintf("%s/api/v2/hosts/search?%s", c.BaseURL, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("censys: request: %w", err)
	}
	req.SetBasicAuth(c.APIID, c.APISecret)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("censys: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("censys: status %d", resp.StatusCode)
	}

	var parsed SearchResponseV2
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("censys: decode: %w", err)
	}
	return mapHits(parsed.Result.Hits), nil
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
