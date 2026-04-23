package fofa

import (
	"context"
	"encoding/base64"
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

// DefaultBaseURL is the FOFA API endpoint. Override via
// Client.BaseURL for tests (httptest.NewServer).
const DefaultBaseURL = "https://fofa.info"

// ErrNoCredentials is returned when either Email or APIKey is
// empty. FOFA requires both — email identifies the account,
// APIKey authenticates. The CLI surfaces this with a hint
// pointing at `elsereno creds store fofa`.
var ErrNoCredentials = errors.New("fofa: no email / API key configured")

// ErrAPIError is returned when FOFA's response body has
// `error: true` (malformed query, quota exceeded, auth refused,
// etc.). The error message carries FOFA's errmsg verbatim.
var ErrAPIError = errors.New("fofa: API error")

// Client is a minimal FOFA REST client for the search API. Scope
// is the same as the Shodan client: host search only, returning
// `(ip, port)` tuples. Advanced endpoints (host detail, stats)
// arrive when CLI verbs wire them up.
type Client struct {
	Email   string
	APIKey  string
	BaseURL string
	HTTP    *http.Client
	Limiter *rate.Limiter
}

// New constructs a Client. FOFA needs BOTH email and APIKey
// (the API key is the per-account token; the email scopes it).
// ratePerSec of 0 disables rate limiting; FOFA's free tier is
// heavily throttled, so callers SHOULD set 1 rps or lower.
func New(email, apiKey string, ratePerSec int) (*Client, error) {
	if email == "" || apiKey == "" {
		return nil, ErrNoCredentials
	}
	c := &Client{
		Email:   email,
		APIKey:  apiKey,
		BaseURL: DefaultBaseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
	if ratePerSec > 0 {
		c.Limiter = rate.NewLimiter(rate.Limit(ratePerSec), ratePerSec)
	}
	return c, nil
}

// SearchResponse is the envelope FOFA returns. We parse the few
// fields we consume; FOFA returns many more (country, asn, os,
// title, etc.) that higher-level UX layers can pick up later.
//
// Results is a slice of 3-element string arrays because FOFA
// returns rows in the order of the requested `fields` param. We
// always request `host,ip,port` to get a stable shape.
type SearchResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg,omitempty"`
	Mode    string     `json:"mode,omitempty"`
	Page    int        `json:"page,omitempty"`
	Size    int        `json:"size,omitempty"`
	Results [][]string `json:"results,omitempty"`
}

// Search calls /api/v1/search/all and returns up to `size`
// parsed hits. `query` is the FOFA search-query language
// expression (e.g. `protocol="iax2"` or `app="Asterisk"`); it
// is base64-encoded per FOFA's requirement before being sent.
func (c *Client) Search(ctx context.Context, query string, size int) ([]core.Target, error) {
	if c.Limiter != nil {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if size <= 0 {
		size = 100
	}
	qbase64 := base64.StdEncoding.EncodeToString([]byte(query))

	q := url.Values{}
	q.Set("email", c.Email)
	q.Set("key", c.APIKey)
	q.Set("qbase64", qbase64)
	q.Set("size", strconv.Itoa(size))
	q.Set("fields", "host,ip,port")

	u := fmt.Sprintf("%s/api/v1/search/all?%s", c.BaseURL, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("fofa: request: %w", err)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fofa: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fofa: status %d", resp.StatusCode)
	}

	var parsed SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("fofa: decode: %w", err)
	}
	if parsed.Error {
		return nil, fmt.Errorf("%w: %s", ErrAPIError, parsed.ErrMsg)
	}

	return mapResults(parsed.Results), nil
}

// mapResults converts FOFA rows to core.Target values. Each row
// is `[host, ip, port]`. Rows whose IP or port fails to parse
// are skipped (not an error — FOFA returns IPv6 / hostname
// variants we haven't taught the core to deal with yet).
func mapResults(rows [][]string) []core.Target {
	out := make([]core.Target, 0, len(rows))
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		addr, err := netip.ParseAddr(row[1])
		if err != nil {
			continue
		}
		p, err := strconv.Atoi(row[2])
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
