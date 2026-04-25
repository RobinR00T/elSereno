package internetdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"golang.org/x/time/rate"

	"local/elsereno/internal/core"
)

// DefaultBaseURL is the Shodan InternetDB endpoint. Override via
// Client.BaseURL for tests (httptest.NewServer).
const DefaultBaseURL = "https://internetdb.shodan.io"

// ErrInvalidIP is returned when the operator-supplied query is
// not a parseable IP address. InternetDB only accepts IPs (not
// hostnames, CIDRs, or search queries).
var ErrInvalidIP = errors.New("internetdb: query must be a parseable IP address")

// Client is a minimal Shodan InternetDB lookup client. No API
// key required (the endpoint is free + rate-limited by Shodan
// to ~10 rps).
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Limiter *rate.Limiter
}

// New constructs a Client. ratePerSec defaults to 5 when ≤ 0
// (the upstream cap is around 10 rps; we stay below to avoid
// 429s on shared connections).
func New(ratePerSec int) *Client {
	if ratePerSec <= 0 {
		ratePerSec = 5
	}
	return &Client{
		BaseURL: DefaultBaseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Limiter: rate.NewLimiter(rate.Limit(ratePerSec), ratePerSec),
	}
}

// LookupResponse is the subset of /<ip> response fields the
// scanner consumes. InternetDB returns much more (cpes, tags,
// vulns) that higher-level UX layers can pick up later.
type LookupResponse struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames,omitempty"`
}

// Lookup calls /<ip> and returns one core.Target per open port.
// The /<ip> endpoint is a public unauthenticated GET; 404 is
// the upstream signal for "no data on this IP" and surfaces as
// an empty target slice (not an error).
func (c *Client) Lookup(ctx context.Context, ip string) ([]core.Target, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidIP, ip)
	}
	if c.Limiter != nil {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	u := fmt.Sprintf("%s/%s", c.BaseURL, addr.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("internetdb: request: %w", err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("internetdb: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to decode
	case http.StatusNotFound:
		// "No information available for this IP" — not an error.
		return nil, nil
	default:
		return nil, fmt.Errorf("internetdb: status %d", resp.StatusCode)
	}

	var parsed LookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("internetdb: decode: %w", err)
	}
	return targetsFor(addr, parsed.Ports), nil
}

// targetsFor returns one core.Target per port for the given IP.
// Invalid ports (out of 1..65535 range) are skipped.
func targetsFor(addr netip.Addr, ports []int) []core.Target {
	out := make([]core.Target, 0, len(ports))
	for _, p := range ports {
		port, err := core.NewPort(p)
		if err != nil {
			continue
		}
		out = append(out, core.Target{Address: addr, Port: port})
	}
	return out
}
