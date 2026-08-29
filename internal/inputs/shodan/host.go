package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"

	"local/elsereno/internal/core"
)

// ErrHostNotFound is returned by Host when Shodan has no record for the
// address (HTTP 404). It is NOT evidence the host is clean, only that
// Shodan never indexed it: callers should treat it like the false-zero
// case (no visibility), never as "no exposure".
var ErrHostNotFound = errors.New("shodan: no host information")

// HostService is one banner Shodan holds for an address: a service seen
// on a port, with whatever passive fingerprint Shodan captured. It is
// the per-service half of the /shodan/host/{ip} response `data` array.
// Surface is kept tight on purpose (same policy as SearchHit): unused
// fields are a future PR, not a silent schema drift.
type HostService struct {
	Port      int      `json:"port"`
	Transport string   `json:"transport,omitempty"`
	Product   string   `json:"product,omitempty"`
	Version   string   `json:"version,omitempty"`
	CPE       []string `json:"cpe,omitempty"`
	// Timestamp is when Shodan last saw this service (RFC3339-ish).
	// With history=true the same port appears multiple times, one per
	// observation, so the exposure can be tracked over time.
	Timestamp string `json:"timestamp,omitempty"`
	// Vulns is Shodan's per-service map, keyed by CVE id. Values carry
	// CVSS/verified detail we do not model; keys are the CVE list.
	Vulns map[string]json.RawMessage `json:"vulns,omitempty"`
}

// CVEs returns the sorted CVE ids Shodan associated with this service.
func (s HostService) CVEs() []string {
	if len(s.Vulns) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.Vulns))
	for cve := range s.Vulns {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

// HostInfo is the parsed /shodan/host/{ip} response: everything Shodan
// passively knows about one address, so an audit can enrich a target
// without sending it a single packet. This is the capability behind
// Shodan's "fast IP enrichment": exposure by lookup, not by scan.
type HostInfo struct {
	IP        string        `json:"ip_str"`
	Hostnames []string      `json:"hostnames,omitempty"`
	OS        string        `json:"os,omitempty"`
	Ports     []int         `json:"ports,omitempty"`
	Data      []HostService `json:"data,omitempty"`
}

// Targets converts the services Shodan knows about into core.Target
// values, so passively-discovered exposure feeds the same pipeline as
// an active sweep. Entries whose IP or port do not parse are skipped.
func (h *HostInfo) Targets() []core.Target {
	if h == nil {
		return nil
	}
	addr, err := netip.ParseAddr(h.IP)
	if err != nil {
		return nil
	}
	out := make([]core.Target, 0, len(h.Data))
	seen := make(map[int]struct{}, len(h.Data))
	for _, s := range h.Data {
		if _, dup := seen[s.Port]; dup {
			// history=true repeats a port per observation; the
			// target set is de-duplicated by port.
			continue
		}
		port, perr := core.NewPort(s.Port)
		if perr != nil {
			continue
		}
		seen[s.Port] = struct{}{}
		out = append(out, core.Target{Address: addr, Port: port})
	}
	return out
}

// CVEs returns the union of CVE ids across all services, sorted and
// de-duplicated: the passive vulnerability picture for the host.
func (h *HostInfo) CVEs() []string {
	if h == nil {
		return nil
	}
	set := make(map[string]struct{})
	for _, s := range h.Data {
		for cve := range s.Vulns {
			set[cve] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for cve := range set {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

// Host calls /shodan/host/{ip} and returns the passive exposure Shodan
// holds for the address. With history=true the response includes every
// past observation (each becomes an extra entry in Data), which lets an
// audit see how a host's exposure changed over time.
//
// Returns ErrHostNotFound on a 404 (Shodan has nothing on the address).
// The API key travels as a query parameter over HTTPS, same as Search
// (PITF-016 covers argv/shell, not TLS-protected query strings).
func (c *Client) Host(ctx context.Context, ip string, history bool) (*HostInfo, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("shodan: bad ip %q: %w", ip, err)
	}
	if c.Limiter != nil {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	q := url.Values{}
	q.Set("key", c.APIKey)
	if history {
		q.Set("history", "true")
	}
	u := fmt.Sprintf("%s/shodan/host/%s?%s", c.BaseURL, addr.String(), q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("shodan: request: %w", err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrHostNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan: status %d", resp.StatusCode)
	}

	var info HostInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("shodan: decode: %w", err)
	}
	return &info, nil
}
