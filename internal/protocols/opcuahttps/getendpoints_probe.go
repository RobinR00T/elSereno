package opcuahttps

// Deep OPC UA HTTPS fingerprint via a real GetEndpoints POST (Part 6
// §7.4 binding). The header-only classifier in opcuahttps.go stays as a
// fallback; this path parses the actual EndpointDescription list so the
// finding can carry the server's security posture (a SecurityMode=None
// endpoint = anonymous, unencrypted UA access).

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/opcua/wire"
	"local/elsereno/internal/scoring"
)

// httpsContentType is the Content-Type for the UA Binary HTTPS binding
// (Part 6 §7.4.2).
const httpsContentType = "application/octet-stream"

// ErrNotUAEndpoints means the endpoint answered HTTP but not with a
// decodable GetEndpointsResponse.
var ErrNotUAEndpoints = errors.New("opcuahttps: no decodable GetEndpointsResponse")

// probeGetEndpoints POSTs a GetEndpointsRequest to postURL over HTTPS
// and decodes the endpoint list. TLS certificates are NOT verified —
// this fingerprints untrusted hosts, it does not trust them.
func probeGetEndpoints(ctx context.Context, postURL, endpointURL string, timeout time.Duration) ([]wire.EndpointDescription, error) {
	body := wire.EncodeGetEndpointsRequest(endpointURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("opcuahttps: build request: %w", err)
	}
	req.Header.Set("Content-Type", httpsContentType)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// #nosec G402 -- fingerprinting untrusted ICS endpoints; we
			// never send credentials and never trust the peer, we only
			// read the (unauthenticated, session-less) endpoint list.
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opcuahttps: POST %s: %w", postURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("opcuahttps: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrNotUAEndpoints, resp.StatusCode)
	}
	eps, err := wire.DecodeGetEndpointsResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotUAEndpoints, err)
	}
	return eps, nil
}

// hasNoneEndpoint reports whether any endpoint advertises SecurityMode
// None (anonymous + unencrypted access).
func hasNoneEndpoint(eps []wire.EndpointDescription) bool {
	for _, e := range eps {
		if e.SecurityMode == wire.SecurityModeNone {
			return true
		}
	}
	return false
}

// buildEndpointsFinding renders a finding from an enumerated
// EndpointDescription list — a definitive OPC UA HTTPS identification.
// A SecurityMode=None endpoint (anonymous, unencrypted UA access) bumps
// exposure + auth_state above the baseline.
func buildEndpointsFinding(target core.Target, eps []wire.EndpointDescription) *core.Finding {
	none := hasNoneEndpoint(eps)
	factors := map[string]int{
		"protocol_risk": 75,
		"exposure":      80,
		"auth_state":    55,
		"capability":    80, // enumerated the endpoint list = definitive UA
		"impact_class":  60,
		"cve_exposure":  12,
	}
	if none {
		factors["auth_state"] = 90
		factors["exposure"] = 90
	}
	note := fmt.Sprintf("ua-https-endpoints n=%d none=%t", len(eps), none)
	score := scoring.ScoreDefault(factors)
	return &core.Finding{
		ID:          hashID(target, note),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hashBytes(target, note),
	}
}
