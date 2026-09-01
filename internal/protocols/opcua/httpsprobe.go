package opcua

// OPC UA HTTPS transport-binding fingerprint (OPC-UA Part 6 §7.4).
//
// The opc.tcp probe in opcua.go sends a Hello and reads ACK/ERR. This
// file adds the HTTPS binding: an OPC UA server that speaks the HTTPS
// transport answers a GetEndpoints POST with its EndpointDescription
// list, which both positively identifies it AND reveals its security
// posture (which SecurityModes / SecurityPolicies it offers — a "None"
// endpoint is an exposure flag). GetEndpoints is session-less and
// unauthenticated, so this stays a read-only fingerprint: no
// SecureChannel, no session, no write.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/opcua/wire"
)

// httpsContentType is the Content-Type for the UA Binary HTTPS binding
// (Part 6 §7.4.2). Servers also accept application/opcua+uabinary; we
// send the more widely-implemented octet-stream.
const httpsContentType = "application/octet-stream"

// ErrHTTPSNotUA means the endpoint answered HTTP but not with a
// decodable GetEndpointsResponse (so it is not an OPC UA HTTPS server,
// or speaks a different encoding).
var ErrHTTPSNotUA = errors.New("opcua: HTTPS endpoint did not return a GetEndpointsResponse")

// ProbeHTTPS POSTs a GetEndpointsRequest to postURL over HTTPS and
// decodes the endpoint list. postURL is the full https:// URL to POST
// to (e.g. "https://host:443/"); endpointURL is the opc.https URL
// placed in the request's endpointUrl field (the address the client
// believes it is talking to). TLS certificates are NOT verified — this
// fingerprints untrusted hosts, it does not trust them.
func ProbeHTTPS(ctx context.Context, postURL, endpointURL string, timeout time.Duration) ([]wire.EndpointDescription, error) {
	body := wire.EncodeGetEndpointsRequest(endpointURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("opcua: build HTTPS request: %w", err)
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
		return nil, fmt.Errorf("opcua: HTTPS POST %s: %w", postURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the body: a GetEndpoints response is a few KiB; a huge body
	// means we hit something that isn't a UA HTTPS server.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("opcua: read HTTPS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrHTTPSNotUA, resp.StatusCode)
	}
	eps, err := wire.DecodeGetEndpointsResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPSNotUA, err)
	}
	return eps, nil
}

// tryHTTPS attempts the OPC UA HTTPS binding on the target's host:port
// and, on success, returns a UA-HTTPS finding. Called only from the
// non-UA-TCP path in Probe; returns nil when the endpoint is not an OPC
// UA HTTPS server (so the caller falls back to its non-UA finding).
func (p *Plugin) tryHTTPS(ctx context.Context, target core.Target) *core.Finding {
	hostport := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	postURL := "https://" + hostport + "/"
	endpointURL := "opc.https://" + hostport + "/"
	eps, err := ProbeHTTPS(ctx, postURL, endpointURL, p.IOTimeout)
	if err != nil || len(eps) == 0 {
		return nil
	}
	return buildHTTPSFinding(target, eps)
}

// buildHTTPSFinding renders a finding for an OPC UA server reached over
// the HTTPS binding. A server that advertises a SecurityMode=None
// endpoint accepts anonymous, unencrypted sessions, so it scores as a
// higher exposure / weaker auth posture than the default UA baseline.
func buildHTTPSFinding(target core.Target, eps []wire.EndpointDescription) *core.Finding {
	hasNone := false
	for _, e := range eps {
		if e.SecurityMode == wire.SecurityModeNone {
			hasNone = true
			break
		}
	}
	factors := map[string]int{
		"protocol_risk": 85,
		"exposure":      75,
		"auth_state":    60,
		"capability":    60, // positively identified as a live UA server
		"impact_class":  85,
		"cve_exposure":  8,
	}
	if hasNone {
		// A None-security endpoint is anonymous + unencrypted access to
		// the UA address space over the Internet.
		factors["auth_state"] = 90
		factors["exposure"] = 90
	}
	note := fmt.Sprintf("ua-https endpoints=%d none=%t", len(eps), hasNone)
	return newFinding(target, note, factors)
}
