package opcua

import (
	"context"
	"fmt"
	"io"

	"local/elsereno/internal/protocols/opcua/wire"
)

// AnonymousAccessResult reports what the anonymous-session probe learned.
// It is read-only recon: the probe opens a session as the anonymous user
// and reports whether that succeeds; it never reads or writes the address
// space.
type AnonymousAccessResult struct {
	// IsOPCUA is true once the server answered the UA-TCP Hello with an
	// Acknowledge.
	IsOPCUA bool
	// AdvertisesAnonymous is true when GetEndpoints returned an endpoint
	// with an Anonymous UserTokenPolicy; AnonymousPolicyID is its PolicyId.
	AdvertisesAnonymous bool
	AnonymousPolicyID   string
	// SessionOpened is the headline finding: an anonymous
	// CreateSession + ActivateSession both returned Good, so anonymous
	// access actually works (not merely that None is advertised).
	SessionOpened bool
}

// readMessage reads one UA-TCP message from r and returns its type + the
// body (the bytes after the 8-byte header).
func readMessage(r io.Reader) (wire.MessageType, []byte, error) {
	hdr := make([]byte, wire.HeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return "", nil, err
	}
	h, err := wire.ParseHeader(hdr)
	if err != nil {
		return "", nil, err
	}
	n := int(h.Length) - wire.HeaderSize
	if n < 0 {
		return "", nil, fmt.Errorf("opcua: negative message body length %d", n)
	}
	body := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return "", nil, err
		}
	}
	return h.Type, body, nil
}

// ProbeAnonymousAccess drives the OPC UA session handshake over conn and
// reports whether an anonymous session opens: HELLO/ACK -> OPN
// (SecurityPolicy#None) -> GetEndpoints (for the anonymous PolicyId) ->
// CreateSession -> ActivateSession(Anonymous). It stops (without error) at
// the first step that says "not exposed" (not OPC UA, no anonymous policy,
// a rejected session), returning what it learned so far. The caller sets
// read/write deadlines on conn.
func ProbeAnonymousAccess(ctx context.Context, conn io.ReadWriter, endpointURL string) (AnonymousAccessResult, error) {
	_, res, err := establishAnonymousSession(ctx, conn, endpointURL)
	return res, err
}

// getAnonymousPolicyID sends GetEndpoints on the open channel and returns
// the first endpoint's anonymous PolicyId (if any advertises Anonymous).
func getAnonymousPolicyID(conn io.ReadWriter, channelID, tokenID uint32, endpointURL string) (string, bool, error) {
	if _, err := conn.Write(wire.EncodeGetEndpointsRequestTCP(channelID, tokenID, 2, 2, endpointURL)); err != nil {
		return "", false, fmt.Errorf("opcua: write GetEndpoints: %w", err)
	}
	mt, body, err := readMessage(conn)
	if err != nil {
		return "", false, fmt.Errorf("opcua: read GetEndpoints response: %w", err)
	}
	if mt != wire.MessageMessage || len(body) < 16 {
		return "", false, nil
	}
	eps, err := wire.DecodeGetEndpointsResponse(body[16:]) // strip symmetric header
	if err != nil {
		return "", false, nil //nolint:nilerr // undecodable endpoint list = treat as "no anonymous found", not a probe error
	}
	for _, e := range eps {
		if e.AllowsAnonymous {
			return e.AnonymousPolicyID, true, nil
		}
	}
	return "", false, nil
}

// openAnonymousSession runs CreateSession + ActivateSession(Anonymous) and
// reports whether both returned Good (anonymous access confirmed). On
// success it also returns the AuthenticationToken, so a caller can keep
// issuing requests on the activated session (the writeable-tag walk). Uses
// sequence/request numbers 3 and 4 (OPN=1, GetEndpoints=2 precede it), so
// the next request on the session is number 5.
func openAnonymousSession(conn io.ReadWriter, channelID, tokenID uint32, endpointURL, policyID string) (opened bool, authToken []byte, err error) {
	// CreateSession. A 32-byte zero nonce is accepted under None.
	nonce := make([]byte, 32)
	if _, err := conn.Write(wire.EncodeCreateSessionRequest(channelID, tokenID, 3, 3, endpointURL, "elsereno", nonce)); err != nil {
		return false, nil, fmt.Errorf("opcua: write CreateSession: %w", err)
	}
	mt, body, err := readMessage(conn)
	if err != nil {
		return false, nil, fmt.Errorf("opcua: read CreateSession response: %w", err)
	}
	if mt != wire.MessageMessage {
		return false, nil, nil
	}
	if status, ok := wire.ResponseServiceResult(body); !ok || status != wire.StatusGood {
		return false, nil, nil // CreateSession itself was refused
	}
	authToken, ok := wire.ParseCreateSessionAuthToken(body)
	if !ok {
		return false, nil, nil
	}

	// ActivateSession as the anonymous user.
	if _, err := conn.Write(wire.EncodeActivateSessionRequestAnonymous(channelID, tokenID, 4, 4, authToken, policyID)); err != nil {
		return false, nil, fmt.Errorf("opcua: write ActivateSession: %w", err)
	}
	mt, body, err = readMessage(conn)
	if err != nil {
		return false, nil, fmt.Errorf("opcua: read ActivateSession response: %w", err)
	}
	if mt != wire.MessageMessage {
		return false, nil, nil
	}
	status, ok := wire.ResponseServiceResult(body)
	if !ok || status != wire.StatusGood {
		return false, nil, nil
	}
	return true, authToken, nil
}
