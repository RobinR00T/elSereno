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
	var res AnonymousAccessResult
	if err := ctx.Err(); err != nil {
		return res, err
	}

	// 1. HELLO / ACK.
	hello := wire.EncodeHello(wire.Hello{
		Version: 0, ReceiveBufSize: 65535, SendBufSize: 65535,
		MaxMessageSize: 0, MaxChunkCount: 0, EndpointURL: endpointURL,
	})
	if _, err := conn.Write(hello); err != nil {
		return res, fmt.Errorf("opcua: write HELLO: %w", err)
	}
	mt, _, err := readMessage(conn)
	if err != nil {
		return res, fmt.Errorf("opcua: read ACK: %w", err)
	}
	if mt != wire.MessageAck {
		return res, nil // not an OPC UA server, or it rejected the Hello
	}
	res.IsOPCUA = true

	// 2. OpenSecureChannel (None).
	if _, err := conn.Write(wire.EncodeOpenSecureChannelRequestNone(1, 1, 3600000)); err != nil {
		return res, fmt.Errorf("opcua: write OPN: %w", err)
	}
	mt, body, err := readMessage(conn)
	if err != nil {
		return res, fmt.Errorf("opcua: read OPN response: %w", err)
	}
	if mt != wire.MessageOpen {
		return res, nil
	}
	channelID, tokenID, ok := wire.ParseOpenSecureChannelResponse(body)
	if !ok {
		return res, nil
	}

	// 3. GetEndpoints -> the anonymous PolicyId.
	policyID, found, err := getAnonymousPolicyID(conn, channelID, tokenID, endpointURL)
	if err != nil {
		return res, err
	}
	res.AdvertisesAnonymous = found
	res.AnonymousPolicyID = policyID
	if !found {
		return res, nil // no anonymous user token advertised: not the exposure
	}

	// 4. CreateSession + 5. ActivateSession(Anonymous).
	res.SessionOpened, err = openAnonymousSession(conn, channelID, tokenID, endpointURL, policyID)
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
// reports whether both returned Good (anonymous access confirmed).
func openAnonymousSession(conn io.ReadWriter, channelID, tokenID uint32, endpointURL, policyID string) (bool, error) {
	// CreateSession. A 32-byte zero nonce is accepted under None.
	nonce := make([]byte, 32)
	if _, err := conn.Write(wire.EncodeCreateSessionRequest(channelID, tokenID, 3, 3, endpointURL, "elsereno", nonce)); err != nil {
		return false, fmt.Errorf("opcua: write CreateSession: %w", err)
	}
	mt, body, err := readMessage(conn)
	if err != nil {
		return false, fmt.Errorf("opcua: read CreateSession response: %w", err)
	}
	if mt != wire.MessageMessage {
		return false, nil
	}
	if status, ok := wire.ResponseServiceResult(body); !ok || status != wire.StatusGood {
		return false, nil // CreateSession itself was refused
	}
	authToken, ok := wire.ParseCreateSessionAuthToken(body)
	if !ok {
		return false, nil
	}

	// ActivateSession as the anonymous user.
	if _, err := conn.Write(wire.EncodeActivateSessionRequestAnonymous(channelID, tokenID, 4, 4, authToken, policyID)); err != nil {
		return false, fmt.Errorf("opcua: write ActivateSession: %w", err)
	}
	mt, body, err = readMessage(conn)
	if err != nil {
		return false, fmt.Errorf("opcua: read ActivateSession response: %w", err)
	}
	if mt != wire.MessageMessage {
		return false, nil
	}
	status, ok := wire.ResponseServiceResult(body)
	return ok && status == wire.StatusGood, nil
}
