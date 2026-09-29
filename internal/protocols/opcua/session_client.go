package opcua

import (
	"context"
	"fmt"
	"io"

	"local/elsereno/internal/protocols/opcua/wire"
)

// uaSession is a live, activated OPC UA session over conn: the secure
// channel ids + the AuthenticationToken + a monotonic sequence/request
// counter. It lets a caller keep issuing service requests after the
// anonymous handshake (the writeable-tag walk browses + reads on it).
type uaSession struct {
	conn      io.ReadWriter
	channelID uint32
	tokenID   uint32
	authToken []byte
	seq       uint32 // last sequence/request number used
}

// next returns the next sequence/request number (used for both, as the
// probe issues one request at a time and waits for its reply).
func (s *uaSession) next() uint32 {
	s.seq++
	return s.seq
}

// establishAnonymousSession drives the full anonymous handshake over conn:
// HELLO/ACK -> OpenSecureChannel(None) -> GetEndpoints (for the anonymous
// PolicyId) -> CreateSession -> ActivateSession(Anonymous). It fills the
// result step by step and, when the anonymous session opens, returns a
// live *uaSession positioned to send further requests (seq continues at
// 5). At the first step that says "not exposed" it returns (nil, res, nil).
// The caller sets read/write deadlines on conn.
func establishAnonymousSession(ctx context.Context, conn io.ReadWriter, endpointURL string) (*uaSession, AnonymousAccessResult, error) {
	var res AnonymousAccessResult
	if err := ctx.Err(); err != nil {
		return nil, res, err
	}

	// 1. HELLO / ACK.
	hello := wire.EncodeHello(wire.Hello{
		Version: 0, ReceiveBufSize: 65535, SendBufSize: 65535,
		MaxMessageSize: 0, MaxChunkCount: 0, EndpointURL: endpointURL,
	})
	if _, err := conn.Write(hello); err != nil {
		return nil, res, fmt.Errorf("opcua: write HELLO: %w", err)
	}
	mt, _, err := readMessage(conn)
	if err != nil {
		return nil, res, fmt.Errorf("opcua: read ACK: %w", err)
	}
	if mt != wire.MessageAck {
		return nil, res, nil // not an OPC UA server, or it rejected the Hello
	}
	res.IsOPCUA = true

	// 2. OpenSecureChannel (None).
	if _, err := conn.Write(wire.EncodeOpenSecureChannelRequestNone(1, 1, 3600000)); err != nil {
		return nil, res, fmt.Errorf("opcua: write OPN: %w", err)
	}
	mt, body, err := readMessage(conn)
	if err != nil {
		return nil, res, fmt.Errorf("opcua: read OPN response: %w", err)
	}
	if mt != wire.MessageOpen {
		return nil, res, nil
	}
	channelID, tokenID, ok := wire.ParseOpenSecureChannelResponse(body)
	if !ok {
		return nil, res, nil
	}

	// 3. GetEndpoints -> the anonymous PolicyId.
	policyID, found, err := getAnonymousPolicyID(conn, channelID, tokenID, endpointURL)
	if err != nil {
		return nil, res, err
	}
	res.AdvertisesAnonymous = found
	res.AnonymousPolicyID = policyID
	if !found {
		return nil, res, nil // no anonymous user token advertised: not the exposure
	}

	// 4. CreateSession + 5. ActivateSession(Anonymous).
	opened, authToken, err := openAnonymousSession(conn, channelID, tokenID, endpointURL, policyID)
	res.SessionOpened = opened
	if err != nil || !opened {
		return nil, res, err
	}
	return &uaSession{
		conn:      conn,
		channelID: channelID,
		tokenID:   tokenID,
		authToken: authToken,
		seq:       4, // OPN=1, GetEndpoints=2, CreateSession=3, ActivateSession=4
	}, res, nil
}

// browse issues a BrowseRequest for node's forward hierarchical references
// and returns the child references. ok=false on any transport/parse error
// (the walk treats it as "nothing to descend", not a fatal error).
func (s *uaSession) browse(node []byte) ([]wire.BrowseRef, bool) {
	n := s.next()
	req := wire.EncodeBrowseRequestTCP(s.channelID, s.tokenID, n, n, s.authToken, node, 0)
	if _, err := s.conn.Write(req); err != nil {
		return nil, false
	}
	mt, body, err := readMessage(s.conn)
	if err != nil || mt != wire.MessageMessage {
		return nil, false
	}
	return wire.ParseBrowseResponse(body)
}

// readUserAccessLevels reads the UserAccessLevel attribute of every node in
// one ReadRequest and returns the results in request order. ok=false on any
// transport/parse error.
func (s *uaSession) readUserAccessLevels(nodes [][]byte) ([]wire.DataValueResult, bool) {
	targets := make([]wire.ReadTarget, len(nodes))
	for i, nd := range nodes {
		targets[i] = wire.ReadTarget{NodeID: nd, AttributeID: wire.AttrUserAccessLevel}
	}
	n := s.next()
	req := wire.EncodeReadRequestTCP(s.channelID, s.tokenID, n, n, s.authToken, targets)
	if _, err := s.conn.Write(req); err != nil {
		return nil, false
	}
	mt, body, err := readMessage(s.conn)
	if err != nil || mt != wire.MessageMessage {
		return nil, false
	}
	return wire.ParseReadResponse(body)
}
