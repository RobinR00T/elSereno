package s7

import (
	"fmt"
	"io"

	"local/elsereno/internal/protocols/s7/wire"
)

// s7Handshake drives the two mandatory handshakes every S7 request needs:
// COTP Connection Request/Confirm, then S7 Setup Communication. It reports
// isS7 (the port answered with a COTP Connection Confirm) and setupOK (the
// Setup Communication negotiated). Shared by the protection and identity
// probes. The caller sets deadlines on conn.
func s7Handshake(conn io.ReadWriter) (isS7, setupOK bool, err error) {
	// COTP Connection Request / Confirm.
	if err := wire.WriteTPKT(conn, wire.BuildCOTPConnectionRequest()); err != nil {
		return false, false, fmt.Errorf("s7: write COTP CR: %w", err)
	}
	cc, err := wire.ReadTPKT(conn)
	if err != nil {
		return false, false, fmt.Errorf("s7: read COTP CC: %w", err)
	}
	if !wire.IsCOTPConfirm(cc.Payload) {
		return false, false, nil // not S7/COTP on this port
	}

	// Setup Communication.
	if err := wire.WriteTPKT(conn, wire.BuildSetupCommunication(setupPDURef)); err != nil {
		return true, false, fmt.Errorf("s7: write Setup Communication: %w", err)
	}
	sr, err := wire.ReadTPKT(conn)
	if err != nil {
		return true, false, fmt.Errorf("s7: read Setup response: %w", err)
	}
	spdu, ok := wire.S7PDU(sr.Payload)
	if !ok {
		return true, false, nil
	}
	if _, ok := wire.ParseSetupResponse(spdu); !ok {
		return true, false, nil
	}
	return true, true, nil
}

// readSZL sends one UserData Read SZL request on an established session and
// returns the S7 PDU of the response. ok=false on a transport error or a
// non-S7 reply.
func readSZL(conn io.ReadWriter, pduRef, szlID, szlIndex uint16) (pdu []byte, ok bool, err error) {
	req := wire.BuildReadSZLRequest(pduRef, szlID, szlIndex)
	if err := wire.WriteTPKT(conn, req); err != nil {
		return nil, false, fmt.Errorf("s7: write Read SZL 0x%04x: %w", szlID, err)
	}
	resp, err := wire.ReadTPKT(conn)
	if err != nil {
		return nil, false, fmt.Errorf("s7: read SZL 0x%04x response: %w", szlID, err)
	}
	p, ok := wire.S7PDU(resp.Payload)
	if !ok {
		return nil, false, nil
	}
	return p, true, nil
}
