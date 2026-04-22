//go:build offensive

package hartip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"local/elsereno/internal/protocols/hartip/wire"
	"local/elsereno/offensive/confirm"
)

// WriteGatedHandler enforces HART-IP per-HART-command gating on
// TokenPassPDU messages. Session-lifecycle messages
// (SessionInitiate, SessionClose, KeepAlive) always pass.
// TokenPassPDU messages carry a HART PDU whose command byte
// names the HART operation; the gate consults the allowlist on
// that byte.
//
// Refusal path: a TokenPassPDU response whose HART body carries
// the "command not implemented" response code (0x40 in the
// device status byte per HART FSK spec §7.1). Real HART masters
// parse this as a standard "unsupported command" reply.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedCommand
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	authorised bool
}

// HART universal commands (subset) used by the gate's default
// policy. Reads are <= 3; Commands 6, 34-53 include write/
// configure operations.
const (
	HARTCmdReadUniqueIdentifier uint8 = 0
	HARTCmdReadPrimaryVariable  uint8 = 1
	HARTCmdReadCurrent          uint8 = 2
	HARTCmdReadDynamicVariables uint8 = 3
	HARTCmdWritePollingAddress  uint8 = 6
	HARTCmdWriteDamping         uint8 = 34
	HARTCmdWriteRangeValues     uint8 = 35
	HARTCmdEnterExitFixedMode   uint8 = 40
	HARTCmdDeviceReset          uint8 = 42
	HARTCmdCalibrate            uint8 = 45
	HARTCmdWriteMessage         uint8 = 48
)

// HART response code "command not implemented" (communication
// status bit 6 set).
const hartRespCommandNotImplemented uint8 = 0x40

// Authorise opens the session.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutation(h.Target, h.Allowed)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned when Handle runs before Authorise.
var ErrSessionNotAuthorised = errors.New("hartip: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(client, upstream, client) }()
	go func() { _, err := io.Copy(client, upstream); errs <- err }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	hdr := make([]byte, wire.HeaderLen)
	for {
		if _, err := io.ReadFull(client, hdr); err != nil {
			return err
		}
		header, err := wire.ParseHeader(hdr)
		if err != nil {
			return fmt.Errorf("hartip: parse header: %w", err)
		}
		bodyLen := int(header.ByteCount) - wire.HeaderLen
		if bodyLen < 0 {
			bodyLen = 0
		}
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(client, body); err != nil {
				return err
			}
		}
		if h.shouldForward(header, body) {
			if _, err := upstream.Write(append(hdr, body...)); err != nil {
				return err
			}
			continue
		}
		if _, err := clientWriter.Write(buildCommandNotImplementedResponse(header, body)); err != nil {
			return err
		}
	}
}

// shouldForward applies the gate. SessionInitiate / Close /
// KeepAlive always pass; TokenPassPDU consults the allowlist.
func (h *WriteGatedHandler) shouldForward(header wire.Header, body []byte) bool {
	if header.MsgID != wire.IDTokenPassPDU {
		return true
	}
	cmd, ok := extractHARTCommand(body)
	if !ok {
		// Body too short to classify; refuse conservatively.
		return false
	}
	// HART commands 0-3 are universal reads; always allow.
	if cmd <= 3 {
		return true
	}
	for _, a := range h.Allowed {
		if a.HARTCmd == cmd {
			return true
		}
	}
	return false
}

// extractHARTCommand reads the command byte from a HART PDU
// embedded in a TokenPassPDU body. HART PDU layout (Token-
// Passing, §6 of HART-IP spec):
//
//	[0]     Delimiter (preamble-stripped, typically 0x82 long frame)
//	[1..5]  Device address (5 bytes, long frame)
//	[6]     Command
//	[7]     Byte count
//	[8..]   Data
//
// Short frames (0x02/0x06) carry a 1-byte address with the
// command at offset 2. The HIGH bit (0x80) of the delimiter
// distinguishes long from short frames (HART-FSK §9.1.2).
func extractHARTCommand(body []byte) (uint8, bool) {
	if len(body) < 3 {
		return 0, false
	}
	delim := body[0]
	if delim&0x80 != 0 { // long frame
		if len(body) < 7 {
			return 0, false
		}
		return body[6], true
	}
	return body[2], true
}

// buildCommandNotImplementedResponse crafts a HART-IP
// TokenPassPDU response whose HART body carries the "command
// not implemented" bit set in byte 0 of the response-code pair.
// Minimal wire-correct reply so the master sees a standard
// HART refusal rather than a TCP RST.
func buildCommandNotImplementedResponse(req wire.Header, reqBody []byte) []byte {
	// Build HART response body. Structure:
	//   [0]   Delimiter (0x86 for long-frame response) or 0x06 short
	//   [1..] Address (mirror)
	//   [n]   Command (mirror)
	//   [n+1] Byte count = 2
	//   [n+2] Response code 1 = 0x40 command-not-impl
	//   [n+3] Response code 2 = 0x00
	hartBody := buildHARTResponse(reqBody)
	out := make([]byte, wire.HeaderLen+len(hartBody))
	out[0] = wire.Version
	out[1] = wire.MsgResponse
	out[2] = wire.IDTokenPassPDU
	out[3] = 0x00
	binary.BigEndian.PutUint16(out[4:6], req.Sequence)
	// #nosec G115 — length ≤ 64 bytes by construction
	binary.BigEndian.PutUint16(out[6:8], uint16(wire.HeaderLen+len(hartBody)))
	copy(out[wire.HeaderLen:], hartBody)
	return out
}

// buildHARTResponse mirrors the request shape so the master's
// correlation logic still works. If the request is malformed
// we emit a minimal short-frame refusal.
func buildHARTResponse(reqBody []byte) []byte {
	if len(reqBody) < 3 {
		return []byte{0x06, 0x00, 0x00, 0x02, hartRespCommandNotImplemented, 0x00}
	}
	delim := reqBody[0]
	if delim&0x80 != 0 && len(reqBody) >= 7 {
		// Long frame: delimiter = 0x86 (response | long), copy
		// 5-byte address + command, then cmd count=2 + resp codes.
		out := make([]byte, 0, 10)
		out = append(out, 0x86)
		out = append(out, reqBody[1:6]...) // address
		out = append(out, reqBody[6])      // command
		out = append(out, 0x02, hartRespCommandNotImplemented, 0x00)
		return out
	}
	// Short frame fallback.
	addr := reqBody[1]
	cmd := reqBody[2]
	return []byte{0x06, addr, cmd, 0x02, hartRespCommandNotImplemented, 0x00}
}
