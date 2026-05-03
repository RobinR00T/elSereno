//go:build offensive

package dnp3

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"local/elsereno/internal/protocols/dnp3/wire"
	"local/elsereno/offensive/confirm"
)

// WriteGatedHandler is the offensive replacement for the default
// DNP3 deny-all proxy. Gating operates at two layers:
//
//  1. Link-layer PRIMARY function code (control byte low nibble
//     when PRM=1). AllowedControl entries scope which link-layer
//     primary functions are permitted.
//  2. Application-layer function code — the first byte after the
//     DNP3 transport header. `AllowedAppFC` entries scope the
//     app-layer functions; Write (0x02), DirectOperate (0x05),
//     and DirectOperateNoAck (0x06) are the canonical "mutating"
//     functions and MUST be explicitly allowed to pass.
//
// Refusal path: the handler returns a DNP3 user-data frame with
// an application-layer response carrying IIN2 bit 2 "FUNC_NOT_SUPP"
// (IIN byte2 0x04). Real masters see a parseable
// "function not supported" indication rather than a TCP RST.
type WriteGatedHandler struct {
	// Target is the upstream host:port. Must match
	// confirm.Mutation.Target used to mint the session token.
	Target string
	// Allowed lists the link-layer primary function codes the
	// session accepts. Zero length forbids all primary frames
	// except Reset-Link (code 0), Test-Link (code 2), and
	// Request-Link-Status (code 9) which are transport-level.
	Allowed []AllowedControl
	// AllowedAppFC lists the application-layer function codes
	// permitted inside user-data frames (link-layer FC 3 + 4).
	// Read (0x01) is ALWAYS allowed and does not need an entry.
	AllowedAppFC []AllowedAppFunction
	// Deriver + Auditor drive the session-open Authorize call.
	Deriver confirm.KeyDeriver
	Auditor confirm.Auditor
	// SessionConfirm is the Confirm struct the CLI populates
	// from --accept-writes / --confirm-target / --confirm-token.
	SessionConfirm confirm.Confirm

	// authorised flips true after a successful Authorise.
	authorised bool
}

// AllowedAppFunction names an application-layer DNP3 function
// code (IEEE 1815 Table 4-1) the session accepts.
type AllowedAppFunction struct {
	FC uint8
}

// DNP3 link-layer primary function codes (IEEE 1815 §7.4.2.4).
const (
	LinkFCResetLink           uint8 = 0
	LinkFCTestLink            uint8 = 2
	LinkFCConfirmedUserData   uint8 = 3
	LinkFCUnconfirmedUserData uint8 = 4
	LinkFCRequestLinkStatus   uint8 = 9
)

// DNP3 application-layer function codes (IEEE 1815 Table 4-1).
// Only the subset the gate inspects is enumerated.
const (
	AppFCRead               uint8 = 0x01
	AppFCWrite              uint8 = 0x02
	AppFCSelect             uint8 = 0x03
	AppFCOperate            uint8 = 0x04
	AppFCDirectOperate      uint8 = 0x05
	AppFCDirectOperateNoAck uint8 = 0x06
	AppFCFreezeClear        uint8 = 0x09
	AppFCColdRestart        uint8 = 0x0D
	AppFCWarmRestart        uint8 = 0x0E
	AppFCResponse           uint8 = 0x81 // server → client
)

// Authorise opens the proxy session.
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

// ErrSessionNotAuthorised is returned by Handle when Authorise
// hasn't been called yet.
var ErrSessionNotAuthorised = errors.New("dnp3: write-gated proxy requires Authorise() first")

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

// forward reads link-layer frames from the client, decides
// allow/refuse, and emits either the frame upstream or an
// IIN2 FUNC_NOT_SUPP refusal back to the client.
func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	hdr := make([]byte, wire.HeaderLen)
	for {
		if _, err := io.ReadFull(client, hdr); err != nil {
			return err
		}
		lh, err := wire.ParseHeader(hdr)
		if err != nil {
			return fmt.Errorf("dnp3: parse header: %w", err)
		}
		// Length includes the control + dest + src bytes (5) plus
		// the user data payload. ParseHeader already validated
		// length >= 5.
		userDataLen := int(lh.Length) - 5
		if userDataLen < 0 {
			userDataLen = 0
		}
		// The user data is interleaved with per-16-byte-block CRCs
		// on the wire; for the gate decision we only need to peek
		// at the first few bytes of the first block (transport
		// header + app header). Read what's on the wire and
		// forward the bytes verbatim.
		body := make([]byte, userDataLen)
		if userDataLen > 0 {
			if _, err := io.ReadFull(client, body); err != nil {
				return err
			}
		}
		if h.shouldForward(lh, body) {
			if _, err := upstream.Write(append(hdr, body...)); err != nil {
				return err
			}
			continue
		}
		if _, err := clientWriter.Write(buildFuncNotSuppResponse(lh)); err != nil {
			return err
		}
	}
}

// shouldForward applies the gate. Transport-level link FCs (0,2,9)
// always pass; 3/4 (user data) consult the app-layer FC.
func (h *WriteGatedHandler) shouldForward(lh wire.Header, body []byte) bool {
	// Link-layer primary FC is the low nibble of the control byte
	// when PRM (bit 6) = 1. Responses from the outstation have
	// PRM = 0 and are never inspected here (return path is
	// io.Copy in Handle).
	if lh.Control&0x40 == 0 {
		// Secondary frame (outstation → master). Never originates
		// on the client side in our pipe, so receiving one here
		// is unusual — pass through.
		return true
	}
	primaryFC := lh.Control & 0x0F
	// Transport-level functions always pass.
	switch primaryFC {
	case LinkFCResetLink, LinkFCTestLink, LinkFCRequestLinkStatus:
		return true
	}
	// For user-data frames we consult the allowlist + the
	// app-layer FC inside the user data.
	if !h.allowsPrimary(primaryFC) {
		return false
	}
	appFC, ok := extractAppFC(body)
	if !ok {
		// Can't find an app-layer FC — rare (truncated frame).
		// Refuse conservatively.
		return false
	}
	// Reads always pass. Writes + operations need explicit
	// allowance.
	if appFC == AppFCRead {
		return true
	}
	return h.allowsApp(appFC)
}

// allowsPrimary returns true when fc is in h.Allowed (or
// h.Allowed is empty and fc is one of the user-data FCs which
// default to allowed for reads only).
func (h *WriteGatedHandler) allowsPrimary(fc uint8) bool {
	if len(h.Allowed) == 0 {
		// No explicit primary allowlist: accept user-data frames
		// so the app-layer gate below makes the real decision.
		return fc == LinkFCConfirmedUserData || fc == LinkFCUnconfirmedUserData
	}
	for _, a := range h.Allowed {
		if a.PrimaryFC == fc {
			return true
		}
	}
	return false
}

// allowsApp returns true when the app-layer FC is in the
// AllowedAppFC list.
func (h *WriteGatedHandler) allowsApp(fc uint8) bool {
	for _, a := range h.AllowedAppFC {
		if a.FC == fc {
			return true
		}
	}
	return false
}

// extractAppFC pulls the application-layer FC from the first
// user-data block. DNP3 user data is laid out as:
//
//	[0]      Transport header (sequence + FIR/FIN)
//	[1]      App-layer header: AC (Application Control, 1 byte)
//	[2]      App-layer header: FC (Function Code, 1 byte)
//	[3..]    Objects
//
// Returns (fc, true) when at least 3 bytes are present.
func extractAppFC(body []byte) (uint8, bool) {
	if len(body) < 3 {
		return 0, false
	}
	return body[2], true
}

// buildFuncNotSuppResponse emits a minimal DNP3 user-data
// response with IIN2 bit 2 "FUNC_NOT_SUPP" set. The response is
// addressed back to the requesting master (swap src/dest from
// the request). Link-layer CRC is left zeroed — most masters
// don't validate the CRC strictly, and a correct CRC-16 would
// require bringing in the CRC table; v1.2 accepts this
// limitation. IIN1 = 0 (no class data, no device state flags).
// IIN2 = 0x04 (FUNC_NOT_SUPP).
func buildFuncNotSuppResponse(req wire.Header) []byte {
	// User data: transport header (1) + AC (1) + FC (1) + IIN (2)
	userData := []byte{
		0xC0,          // transport: FIR=1, FIN=1, seq=0
		0xC0,          // AC: FIR=1, FIN=1, CON=0, UNS=0, seq=0
		AppFCResponse, // app FC (0x81)
		0x00,          // IIN1
		0x04,          // IIN2: bit 2 = FUNC_NOT_SUPP
	}
	frame := make([]byte, wire.HeaderLen+len(userData))
	frame[0] = wire.StartBytes[0]
	frame[1] = wire.StartBytes[1]
	frame[2] = uint8(5 + len(userData))                 // #nosec G115 -- userData is a fixed 5-byte response                 // length
	frame[3] = 0x44                                     // control: DIR=1, PRM=0, FCV=0, FC=4 unconfirmed response
	binary.LittleEndian.PutUint16(frame[4:6], req.Src)  // dest = original src
	binary.LittleEndian.PutUint16(frame[6:8], req.Dest) // src  = original dest
	// CRC left zero — see docstring.
	copy(frame[wire.HeaderLen:], userData)
	return frame
}
