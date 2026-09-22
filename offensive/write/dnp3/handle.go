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

// WriteGatedHandler is the offensive replacement for the default DNP3
// deny-all proxy. Gating operates at four layers:
//
//  1. Link-layer PRIMARY function code (control byte low nibble when
//     PRM=1). `Allowed` scopes which primary functions pass.
//  2. Destination link address. A control / write to a broadcast
//     address (0xFFFD-0xFFFF) reaches every outstation at once and is
//     always refused. `AllowedLink`, when set, pins the accepted
//     master->outstation address pairs for mutating frames.
//  3. Application-layer function code. `AllowedAppFC` scopes the
//     app-layer functions; Read (0x01) is always allowed. Write,
//     Direct Operate and the restarts must be explicitly allowed.
//  4. Control Relay Output Block. `AllowedControlOutput`, when set,
//     scopes an Operate / Direct Operate to a (point-index,
//     control-code) allowlist, so an operator can permit LATCH on a
//     point yet still refuse TRIP / CLOSE on any breaker.
//
// Refusal path: a DNP3 user-data frame with an application-layer
// response carrying IIN2 bit 2 "FUNC_NOT_SUPP" (byte2 0x04), with
// correct CRCs. Real masters see a parseable "function not supported"
// indication rather than a TCP RST or a wire fault.
type WriteGatedHandler struct {
	// Target is the upstream host:port. Must match
	// confirm.Mutation.Target used to mint the session token.
	Target string
	// Allowed lists the link-layer primary function codes the
	// session accepts. Zero length forbids all primary frames except
	// Reset-Link (0), Test-Link (2), and Request-Link-Status (9),
	// which are transport-level.
	Allowed []AllowedControl
	// AllowedAppFC lists the application-layer function codes permitted
	// inside user-data frames (link-layer FC 3 + 4). Read (0x01) is
	// ALWAYS allowed and does not need an entry.
	AllowedAppFC []AllowedAppFunction
	// AllowedLink pins accepted master->outstation link-address pairs.
	// Empty disables the check. When set, a mutating frame whose
	// (Src, Dest) matches no pair is refused.
	AllowedLink []LinkPair
	// AllowedControlOutput scopes CROBs by (index-range, control-code).
	// Empty disables the check (Operate is gated by FC alone). When
	// set, every CROB in an Operate / Direct Operate must match.
	AllowedControlOutput []AllowedCROBControl
	// AllowedAnalogOutput scopes g41 setpoints by (index-range, value-
	// window). Empty disables the analog check. When either this or
	// AllowedControlOutput is set, a control's objects must match the
	// scope for their object type, and any other control object is
	// refused (fail-closed).
	AllowedAnalogOutput []AllowedAnalogControl
	// Deriver + Auditor drive the session-open Authorize call.
	Deriver confirm.KeyDeriver
	Auditor confirm.Auditor
	// SessionConfirm is the Confirm struct the CLI populates from
	// --accept-writes / --confirm-target / --confirm-token.
	SessionConfirm confirm.Confirm

	// OnIIN, when set, receives every notable Internal Indications
	// observation on the outstation->master path (device restart /
	// trouble / config-corrupt, and error-response bursts). Nil logs
	// to stderr. Observation never gates or alters the response.
	OnIIN func(IINEvent)
	// IINErrorBurstThreshold is the number of error-bearing responses
	// in a session that trips an enumeration/fuzzing alert. 0 uses the
	// default (defaultIINErrorBurst).
	IINErrorBurstThreshold int

	// authorised flips true after a successful Authorise.
	authorised bool
}

// AllowedAppFunction names an application-layer DNP3 function code
// (IEEE 1815 Table 4-1) the session accepts.
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
	AppFCResponse           uint8 = 0x81 // server -> client
)

// allowlist assembles the session's full allowlist for token binding.
func (h *WriteGatedHandler) allowlist() Allowlist {
	return Allowlist{
		Control:       h.Allowed,
		AppFC:         h.AllowedAppFC,
		Links:         h.AllowedLink,
		ControlOutput: h.AllowedControlOutput,
		AnalogOutput:  h.AllowedAnalogOutput,
	}
}

// Authorise opens the proxy session.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutation(h.Target, h.allowlist())
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise hasn't
// been called yet.
var ErrSessionNotAuthorised = errors.New("dnp3: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(client, upstream, client) }()
	go func() { errs <- h.forwardResponses(upstream, client) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

// forward reads full link-layer frames from the client (header + the
// block-CRC-framed user data), decides allow/refuse, and emits either
// the frame verbatim upstream or an IIN2 FUNC_NOT_SUPP refusal back to
// the client.
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
		// Read the on-wire body: user data interleaved with a 2-byte
		// CRC after each <=16-octet block.
		wireBody := make([]byte, wire.BodyLen(lh.Length))
		if len(wireBody) > 0 {
			if _, err := io.ReadFull(client, wireBody); err != nil {
				return err
			}
		}
		// De-block for inspection (verifies every block CRC). A
		// malformed frame fails closed.
		apdu, ok := wire.StripBlockCRCs(wireBody, int(lh.Length)-5)
		if !ok {
			if _, err := clientWriter.Write(buildFuncNotSuppResponse(lh)); err != nil {
				return err
			}
			continue
		}
		if h.shouldForward(lh, apdu) {
			if _, err := upstream.Write(append(hdr, wireBody...)); err != nil {
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
// always pass; 3/4 (user data) consult the destination address, the
// link-address pins, the app-layer FC and the CROB scope.
func (h *WriteGatedHandler) shouldForward(lh wire.Header, apdu []byte) bool {
	if lh.Control&0x40 == 0 {
		// Secondary frame (outstation -> master). Never originates on
		// the client side in our pipe; pass through.
		return true
	}
	primaryFC := lh.Control & 0x0F
	switch primaryFC {
	case LinkFCResetLink, LinkFCTestLink, LinkFCRequestLinkStatus:
		return true
	}
	if !h.allowsPrimary(primaryFC) {
		return false
	}
	appFC, ok := extractAppFC(apdu)
	if !ok {
		return false // truncated user data: refuse conservatively
	}
	// Reads always pass and are never scoped.
	if appFC == AppFCRead {
		return true
	}
	// A control or write to a broadcast address lands on every
	// outstation at once and cannot be scoped: always refuse.
	if wire.IsBroadcast(lh.Dest) {
		return false
	}
	// Link-address pinning applies to every mutating frame.
	if !h.allowsLink(lh.Src, lh.Dest) {
		return false
	}
	if !h.allowsApp(appFC) {
		return false
	}
	// Control-object scoping refines Operate / Direct Operate / Select
	// when the operator scopes either CROBs or analog setpoints.
	if wire.AppIsControl(appFC) && (len(h.AllowedControlOutput) > 0 || len(h.AllowedAnalogOutput) > 0) {
		return h.allowsControlObjects(apdu)
	}
	return true
}

// allowsPrimary returns true when fc is in h.Allowed (or h.Allowed is
// empty and fc is a user-data FC, so the app-layer gate decides).
func (h *WriteGatedHandler) allowsPrimary(fc uint8) bool {
	if len(h.Allowed) == 0 {
		return fc == LinkFCConfirmedUserData || fc == LinkFCUnconfirmedUserData
	}
	for _, a := range h.Allowed {
		if a.PrimaryFC == fc {
			return true
		}
	}
	return false
}

// allowsLink returns true when link-address pinning is disabled (empty
// list) or (src, dest) matches a pin (0 field = wildcard).
func (h *WriteGatedHandler) allowsLink(src, dest uint16) bool {
	if len(h.AllowedLink) == 0 {
		return true
	}
	for _, lp := range h.AllowedLink {
		if (lp.Src == 0 || lp.Src == src) && (lp.Dest == 0 || lp.Dest == dest) {
			return true
		}
	}
	return false
}

// allowsApp returns true when the app-layer FC is in AllowedAppFC.
func (h *WriteGatedHandler) allowsApp(fc uint8) bool {
	for _, a := range h.AllowedAppFC {
		if a.FC == fc {
			return true
		}
	}
	return false
}

// allowsControlObjects enforces the configured scope on a control's
// objects. A g12v1 CROB is checked against AllowedControlOutput, a g41
// Analog Output Block against AllowedAnalogOutput. A malformed control
// object, or one whose object type the operator did not scope, fails
// closed.
func (h *WriteGatedHandler) allowsControlObjects(apdu []byte) bool {
	objs := objectRegion(apdu)
	crobs, ok := wire.ExtractCROBs(objs)
	if !ok {
		return false // malformed g12v1
	}
	if len(crobs) > 0 {
		if len(h.AllowedControlOutput) == 0 {
			return false // CROBs not authorised in this session
		}
		for _, p := range crobs {
			if !h.crobPermitted(p) {
				return false
			}
		}
		return true
	}
	analogs, ok := wire.ExtractAnalogOutputs(objs)
	if !ok {
		return false // malformed g41
	}
	if len(analogs) > 0 {
		if len(h.AllowedAnalogOutput) == 0 {
			return false // analog setpoints not authorised in this session
		}
		for _, p := range analogs {
			if !h.analogPermitted(p) {
				return false
			}
		}
		return true
	}
	// A control carrying neither a CROB nor an analog output we scope.
	return false
}

// analogPermitted reports whether a single (index, value) setpoint
// matches any AllowedAnalogOutput entry.
func (h *WriteGatedHandler) analogPermitted(p wire.AnalogPoint) bool {
	for _, a := range h.AllowedAnalogOutput {
		if p.Index < a.IndexStart || p.Index > a.IndexEnd {
			continue
		}
		if !a.Bounded || (p.Value >= a.Min && p.Value <= a.Max) {
			return true
		}
	}
	return false
}

// crobPermitted reports whether a single (index, control-code) matches
// any AllowedControlOutput entry.
func (h *WriteGatedHandler) crobPermitted(p wire.ControlPoint) bool {
	for _, c := range h.AllowedControlOutput {
		if p.Index < c.IndexStart || p.Index > c.IndexEnd {
			continue
		}
		if len(c.Codes) == 0 {
			return true
		}
		for _, code := range c.Codes {
			if code == p.ControlCode {
				return true
			}
		}
	}
	return false
}

// extractAppFC pulls the application-layer FC from the de-blocked user
// data:
//
//	[0]   Transport header (sequence + FIR/FIN)
//	[1]   Application control (AC)
//	[2]   Function code (FC)
//	[3..] Objects
func extractAppFC(apdu []byte) (uint8, bool) {
	if len(apdu) < 3 {
		return 0, false
	}
	return apdu[2], true
}

// objectRegion returns the object bytes that follow the app-layer
// header (transport + AC + FC), or nil when there are none.
func objectRegion(apdu []byte) []byte {
	if len(apdu) < 3 {
		return nil
	}
	return apdu[3:]
}

// buildFuncNotSuppResponse emits a well-formed DNP3 user-data response
// with IIN2 bit 2 "FUNC_NOT_SUPP" set, addressed back to the
// requesting master (src/dest swapped). Header and data-block CRCs are
// computed: a zeroed CRC would itself read as a wire fault on port
// 20000. IIN1 = 0, IIN2 = 0x04 (FUNC_NOT_SUPP).
func buildFuncNotSuppResponse(req wire.Header) []byte {
	userData := []byte{
		0xC0,          // transport: FIR=1, FIN=1, seq=0
		0xC0,          // AC: FIR=1, FIN=1, CON=0, UNS=0, seq=0
		AppFCResponse, // app FC (0x81)
		0x00,          // IIN1
		0x04,          // IIN2: bit 2 = FUNC_NOT_SUPP
	}
	body := wire.AppendBlockCRCs(userData)
	frame := make([]byte, wire.HeaderLen+len(body))
	frame[0] = wire.StartBytes[0]
	frame[1] = wire.StartBytes[1]
	frame[2] = uint8(5 + len(userData))                 // #nosec G115 -- fixed 5-byte user data
	frame[3] = 0x44                                     // control: PRM=1, FC=4 (unconfirmed user data)
	binary.LittleEndian.PutUint16(frame[4:6], req.Src)  // dest = original src
	binary.LittleEndian.PutUint16(frame[6:8], req.Dest) // src  = original dest
	crc := wire.CRC16(frame[0:8])
	binary.LittleEndian.PutUint16(frame[8:10], crc)
	copy(frame[wire.HeaderLen:], body)
	return frame
}
