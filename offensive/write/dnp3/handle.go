//go:build offensive

package dnp3

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"

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
	// Allowed lists the link-layer primary function codes the session
	// accepts for user data. Zero length lets both user-data functions
	// (3 and 4) through to the application-layer gate. Reset-Link (0),
	// Test-Link (2) and Request-Link-Status (9) always pass, header-only;
	// any other function is an invalid frame and is discarded first.
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

// Discard logging. The master side decides how many frames the gate
// discards, so after the first discardLogBurst in a session only every
// discardLogEvery-th is logged, with the running count.
const (
	discardLogBurst = 3
	discardLogEvery = 1000
)

func logDiscard(n int, reason error) {
	if n <= discardLogBurst || n%discardLogEvery == 0 {
		log.Printf("dnp3: discarded from the master side (%d this session): %v", n, reason)
	}
}

// maxHeldRequest caps the application octets (after the transport
// octet) the gate holds while it reassembles a multi-segment request; a
// larger request is discarded.
const maxHeldRequest = 2048

// heldRequest is a request the gate judges as one: a single frame, or
// the transport segments of a multi-segment request.
type heldRequest struct {
	first  wire.Header // header of the first segment
	frames []byte      // the frames, verbatim and in order
	apdu   []byte      // the first segment's user data + the application octets of the rest
	next   uint8       // transport sequence the next segment must carry
	contOK bool        // every continuation segment's link function is allowed
	multi  bool        // more than one segment
	read   bool        // the first segment carries the application header of a Read
}

// reassembler holds the segments of a multi-segment request until the
// one carrying FIN arrives, so that the gate judges the whole
// application fragment instead of one segment at a time.
type reassembler struct {
	held          *heldRequest
	allowsPrimary func(uint8) bool
}

// add takes one user-data frame that passed CheckToOutstation. It
// returns the complete request to judge, or nil while segments are
// held; a non-nil reason names something discarded, to log.
func (a *reassembler) add(lh wire.Header, frame, apdu []byte) (done *heldRequest, reason error) {
	th := apdu[0]
	seq := th & wire.TransportSeqMask
	if th&wire.TransportFIR != 0 {
		if a.held != nil {
			reason = errors.New("a new first segment dropped an incomplete multi-segment request")
		}
		a.held = &heldRequest{
			first: lh, frames: frame, apdu: apdu, next: (seq + 1) & wire.TransportSeqMask, contOK: true,
			read: len(apdu) >= 3 && apdu[2] == AppFCRead,
		}
	} else {
		h := a.held
		switch {
		case h == nil:
			return nil, errors.New("a continuation segment without a first segment")
		case seq != h.next || lh.Src != h.first.Src || lh.Dest != h.first.Dest:
			a.held = nil
			return nil, errors.New("a segment out of sequence or from another address pair dropped the held request")
		}
		h.frames = append(h.frames, frame...)
		h.apdu = append(h.apdu, apdu[1:]...)
		h.next = (seq + 1) & wire.TransportSeqMask
		h.contOK = h.contOK && a.allowsPrimary(lh.Control&0x0F)
		h.multi = true
		if len(h.apdu)-1 > maxHeldRequest {
			a.held = nil
			return nil, fmt.Errorf("a multi-segment request above %d octets", maxHeldRequest)
		}
	}
	if th&wire.TransportFIN == 0 {
		return nil, reason
	}
	done, a.held = a.held, nil
	return done, reason
}

// forward reads full link-layer frames from the client (header + the
// block-CRC-framed user data) and does one of three things: discards a
// frame that fails AN2013-004b Table 1, without a reply; forwards an
// allowed request verbatim upstream; or answers a refused one with an
// IIN2 FUNC_NOT_SUPP response.
//
// A request is judged whole. The segments of a multi-segment request
// are held until the one carrying FIN arrives and then forwarded or
// refused together; a continuation without a first segment, out of
// sequence or from another address pair is discarded. Only a Read may
// span several segments: the gate cannot know which segments the
// outstation's link layer accepts (a DIR=0 frame, a Confirmed User Data
// frame with an unexpected FCB, a frame of LENGTH 6 may be dropped
// there), and if it drops one, the segments of two requests can join
// into one the gate never judged. With every multi-segment request a
// Read whose function sits in its first segment, whatever the
// outstation reassembles is a single frame the gate judged, or a Read.
// Until 2026-10-14 the gate judged each frame on its own and read the
// function code at the same offset of every segment, so a Direct
// Operate split in two passed with only its first segment checked
// (PITF-082). Limits: a control or write too long for one frame (about
// 249 application octets) is refused; and a master that asks for a link
// confirmation of each segment waits for an ACK the gate only lets
// through once the request is complete, and times out.
func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	r := bufio.NewReader(client)
	discards := 0
	discard := func(reason error) {
		discards++
		logDiscard(discards, reason)
	}
	asm := reassembler{allowsPrimary: h.allowsPrimary}
	for {
		// ReadFrame skips octets that do not start a valid header (start
		// octets, LENGTH, header CRC) and reads the body as user data
		// interleaved with a 2-byte CRC after each <=16-octet block.
		lh, hdr, wireBody, skipped, err := wire.ReadFrame(r)
		if err != nil {
			return err
		}
		if skipped > 0 {
			discard(fmt.Errorf("%d octets before a valid link header", skipped))
		}
		// AN2013-004b Table 1 first: a frame a conformant outstation
		// would discard is discarded here too, without a reply. This
		// also verifies every block CRC and de-blocks the user data.
		apdu, err := wire.CheckToOutstation(lh, wireBody)
		if err != nil {
			discard(err)
			continue
		}
		frame := make([]byte, 0, len(hdr)+len(wireBody))
		frame = append(append(frame, hdr...), wireBody...)
		if !wire.IsUserData(lh.Control) {
			// Header-only link frames (Reset Link, Test Link, Request
			// Link Status, the master's link replies) carry no request;
			// they pass, also between the segments of a held request.
			if h.shouldForward(lh, nil) {
				if _, err := upstream.Write(frame); err != nil {
					return err
				}
			}
			continue
		}
		req, reason := asm.add(lh, frame, apdu)
		if reason != nil {
			discard(reason)
		}
		if req == nil {
			continue
		}
		if err := h.decide(req, upstream, clientWriter); err != nil {
			return err
		}
	}
}

// decide forwards a complete request (one frame or the held segments)
// or answers it with a refusal. A multi-segment request passes only if
// it is a Read (see forward).
func (h *WriteGatedHandler) decide(req *heldRequest, upstream, clientWriter io.Writer) error {
	first, frames, apdu := req.first, req.frames, req.apdu
	if req.contOK && (!req.multi || req.read) && h.shouldForward(first, apdu) {
		_, err := upstream.Write(frames)
		return err
	}
	_, err := clientWriter.Write(buildFuncNotSuppResponse(first))
	return err
}

// shouldForward applies the gate to a frame that passed
// wire.CheckToOutstation. Transport-level link FCs (0,2,9) always pass,
// header-only; 3/4 (user data) consult the destination address, the
// link-address pins, the app-layer FC and the CROB scope.
func (h *WriteGatedHandler) shouldForward(lh wire.Header, apdu []byte) bool {
	if lh.Control&0x40 == 0 {
		// Secondary frame: a header-only link reply the master returns
		// to the outstation (ACK, NACK, LINK_STATUS, NOT SUPPORTED);
		// CheckToOutstation refused any other secondary function and
		// any body. Until 2026-10-14 every PRM=0 frame passed here with
		// its body and skipped all four layers (PITF-081).
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
	// Every object header counts: the outstation acts on all of them.
	// Until 2026-10-14 only the first was read, so a TRIP in a second
	// header of an allowed LATCH passed (PITF-082).
	crobs, analogs, ok := wire.ExtractControlObjects(objectRegion(apdu))
	if !ok {
		return false // malformed, left-over octets, or an object type we do not scope
	}
	if len(crobs) == 0 && len(analogs) == 0 {
		return false // a control carrying neither a CROB nor an analog output
	}
	if len(crobs) > 0 && len(h.AllowedControlOutput) == 0 {
		return false // CROBs not authorised in this session
	}
	for _, p := range crobs {
		if !h.crobPermitted(p) {
			return false
		}
	}
	if len(analogs) > 0 && len(h.AllowedAnalogOutput) == 0 {
		return false // analog setpoints not authorised in this session
	}
	for _, p := range analogs {
		if !h.analogPermitted(p) {
			return false
		}
	}
	return true
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
