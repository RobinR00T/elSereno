package wire

import (
	"errors"
	"io"
)

// M-Bus control-field catalogue used by the offensive write
// gate (v1.56). The fingerprint plugin (v1.21 chunk 2) only
// needed the REQ_UD2 (0x5B) constant; offensive gating needs
// the wider catalogue so the gate can classify any frame the
// client sends.
//
// Control fields are 4-bit direction + 1-bit FCB (frame count
// bit) + 1-bit FCV (FCB valid) + 4-bit function. EN 13757-3
// §5.5 enumerates them. Master-to-slave functions:
//
//	0x40  SND_NKE       send link reset (always-safe)
//	0x53  SND_UD        send user data (data-bearing write)
//	0x73  SND_UD        send user data, alt FCB/FCV pattern
//	0x5A  REQ_UD1       request user data class 1 (alarms)
//	0x5B  REQ_UD2       request user data class 2 (canonical read)
//	0x7A  REQ_UD1       request user data class 1, alt FCB pattern
//	0x7B  REQ_UD2       request user data class 2, alt FCB pattern
//
// Slave-to-master:
//
//	0x08  RSP_UD        respond user data
//	0x0B  ACK / response with FCB
//	0xE5  single-byte ACK (special: not framed)
//
// Mutating from the gate's perspective: SND_UD and SND_NKE.
// SND_NKE is link-reset only (no payload), so it's safe in
// practice — operators who want to refuse it can leave it off
// the always-safe list, but the default posture is safe.
const (
	// ControlSNDNKE is the link-reset send (0x40). Always-safe:
	// no payload, just resets the FCB toggle on the slave.
	ControlSNDNKE byte = 0x40
	// ControlSNDUD is "send user data" with FCB=0 (0x53). The
	// flagship write control: every parameter write, baud
	// reconfigure, primary-address reassign, application-reset
	// rides this control + a CI byte that selects the operation.
	ControlSNDUD byte = 0x53
	// ControlSNDUDFCB is "send user data" with FCB=1 (0x73). Same
	// semantics as 0x53; FCB toggles on retransmit.
	ControlSNDUDFCB byte = 0x73
	// ControlREQUD1 is request alarms class 1 (0x5A).
	ControlREQUD1 byte = 0x5A
	// ControlREQUD1FCB alt pattern (0x7A).
	ControlREQUD1FCB byte = 0x7A
	// ControlREQUD2FCB is REQ_UD2 with FCB=1 (0x7B).
	ControlREQUD2FCB byte = 0x7B
)

// CI byte catalogue (master → slave). Identifies what kind of
// payload follows a SND_UD. Per EN 13757-3 §6.4 + §7.5.
//
//	0x50  Application Reset             reset internal state
//	0x51  Data send                     parameter write payload
//	0x52  Selection of slave            secondary-address select
//	0x53  Application Reset (extended)
//	0x54  Authentication                send password
//	0x55  Sync Action                   counter sync (DESTRUCTIVE)
//	0x56  Set baudrate to 300 bps       reconfigure link
//	0x57  Set baudrate to 600 bps
//	0x58  Set baudrate to 1200 bps
//	0x59  Set baudrate to 2400 bps
//	0x5A  Set baudrate to 4800 bps
//	0x5B  Set baudrate to 9600 bps
//	0x5C  Set baudrate to 19200 bps
//	0x5D  Set baudrate to 38400 bps
//	0xB1  Reset application
//	0xB2..0xBC  Manufacturer-specific writes
const (
	// CIAppReset is "Application Reset" (0x50). Soft-reset the
	// meter's internal state (clears tariff buffers, retariffs).
	CIAppReset byte = 0x50
	// CIDataSend is "Data send" (0x51) — the dominant write CI.
	// Parameter values + tariff configuration ride this.
	CIDataSend byte = 0x51
	// CISelectSlave is secondary-address selection (0x52). Not
	// strictly mutating but routes subsequent SND_UD to the
	// selected slave.
	CISelectSlave byte = 0x52
	// CISyncAction is "Sync Action" (0x55) — sync counters across
	// a meter group. DESTRUCTIVE: typically resets all slaves.
	CISyncAction byte = 0x55
	// CISetBaudBase is the start of the "set baudrate to X" range
	// (0x56..0x5D). Reconfigures the slave's link speed; if the
	// operator's gateway is bridged to a wired M-Bus link, this
	// can desynchronise the gateway from the meters.
	CISetBaudBase byte = 0x56
	// CISetBaudEnd marks the inclusive end of the set-baud range
	// (0x5D = 38400 bps).
	CISetBaudEnd byte = 0x5D
)

// Stream-parser sentinels.
var (
	// ErrFrameUnknownStart means the start byte is neither 0x68
	// (long), 0x10 (short), nor 0xE5 (single-byte ACK).
	ErrFrameUnknownStart = errors.New("mbustcp: frame start byte is not 0x68, 0x10, or 0xE5")
)

// Frame captures a single parsed M-Bus frame off the wire.
// Short frames have no UD; long frames have UD payload + CI byte.
// ACK frames are 1 byte and have no other fields populated.
type Frame struct {
	// Raw is the verbatim wire bytes (for forwarding without
	// reconstruction).
	Raw []byte
	// IsACK is true for the single-byte 0xE5 ACK.
	IsACK bool
	// IsShort is true for 5-byte 0x10 ... 0x16 short frames.
	IsShort bool
	// IsLong is true for 0x68 ... 0x16 long frames.
	IsLong bool
	// Control is the control byte (offset depends on shape).
	// Zero on ACK.
	Control byte
	// Address is the primary address (offset depends on shape).
	// Zero on ACK.
	Address byte
	// CI is the control-information byte (long frames only;
	// indicates the SND_UD operation).
	CI byte
}

// ReadFrame reads a single M-Bus frame from r. Buffers as much
// as needed for the declared length, returning the verbatim
// wire bytes plus the parsed metadata. Errors fall into:
//
//   - io.EOF / io.ErrUnexpectedEOF if the stream closes mid-frame
//   - ErrFrameUnknownStart if the start byte is unrecognised
//   - ErrLengthMismatch if the long-frame L bytes disagree
//   - ErrBadStop if the long-frame trailer isn't 0x16
//
// The function is deliberately conservative: any structural
// problem returns an error, which the gate uses to refuse the
// session. We don't try to recover.
func ReadFrame(r io.Reader) (Frame, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return Frame{}, err
	}
	switch first[0] {
	case ACKByte:
		return Frame{Raw: []byte{ACKByte}, IsACK: true}, nil
	case StartShort:
		return readShortFrame(r, first[0])
	case StartLong:
		return readLongFrame(r, first[0])
	default:
		return Frame{}, ErrFrameUnknownStart
	}
}

// readShortFrame consumes the remaining 4 bytes of a 5-byte
// short frame after the leading 0x10 has been read.
func readShortFrame(r io.Reader, start byte) (Frame, error) {
	tail := make([]byte, 4)
	if _, err := io.ReadFull(r, tail); err != nil {
		return Frame{}, err
	}
	if tail[3] != StopByte {
		return Frame{}, ErrBadStop
	}
	cs := tail[0] + tail[1]
	if cs != tail[2] {
		return Frame{}, ErrChecksumMismatch
	}
	raw := make([]byte, 5)
	raw[0] = start
	copy(raw[1:], tail)
	return Frame{
		Raw:     raw,
		IsShort: true,
		Control: tail[0],
		Address: tail[1],
	}, nil
}

// readLongFrame consumes the remainder of a long frame after
// the leading 0x68 has been read. The wire shape is
// 0x68 L L 0x68 [body of L bytes] CS 0x16, so we read L L 0x68
// first, then L bytes of body, then CS + 0x16.
func readLongFrame(r io.Reader, start byte) (Frame, error) {
	hdr := make([]byte, 3) // L L 0x68
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Frame{}, err
	}
	if hdr[0] != hdr[1] {
		return Frame{}, ErrLengthMismatch
	}
	if hdr[2] != StartLong {
		return Frame{}, ErrBadStart
	}
	bodyLen := int(hdr[0])
	if bodyLen < 3 {
		// Body must contain at least C, A, CI.
		return Frame{}, ErrShortFrame
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, err
	}
	tail := make([]byte, 2) // CS + Stop
	if _, err := io.ReadFull(r, tail); err != nil {
		return Frame{}, err
	}
	if tail[1] != StopByte {
		return Frame{}, ErrBadStop
	}
	var cs byte
	for _, b := range body {
		cs += b
	}
	if cs != tail[0] {
		return Frame{}, ErrChecksumMismatch
	}
	raw := make([]byte, 4+bodyLen+2)
	raw[0] = start
	raw[1] = hdr[0]
	raw[2] = hdr[1]
	raw[3] = hdr[2]
	copy(raw[4:4+bodyLen], body)
	raw[4+bodyLen] = tail[0]
	raw[4+bodyLen+1] = tail[1]
	return Frame{
		Raw:     raw,
		IsLong:  true,
		Control: body[0],
		Address: body[1],
		CI:      body[2],
	}, nil
}

// IsSNDUD reports whether the frame is a SND_UD (any FCB).
func (f Frame) IsSNDUD() bool {
	return f.IsLong && (f.Control == ControlSNDUD || f.Control == ControlSNDUDFCB)
}

// IsAlwaysSafeControl reports whether the control byte falls in
// the read/keep-alive set: SND_NKE, REQ_UD1, REQ_UD2.
func (f Frame) IsAlwaysSafeControl() bool {
	if !f.IsShort && !f.IsLong {
		return false
	}
	switch f.Control {
	case ControlSNDNKE, ControlREQUD1, ControlREQUD1FCB, ControlREQUD2, ControlREQUD2FCB:
		return true
	}
	return false
}
