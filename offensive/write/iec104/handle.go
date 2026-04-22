//go:build offensive

package iec104

import (
	"context"
	"errors"
	"fmt"
	"io"

	"local/elsereno/internal/protocols/iec104/wire"
	"local/elsereno/offensive/confirm"
)

// WriteGatedHandler enforces IEC 60870-5-104 ASDU-type-ID gating.
// I-format frames carry ASDU payloads; the Type Identifier is
// the first byte of the ASDU (APCI offset 6).
//
// U-format (STARTDT/STOPDT/TESTFR) and S-format (supervisory)
// frames are transport-level and always pass. I-format frames
// with an ASDU Type ID in the allowlist are forwarded; those
// outside the allowlist get a protocol-native ACT_CON (Activation
// Confirmation) response with COT (Cause of Transmission) = 47
// "activation not supported".
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedASDU
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	authorised bool
}

// IEC 60870-5-104 ASDU Type IDs (§7.3.1.1) relevant to the gate.
const (
	TypeIDSingleCommand      uint8 = 45  // C_SC_NA_1 — write single
	TypeIDDoubleCommand      uint8 = 46  // C_DC_NA_1
	TypeIDRegulatingStep     uint8 = 47  // C_RC_NA_1
	TypeIDSetpointNormalised uint8 = 48  // C_SE_NA_1 — setpoint
	TypeIDSetpointScaled     uint8 = 49  // C_SE_NB_1
	TypeIDSetpointShortFloat uint8 = 50  // C_SE_NC_1
	TypeIDBitstringCommand   uint8 = 51  // C_BO_NA_1
	TypeIDInterrogation      uint8 = 100 // C_IC_NA_1 — ask for full state
	TypeIDCounterRequest     uint8 = 101 // C_CI_NA_1
	TypeIDClockSync          uint8 = 103 // C_CS_NA_1 — write clock
	TypeIDResetProcess       uint8 = 105 // C_RP_NA_1 — reset!
)

// COT codes (§7.4) referenced in refusals.
const (
	COTUnknownType       uint8 = 44
	COTUnknownCOT        uint8 = 45
	COTUnknownCA         uint8 = 46
	COTUnknownIOA        uint8 = 47
	COTActivationNotSupp uint8 = 47 // same numeric: "unknown IOA" doubles as "act not supp" by convention
	COTPositiveConfirm   uint8 = 7
	COTNegativeConfirm   uint8 = 71
)

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
var ErrSessionNotAuthorised = errors.New("iec104: write-gated proxy requires Authorise() first")

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
	apci := make([]byte, wire.APCILen)
	for {
		if _, err := io.ReadFull(client, apci); err != nil {
			return err
		}
		a, err := wire.ParseAPCI(apci)
		if err != nil {
			return fmt.Errorf("iec104: parse APCI: %w", err)
		}
		asduLen := int(a.Length) - 4 // APDULength excludes Start+Length, includes Control(4) + ASDU
		if asduLen < 0 {
			asduLen = 0
		}
		asdu := make([]byte, asduLen)
		if asduLen > 0 {
			if _, err := io.ReadFull(client, asdu); err != nil {
				return err
			}
		}
		if h.shouldForward(a, asdu) {
			if _, err := upstream.Write(append(apci, asdu...)); err != nil {
				return err
			}
			continue
		}
		if _, err := clientWriter.Write(buildActNotSupp(asdu)); err != nil {
			return err
		}
	}
}

// shouldForward: U/S frames always pass; I-frames consult the
// ASDU Type ID allowlist.
func (h *WriteGatedHandler) shouldForward(a wire.APCI, asdu []byte) bool {
	if a.Type() != wire.FrameI {
		return true
	}
	if len(asdu) == 0 {
		// I-frame with no ASDU body is malformed; pass through so
		// the server can error.
		return true
	}
	typeID := asdu[0]
	return h.isAllowed(typeID)
}

func (h *WriteGatedHandler) isAllowed(t uint8) bool {
	for _, a := range h.Allowed {
		if a.TypeID == t {
			return true
		}
	}
	return false
}

// buildActNotSupp crafts an I-format response with the same
// ASDU Type ID + COT = COTActivationNotSupp (negative confirm).
// Minimal body: Type(1) + VSQ(1) + COT(2) + CA(2) = 6 bytes.
// If the original ASDU can't be mirrored (too short), we send
// a generic U-format TESTFR-ish refusal with Control 0x00 so
// the master at least sees a response.
func buildActNotSupp(asdu []byte) []byte {
	if len(asdu) < 6 {
		// Fallback: emit a minimal S-format "short supervisory"
		// reply. Control bytes: 0x01 = S-format.
		return []byte{wire.Start, 0x04, 0x01, 0x00, 0x00, 0x00}
	}
	// Mirror Type + VSQ + Common Address; set COT to 47 + P/N
	// bit = 1 (negative confirm) per §7.2.3.
	typeID := asdu[0]
	vsq := asdu[1] & 0x7F // drop SQ bit (only one element in our reply)
	// COT byte 0: P/N (bit 6) = 1 negative, T (bit 7) = 0. Low
	// 6 bits = cause value.
	cot0 := uint8(0x40) | COTActivationNotSupp
	// Common Address: keep the original 2 bytes.
	ca0 := asdu[4]
	ca1 := asdu[5]
	// Build I-format reply. Control 0x00 0x00 0x00 0x00 is fine
	// (send-seq = 0; master tolerates reset sequence on a fault).
	body := []byte{
		typeID,
		vsq,
		cot0,
		0x00, // COT byte 1 (Originator Address) = 0
		ca0, ca1,
	}
	apdu := make([]byte, 0, wire.APCILen+len(body))
	// #nosec G115 — body is a fixed 6-byte refusal; length fits uint8
	apdu = append(apdu, wire.Start, uint8(4+len(body)))
	apdu = append(apdu, 0x00, 0x00, 0x00, 0x00) // Control (I-format, seqs 0)
	apdu = append(apdu, body...)
	return apdu
}
