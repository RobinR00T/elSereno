package s7

import (
	"context"
	"fmt"
	"io"

	"local/elsereno/internal/protocols/s7/wire"
)

// The pduRefs the probe uses to correlate its requests. They are opaque
// to the PLC (it echoes them), so any distinct values work.
const (
	setupPDURef uint16 = 0x0001
	szlPDURef   uint16 = 0x0002
)

// ProtectionResult reports what the CPU protection-level probe learned.
// It is read-only recon: the probe reads the protection SZL, it never
// writes, controls, or stops the PLC.
type ProtectionResult struct {
	// IsS7 is true once the PLC answered the COTP Connection Request with
	// a Connection Confirm (this port speaks TPKT/COTP, almost always S7).
	IsS7 bool
	// SetupOK is true once S7 Setup Communication succeeded.
	SetupOK bool
	// ProtectionRead is true when the Read SZL 0x0132/4 returned a
	// protection record. A CPU can succeed at Setup yet refuse the SZL
	// read (itself a sign of a locked-down CPU), leaving this false.
	ProtectionRead bool
	// Record is the decoded protection record (valid when ProtectionRead).
	Record wire.ProtectionRecord
	// Exposed is the headline: the CPU's effective protection level is 0
	// or 1, i.e. no read/write password is enforced, so a stranger can
	// write or control it (subject to the key-switch position).
	Exposed bool
}

// ProbeProtection drives the S7 handshake over conn and reads the CPU
// protection SZL: COTP Connection Request/Confirm -> Setup Communication
// -> UserData Read SZL 0x0132 index 4. It fills the result step by step
// and stops (without error) at the first step that says "not exposed / not
// readable". The caller sets read/write deadlines on conn. Read-only.
func ProbeProtection(ctx context.Context, conn io.ReadWriter) (ProtectionResult, error) {
	var res ProtectionResult
	if err := ctx.Err(); err != nil {
		return res, err
	}

	isS7, setupOK, err := s7Handshake(conn)
	res.IsS7 = isS7
	res.SetupOK = setupOK
	if err != nil || !setupOK {
		return res, err
	}

	// UserData Read SZL 0x0132 index 4 (CPU protection).
	rec, ok, err := readProtectionRecord(conn)
	if err != nil {
		return res, err
	}
	if !ok {
		return res, nil // CPU refused/empty SZL read (SetupOK stays a useful signal)
	}
	res.ProtectionRead = true
	res.Record = rec
	res.Exposed = rec.RealLevel <= 1
	return res, nil
}

// ProtectionLevelText renders an effective protection level as a short
// human label.
func ProtectionLevelText(level uint16) string {
	switch level {
	case 0:
		return "0 (undefined / none enforced)"
	case 1:
		return "1 (no password; access via key switch only)"
	case 2:
		return "2 (write-protected; write needs password)"
	case 3:
		return "3 (read+write protected)"
	default:
		return fmt.Sprintf("%d (unknown)", level)
	}
}

// ModeSelectorText renders a mode-selector (bart_sch) value as a label.
func ModeSelectorText(v uint16) string {
	switch v {
	case wire.ModeSelectorRUN:
		return "RUN"
	case wire.ModeSelectorRUNP:
		return "RUN-P (programming enabled)"
	case wire.ModeSelectorSTOP:
		return "STOP"
	case wire.ModeSelectorMRES:
		return "MRES"
	default:
		return fmt.Sprintf("%d (undefined / no switch)", v)
	}
}
