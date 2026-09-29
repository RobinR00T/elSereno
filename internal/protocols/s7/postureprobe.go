package s7

import (
	"context"
	"io"

	"local/elsereno/internal/protocols/s7/wire"
)

// PostureResult is the full S7 CPU posture read in one connection: what the
// CPU is (identity + firmware) and whether it accepts writes/control
// without a password (protection). It is the one-shot report an auditor
// runs first. Read-only recon.
type PostureResult struct {
	IsS7    bool
	SetupOK bool

	// Identity (SZL 0x0011 + 0x001C).
	OrderNumber      string
	Firmware         string
	ModuleType       string
	SerialNumber     string
	StationName      string
	PlantDesignation string

	// Protection (SZL 0x0132 index 4).
	ProtectionRead bool
	Protection     wire.ProtectionRecord
	Exposed        bool
}

// ProbePosture drives one S7 handshake and reads identity + protection in a
// single connection: COTP CR/CC -> Setup Communication -> Read SZL 0x0011
// -> 0x001C -> 0x0132/4. Strictly read-only. The caller sets deadlines on
// conn.
func ProbePosture(ctx context.Context, conn io.ReadWriter) (PostureResult, error) {
	var res PostureResult
	if err := ctx.Err(); err != nil {
		return res, err
	}

	isS7, setupOK, err := s7Handshake(conn)
	res.IsS7 = isS7
	res.SetupOK = setupOK
	if err != nil || !setupOK {
		return res, err
	}

	mi, err := readModuleIdentInfo(conn)
	if err != nil {
		return res, err
	}
	res.OrderNumber = mi.orderNumber
	res.Firmware = mi.firmware

	ci, err := readComponentIdentInfo(conn)
	if err != nil {
		return res, err
	}
	res.ModuleType = ci.moduleType
	res.SerialNumber = ci.serialNumber
	res.StationName = ci.stationName
	res.PlantDesignation = ci.plantDesignation

	rec, ok, err := readProtectionRecord(conn)
	if err != nil {
		return res, err
	}
	if ok {
		res.ProtectionRead = true
		res.Protection = rec
		res.Exposed = rec.RealLevel <= 1
	}
	return res, nil
}
