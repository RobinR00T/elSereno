package s7

import (
	"context"
	"io"
)

// pduRefs for the two identity SZL reads (opaque, echoed by the PLC).
const (
	identPDURefModule uint16 = 0x0003
	identPDURefComp   uint16 = 0x0004
)

// IdentityResult reports the CPU identity/firmware the probe read. Fields
// are empty when the CPU did not return them. It is read-only recon.
type IdentityResult struct {
	// IsS7 / SetupOK mirror the handshake (see ProtectionResult).
	IsS7    bool `json:"is_s7"`
	SetupOK bool `json:"setup_ok"`

	// From SZL 0x0011 (Module Identification):
	OrderNumber string `json:"order_number"` // MLFB, e.g. "6ES7 151-8AB01-0AB0"
	Firmware    string `json:"firmware"`     // e.g. "V3.2.6"

	// From SZL 0x001C (Component Identification):
	ModuleType       string `json:"module_type"`
	SerialNumber     string `json:"serial_number"`
	StationName      string `json:"station_name"`
	PlantDesignation string `json:"plant_designation"`
}

// ProbeIdentity drives the S7 handshake and reads the two identity SZL
// lists: COTP CR/CC -> Setup Communication -> Read SZL 0x0011 (module) ->
// Read SZL 0x001C (component). It pins the exact CPU + firmware, which a
// CVE / advisory lookup needs. Strictly read-only. The caller sets
// deadlines on conn.
func ProbeIdentity(ctx context.Context, conn io.ReadWriter) (IdentityResult, error) {
	var res IdentityResult
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
	return res, nil
}
