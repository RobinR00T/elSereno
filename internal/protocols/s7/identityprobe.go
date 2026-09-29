package s7

import (
	"context"
	"io"

	"local/elsereno/internal/protocols/s7/wire"
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
	IsS7    bool
	SetupOK bool

	// From SZL 0x0011 (Module Identification):
	OrderNumber string // MLFB, e.g. "6ES7 151-8AB01-0AB0"
	Firmware    string // e.g. "V3.2.6"

	// From SZL 0x001C (Component Identification):
	ModuleType       string
	SerialNumber     string
	StationName      string
	PlantDesignation string
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
	if err := res.applyModuleIdent(conn); err != nil {
		return res, err
	}
	if err := res.applyComponentIdent(conn); err != nil {
		return res, err
	}
	return res, nil
}

// applyModuleIdent reads SZL 0x0011 and fills the order number + firmware.
// A read/parse miss is not an error (the field stays empty); only a
// transport error propagates.
func (res *IdentityResult) applyModuleIdent(conn io.ReadWriter) error {
	pdu, ok, err := readSZL(conn, identPDURefModule, wire.SZLIDModuleIdent, 0)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	recs, ok := wire.ParseModuleIdent(pdu)
	if !ok {
		return nil
	}
	for _, r := range recs {
		switch r.Index {
		case wire.ModuleIndexOrderNumber:
			if res.OrderNumber == "" {
				res.OrderNumber = r.MLFB
			}
		case wire.ModuleIndexFirmware:
			if r.Version != "" {
				res.Firmware = r.Version
			}
		}
	}
	return nil
}

// applyComponentIdent reads SZL 0x001C and fills the module type, serial,
// station name and plant designation.
func (res *IdentityResult) applyComponentIdent(conn io.ReadWriter) error {
	pdu, ok, err := readSZL(conn, identPDURefComp, wire.SZLIDComponentIdent, 0)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	recs, ok := wire.ParseComponentIdent(pdu)
	if !ok {
		return nil
	}
	for _, r := range recs {
		switch r.Index {
		case wire.ComponentIndexModuleType:
			res.ModuleType = r.Text
		case wire.ComponentIndexSerial:
			res.SerialNumber = r.Text
		case wire.ComponentIndexStationName:
			res.StationName = r.Text
		case wire.ComponentIndexPlantDesig:
			res.PlantDesignation = r.Text
		}
	}
	return nil
}
