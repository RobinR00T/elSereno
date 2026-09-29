package s7

import (
	"fmt"
	"io"

	"local/elsereno/internal/protocols/s7/wire"
)

// s7Handshake drives the two mandatory handshakes every S7 request needs:
// COTP Connection Request/Confirm, then S7 Setup Communication. It reports
// isS7 (the port answered with a COTP Connection Confirm) and setupOK (the
// Setup Communication negotiated). Shared by the protection and identity
// probes. The caller sets deadlines on conn.
func s7Handshake(conn io.ReadWriter) (isS7, setupOK bool, err error) {
	// COTP Connection Request / Confirm.
	if err := wire.WriteTPKT(conn, wire.BuildCOTPConnectionRequest()); err != nil {
		return false, false, fmt.Errorf("s7: write COTP CR: %w", err)
	}
	cc, err := wire.ReadTPKT(conn)
	if err != nil {
		return false, false, fmt.Errorf("s7: read COTP CC: %w", err)
	}
	if !wire.IsCOTPConfirm(cc.Payload) {
		return false, false, nil // not S7/COTP on this port
	}

	// Setup Communication.
	if err := wire.WriteTPKT(conn, wire.BuildSetupCommunication(setupPDURef)); err != nil {
		return true, false, fmt.Errorf("s7: write Setup Communication: %w", err)
	}
	sr, err := wire.ReadTPKT(conn)
	if err != nil {
		return true, false, fmt.Errorf("s7: read Setup response: %w", err)
	}
	spdu, ok := wire.S7PDU(sr.Payload)
	if !ok {
		return true, false, nil
	}
	if _, ok := wire.ParseSetupResponse(spdu); !ok {
		return true, false, nil
	}
	return true, true, nil
}

// readSZL sends one UserData Read SZL request on an established session and
// returns the S7 PDU of the response. ok=false on a transport error or a
// non-S7 reply.
func readSZL(conn io.ReadWriter, pduRef, szlID, szlIndex uint16) (pdu []byte, ok bool, err error) {
	req := wire.BuildReadSZLRequest(pduRef, szlID, szlIndex)
	if err := wire.WriteTPKT(conn, req); err != nil {
		return nil, false, fmt.Errorf("s7: write Read SZL 0x%04x: %w", szlID, err)
	}
	resp, err := wire.ReadTPKT(conn)
	if err != nil {
		return nil, false, fmt.Errorf("s7: read SZL 0x%04x response: %w", szlID, err)
	}
	p, ok := wire.S7PDU(resp.Payload)
	if !ok {
		return nil, false, nil
	}
	return p, true, nil
}

// moduleIdentInfo / componentIdentInfo hold the parsed identity fields the
// probes surface, decoupled from the transport so the protection, identity
// and posture probes share one read path.
type moduleIdentInfo struct {
	orderNumber string
	firmware    string
}

type componentIdentInfo struct {
	moduleType       string
	serialNumber     string
	stationName      string
	plantDesignation string
}

// readProtectionRecord reads SZL 0x0132 index 4 and returns the protection
// record. ok=false when the CPU refused or returned no record; only a
// transport error propagates.
func readProtectionRecord(conn io.ReadWriter) (rec wire.ProtectionRecord, ok bool, err error) {
	pdu, ok, err := readSZL(conn, szlPDURef, wire.SZLIDProtection, wire.SZLIndexProtection)
	if err != nil || !ok {
		return wire.ProtectionRecord{}, false, err
	}
	rec, ok = wire.ParseProtectionSZL(pdu)
	return rec, ok, nil
}

// readModuleIdentInfo reads SZL 0x0011 and returns the order number +
// firmware. A read/parse miss yields empty fields, not an error.
func readModuleIdentInfo(conn io.ReadWriter) (moduleIdentInfo, error) {
	var mi moduleIdentInfo
	pdu, ok, err := readSZL(conn, identPDURefModule, wire.SZLIDModuleIdent, 0)
	if err != nil {
		return mi, err
	}
	if !ok {
		return mi, nil
	}
	recs, ok := wire.ParseModuleIdent(pdu)
	if !ok {
		return mi, nil
	}
	for _, r := range recs {
		switch r.Index {
		case wire.ModuleIndexOrderNumber:
			if mi.orderNumber == "" {
				mi.orderNumber = r.MLFB
			}
		case wire.ModuleIndexFirmware:
			if r.Version != "" {
				mi.firmware = r.Version
			}
		}
	}
	return mi, nil
}

// readComponentIdentInfo reads SZL 0x001C and returns the module type,
// serial number, station name and plant designation.
func readComponentIdentInfo(conn io.ReadWriter) (componentIdentInfo, error) {
	var ci componentIdentInfo
	pdu, ok, err := readSZL(conn, identPDURefComp, wire.SZLIDComponentIdent, 0)
	if err != nil {
		return ci, err
	}
	if !ok {
		return ci, nil
	}
	recs, ok := wire.ParseComponentIdent(pdu)
	if !ok {
		return ci, nil
	}
	for _, r := range recs {
		switch r.Index {
		case wire.ComponentIndexModuleType:
			ci.moduleType = r.Text
		case wire.ComponentIndexSerial:
			ci.serialNumber = r.Text
		case wire.ComponentIndexStationName:
			ci.stationName = r.Text
		case wire.ComponentIndexPlantDesig:
			ci.plantDesignation = r.Text
		}
	}
	return ci, nil
}
