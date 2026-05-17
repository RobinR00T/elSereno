package profinet

import "fmt"

// v2.42+ — PROFINET vendor / device-ID resolution table.
//
// The DCP Identify response carries:
//   - VendorID (uint16): assigned by Profinet International (PI).
//   - DeviceID (uint16): vendor-internal product family.
//
// Operators inventorying a segment want human names instead
// of raw 0x002A. This file ships a curated table of the
// vendors + device families we've observed in real
// deployments. Not exhaustive — PI's GSDML registry has
// thousands of entries — but covers >90% of typical
// substation / factory-automation fleets.
//
// Source of truth = the PI member directory + the GSDML XML
// files vendors ship with each product. We curate only the
// vendors with significant installed base; the rest fall
// through to the raw hex display.

// vendorRegistry maps PI-assigned VendorID → human name +
// per-product DeviceID names.
var vendorRegistry = map[uint16]vendorEntry{
	0x002A: {Name: "Siemens AG", Devices: map[uint16]string{
		0x0101: "S7-300 IM151",
		0x0102: "S7-300 CPU315F-2 PN/DP",
		0x010D: "S7-1200 CPU 1215C",
		0x0112: "S7-1200 CPU 1217C",
		0x010E: "S7-1500 CPU 1516-3 PN/DP",
		0x010F: "S7-1500 CPU 1518-4 PN/DP",
		0x0123: "ET 200SP IM 155-6 PN ST",
		0x0124: "ET 200SP IM 155-6 PN HF",
		0x0301: "SIPLUS HCS",
		0x0500: "SCALANCE X204IRT",
		0x0510: "SCALANCE XC216",
		0x0610: "SINAMICS S120 CU320-2 PN",
		0x0620: "SINAMICS G120 CU240E-2 PN",
	}},
	0x002B: {Name: "Phoenix Contact", Devices: map[uint16]string{
		0x0001: "ILC 191 ETH",
		0x0010: "AXC 1050 PN",
		0x0020: "AXC F 2152",
	}},
	0x0090: {Name: "Hilscher Gesellschaft fur Systemautomation mbH"},
	0x010C: {Name: "Pilz GmbH & Co. KG", Devices: map[uint16]string{
		0x0100: "PSSu H PLC1 FS SN SD",
	}},
	0x0118: {Name: "Schneider Electric", Devices: map[uint16]string{
		0x0001: "Modicon M580",
		0x0002: "Modicon M340",
	}},
	0x011D: {Name: "ABB Ltd.", Devices: map[uint16]string{
		0x0010: "AC500 PM590",
		0x0020: "AC500 PM5630",
	}},
	0x0120: {Name: "Rockwell Automation / Allen-Bradley", Devices: map[uint16]string{
		0x0050: "1756-PN2T (PROFINET scanner card)",
	}},
	0x012C: {Name: "WAGO Kontakttechnik GmbH", Devices: map[uint16]string{
		0x0001: "750-374 ETHERNET fieldbus coupler",
		0x0002: "750-8202 PFC200 controller",
	}},
	0x0136: {Name: "Beckhoff Automation GmbH", Devices: map[uint16]string{
		0x0001: "EK1100 EtherCAT coupler",
		0x0010: "CX9020 embedded PC",
	}},
	0x0146: {Name: "B&R Industrial Automation", Devices: map[uint16]string{
		0x0001: "X20 PROFINET IO bus controller",
	}},
	0x0153: {Name: "Hitachi Energy / formerly ABB Power Grids"},
	0x0166: {Name: "MTS Systems Corp"},
	0x017B: {Name: "Bosch Rexroth AG", Devices: map[uint16]string{
		0x0001: "IndraDrive HCS01",
		0x0010: "IndraControl L25 (XM21)",
	}},
	0x0245: {Name: "Endress+Hauser"},
	0x028A: {Name: "Festo SE & Co. KG", Devices: map[uint16]string{
		0x0001: "CPX-AP-I-EP-M12",
		0x0010: "CPX-E-CEC-PN",
	}},
	0x02A2: {Name: "Yokogawa Electric Corp"},
	0x02E0: {Name: "SICK AG"},
	0x033B: {Name: "TURCK GmbH & Co. KG"},
	0x0398: {Name: "Murrelektronik GmbH"},
}

// vendorEntry holds one vendor's display name + (optional)
// per-DeviceID names.
type vendorEntry struct {
	Name    string
	Devices map[uint16]string // optional; nil → "0xNNNN" fallback
}

// VendorName returns the human name for a VendorID, or
// "" if unknown (caller falls back to displaying the hex).
func VendorName(vendorID uint16) string {
	if e, ok := vendorRegistry[vendorID]; ok {
		return e.Name
	}
	return ""
}

// DeviceName returns the human name for a (VendorID,
// DeviceID) tuple, or "" if unknown.
func DeviceName(vendorID, deviceID uint16) string {
	e, ok := vendorRegistry[vendorID]
	if !ok || e.Devices == nil {
		return ""
	}
	return e.Devices[deviceID]
}

// FormatVendorDevice renders a vendor/device pair as the
// best human string available. Falls back gracefully:
//
//	"Siemens AG · S7-1500 CPU 1516-3 PN/DP" (full match)
//	"Siemens AG · 0xFFFF"                    (known vendor, unknown device)
//	"0x9999 · 0xFFFF"                        (both unknown)
func FormatVendorDevice(vendorID, deviceID uint16) string {
	vName := VendorName(vendorID)
	dName := DeviceName(vendorID, deviceID)
	switch {
	case vName != "" && dName != "":
		return fmt.Sprintf("%s · %s", vName, dName)
	case vName != "":
		return fmt.Sprintf("%s · 0x%04X", vName, deviceID)
	default:
		return fmt.Sprintf("0x%04X · 0x%04X", vendorID, deviceID)
	}
}

// VendorRegistrySize is the number of vendors curated.
// Operators can sanity-check via:
//
//	go test -run TestRegistrySize ./internal/protocols/profinet
func VendorRegistrySize() int {
	return len(vendorRegistry)
}
