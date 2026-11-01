// Package honeypot flags device identities that match the published
// defaults of open-source ICS honeypots. An internet-exposed "PLC" that
// reports Conpot's stock serial number is far more likely a research
// sensor than a plant, and a report should say so before anyone acts on
// it.
//
// Signatures come from Conpot's default template (GPLv2, values only,
// checked against the upstream templates on 2026-10-27). A match is
// evidence, not proof: an operator can change every default, and a real
// device can share one string with a template (IM151-8 PN/DP CPU is a
// real Siemens module). So one field alone never makes a verdict unless
// it is an identifier (a serial number) that no real device should share.
package honeypot

import "strings"

// Field names used in signatures and in the values passed to Check.
const (
	FieldSerial      = "serial"
	FieldStation     = "station_name"
	FieldModuleName  = "module_name"
	FieldModuleType  = "module_type"
	FieldPlant       = "plant_designation"
	FieldCopyright   = "copyright"
	FieldVendor      = "vendor"
	FieldModel       = "model"
	FieldDescription = "description"
	FieldProduct     = "product"
)

// Signature is one default value of one honeypot.
type Signature struct {
	Honeypot string
	Protocol string
	Field    string
	Value    string
	// Strong marks an identifier no real device should share.
	Strong bool
}

var signatures = []Signature{
	{"conpot", "s7", FieldSerial, "88111222", true},
	{"conpot", "s7", FieldStation, "Technodrome", false},
	{"conpot", "s7", FieldModuleName, "Siemens, SIMATIC, S7-200", false},
	{"conpot", "s7", FieldPlant, "Mouser Factory", false},
	{"conpot", "s7", FieldCopyright, "Original Siemens Equipment", false},
	{"conpot", "s7", FieldModuleType, "IM151-8 PN/DP CPU", false},
	{"conpot", "bacnet", FieldVendor, "Alerton Technologies, Inc.", false},
	{"conpot", "bacnet", FieldModel, "VAV-DD Controller", false},
	{"conpot", "bacnet", FieldDescription, "VAV Dual Duct Controller", false},
	{"conpot", "enip", FieldSerial, "7079450", true},
	{"conpot", "enip", FieldProduct, "1756-L61/B LOGIX5561", false},
}

// Verdict is the result of Check.
type Verdict struct {
	Suspect  bool     `json:"suspect"`
	Honeypot string   `json:"honeypot,omitempty"`
	Matches  []string `json:"matches,omitempty"` // "field=value"
}

// Check compares the identity fields of a device speaking protocol with
// the catalogue. Suspect is true on one strong match or two weak ones.
func Check(protocol string, fields map[string]string) Verdict {
	var v Verdict
	strong := false
	for _, s := range signatures {
		if s.Protocol != protocol {
			continue
		}
		got := strings.TrimSpace(fields[s.Field])
		if got == "" || !strings.EqualFold(got, s.Value) {
			continue
		}
		v.Matches = append(v.Matches, s.Field+"="+s.Value)
		v.Honeypot = s.Honeypot
		strong = strong || s.Strong
	}
	v.Suspect = strong || len(v.Matches) >= 2
	if len(v.Matches) == 0 {
		v.Honeypot = ""
	}
	return v
}

// Signatures returns a copy of the catalogue.
func Signatures() []Signature { return append([]Signature(nil), signatures...) }
