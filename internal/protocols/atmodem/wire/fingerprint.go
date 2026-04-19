package wire

import "strings"

// Vendor labels the manufacturer family detected by Fingerprint.
type Vendor string

// Vendor families recognised by the fingerprinter. Values match the
// labels the operator sees in findings and telemetry.
const (
	VendorUnknown   Vendor = "unknown"
	VendorHayes     Vendor = "hayes"
	VendorSiemens   Vendor = "siemens"
	VendorNokia     Vendor = "nokia"
	VendorSierra    Vendor = "sierra"
	VendorMultiTech Vendor = "multitech"
	VendorCinterion Vendor = "cinterion"
	VendorTelit     Vendor = "telit"
	VendorUBlox     Vendor = "ublox"
	VendorQuectel   Vendor = "quectel"
	VendorHuawei    Vendor = "huawei"
	VendorKoneLift  Vendor = "kone"      // EN 81-28
	VendorOtisLift  Vendor = "otis"      // EN 81-28
	VendorSchindler Vendor = "schindler" // EN 81-28
)

// Class is the broader family a fingerprint falls into. GSM modems
// support +CGMI/+CGMM; Hayes-only modems do not. Lift interphones are
// AT-like but carry EN 81-28 semantics.
type Class string

// Protocol classes.
const (
	ClassUnknown Class = "unknown"
	ClassHayes   Class = "hayes"
	ClassGSM     Class = "gsm"
	ClassLift    Class = "en81-28" // lift interphone
)

// Fingerprint holds the detected class + vendor + raw banner text.
type Fingerprint struct {
	Class  Class
	Vendor Vendor
	Banner string
}

// vendorMatch pairs a lowercase needle with its Class+Vendor labels.
// The order is the priority order Detect walks.
type vendorMatch struct {
	needles []string
	class   Class
	vendor  Vendor
}

var vendorMatches = []vendorMatch{
	{[]string{"kone "}, ClassLift, VendorKoneLift},
	{[]string{"otis"}, ClassLift, VendorOtisLift},
	{[]string{"schindler"}, ClassLift, VendorSchindler},
	{[]string{"siemens"}, ClassGSM, VendorSiemens},
	{[]string{"nokia"}, ClassGSM, VendorNokia},
	{[]string{"sierra"}, ClassGSM, VendorSierra},
	{[]string{"multitech"}, ClassGSM, VendorMultiTech},
	{[]string{"cinterion"}, ClassGSM, VendorCinterion},
	{[]string{"telit"}, ClassGSM, VendorTelit},
	{[]string{"u-blox", "ublox"}, ClassGSM, VendorUBlox},
	{[]string{"quectel"}, ClassGSM, VendorQuectel},
	{[]string{"huawei"}, ClassGSM, VendorHuawei},
}

// Detect scans response bodies for known markers. `banner` is the
// welcome / `ATI` banner text; `cgmi` is the response to `AT+CGMI`;
// either may be empty.
func Detect(banner, cgmi string) Fingerprint {
	f := Fingerprint{Class: ClassUnknown, Vendor: VendorUnknown, Banner: banner}

	text := strings.ToLower(banner + "\n" + cgmi)
	for _, m := range vendorMatches {
		for _, n := range m.needles {
			if contains(text, n) {
				f.Class, f.Vendor = m.class, m.vendor
				return f
			}
		}
	}
	switch {
	case cgmi != "":
		f.Class = ClassGSM
	case banner != "":
		f.Class = ClassHayes
		f.Vendor = VendorHayes
	}
	return f
}

func contains(hay, needle string) bool {
	if needle == "" {
		return false
	}
	return strings.Contains(hay, needle)
}
