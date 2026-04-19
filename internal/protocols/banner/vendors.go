package banner

import "strings"

// Vendor identifies the manufacturer family hinted by a TCP banner.
type Vendor string

// Vendor constants.
const (
	VendorUnknown   Vendor = "unknown"
	VendorMoxa      Vendor = "moxa"      // Moxa NPort serial-over-IP
	VendorLantronix Vendor = "lantronix" // Lantronix serial servers
	VendorDigi      Vendor = "digi"      // Digi PortServer
	VendorNetBurner Vendor = "netburner" // NetBurner embedded
	VendorKoneLift  Vendor = "kone"      // KONE lift interphone
	VendorOtisLift  Vendor = "otis"      // Otis lift
	VendorSchindler Vendor = "schindler" // Schindler lift
	VendorTelnetBSD Vendor = "telnet-bsd"
	VendorOpenSSH   Vendor = "openssh"
)

// vendorRule pairs a lowercase needle with its Vendor label. The
// first match wins, so more-specific rules go first.
type vendorRule struct {
	needle string
	vendor Vendor
}

var vendorRules = []vendorRule{
	{"moxa nport", VendorMoxa},
	{"moxa", VendorMoxa},
	{"lantronix", VendorLantronix},
	{"digi connect", VendorDigi},
	{"portserver", VendorDigi},
	{"netburner", VendorNetBurner},
	{"kone ", VendorKoneLift},
	{"otis", VendorOtisLift},
	{"schindler", VendorSchindler},
	{"openssh", VendorOpenSSH},
	{"ssh-", VendorOpenSSH},
}

// DetectVendor scans a rendered banner (already SafeBytes-sanitised)
// for a known vendor marker. Returns VendorUnknown if nothing
// matches.
func DetectVendor(banner string) Vendor {
	if banner == "" {
		return VendorUnknown
	}
	lower := strings.ToLower(banner)
	for _, r := range vendorRules {
		if strings.Contains(lower, r.needle) {
			return r.vendor
		}
	}
	return VendorUnknown
}
