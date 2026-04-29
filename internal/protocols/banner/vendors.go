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

	// Industrial controller / HMI / RTU vendors (v1.23 chunk 2
	// expansion). Each maps a banner substring to a vendor
	// family. The vendor list is curated against
	// Internet-exposed device populations actually seen in
	// public ICS scans (Shodan, Censys), not exhaustive of
	// every automation vendor.
	VendorSiemens         Vendor = "siemens"          // Siemens SIMATIC + RUGGEDCOM
	VendorRockwell        Vendor = "rockwell"         // Rockwell Automation / Allen-Bradley
	VendorSchneider       Vendor = "schneider"        // Schneider Electric Modicon family
	VendorABB             Vendor = "abb"              // ABB ACS / AC500 / RobotStudio
	VendorWAGO            Vendor = "wago"             // WAGO PFC / 750-series
	VendorBeckhoff        Vendor = "beckhoff"         // Beckhoff CX / BX / industrial Ethernet
	VendorPhoenixContact  Vendor = "phoenix-contact"  // Phoenix Contact FL / AXC / ME-PLC
	VendorHirschmann      Vendor = "hirschmann"       // Hirschmann / Belden industrial switches
	VendorWestermo        Vendor = "westermo"         // Westermo industrial routers
	VendorAdvantech       Vendor = "advantech"        // Advantech industrial PC / EKI
	VendorSealevel        Vendor = "sealevel"         // Sealevel serial gateways
	VendorHoneywell       Vendor = "honeywell"        // Honeywell RTU / EBI / Experion
	VendorJohnsonControls Vendor = "johnson-controls" // Johnson Controls Metasys
	VendorTridium         Vendor = "tridium"          // Tridium Niagara (banner-only path)

	// Network gear commonly co-located with ICS deployments.
	// These don't directly indicate ICS but they're frequent
	// adjacent surfaces and the vendor label aids triage.
	VendorCiscoIOS Vendor = "cisco-ios" // Cisco IOS / IOS-XE
	VendorMikroTik Vendor = "mikrotik"  // MikroTik RouterOS
	VendorUbiquiti Vendor = "ubiquiti"  // Ubiquiti EdgeOS / UniFi
	VendorPfSense  Vendor = "pfsense"   // pfSense / OPNsense
	VendorDropbear Vendor = "dropbear"  // Dropbear SSH (common embedded)
	VendorRomPager Vendor = "rompager"  // RomPager (Misfortune Cookie family)
)

// vendorRule pairs a lowercase needle with its Vendor label. The
// first match wins, so more-specific rules go first.
type vendorRule struct {
	needle string
	vendor Vendor
}

var vendorRules = []vendorRule{
	// Most-specific serial-gateway / lift / embedded patterns
	// first so a banner that names "Moxa NPort" matches the
	// product-specific rule before falling back to the family.
	{"moxa nport", VendorMoxa},
	{"moxa", VendorMoxa},
	{"lantronix", VendorLantronix},
	{"digi connect", VendorDigi},
	{"portserver", VendorDigi},
	{"netburner", VendorNetBurner},
	{"kone ", VendorKoneLift},
	{"otis", VendorOtisLift},
	{"schindler", VendorSchindler},

	// Industrial controller / HMI / RTU vendors. Long-form
	// product strings first.
	{"simatic", VendorSiemens},
	{"ruggedcom", VendorSiemens},
	{"siemens", VendorSiemens},
	{"allen-bradley", VendorRockwell},
	{"rockwell automation", VendorRockwell},
	{"micrologix", VendorRockwell},
	{"compactlogix", VendorRockwell},
	{"controllogix", VendorRockwell},
	{"modicon", VendorSchneider},
	{"schneider electric", VendorSchneider},
	{"schneider-electric", VendorSchneider},
	{"abb ac500", VendorABB},
	{"abb robotics", VendorABB},
	{"abb ", VendorABB},
	{"wago pfc", VendorWAGO},
	{"wago 750", VendorWAGO},
	{"wago-io", VendorWAGO},
	{"wago", VendorWAGO},
	{"beckhoff cx", VendorBeckhoff},
	{"beckhoff bx", VendorBeckhoff},
	{"beckhoff", VendorBeckhoff},
	{"phoenix contact", VendorPhoenixContact},
	{"phoenixcontact", VendorPhoenixContact},
	{"hirschmann", VendorHirschmann},
	{"westermo", VendorWestermo},
	{"advantech", VendorAdvantech},
	{"sealevel", VendorSealevel},
	{"honeywell experion", VendorHoneywell},
	{"honeywell ", VendorHoneywell},
	{"metasys", VendorJohnsonControls},
	{"johnson controls", VendorJohnsonControls},
	{"niagara", VendorTridium},
	{"tridium", VendorTridium},

	// Network gear adjacent to ICS — keep these AFTER vendor
	// rules so a Cisco IOS banner that references SIMATIC
	// (e.g. on a Siemens RUGGEDCOM RX series IOS-XE box)
	// matches Siemens first.
	{"cisco ios", VendorCiscoIOS},
	{"ios software", VendorCiscoIOS},
	{"mikrotik", VendorMikroTik},
	{"routeros", VendorMikroTik}, //nolint:misspell // RouterOS is a real MikroTik product name, not "routers"
	{"ubiquiti", VendorUbiquiti},
	{"edgeos", VendorUbiquiti},
	{"unifi", VendorUbiquiti},
	{"pfsense", VendorPfSense},
	{"opnsense", VendorPfSense},
	{"dropbear", VendorDropbear},
	{"rompager", VendorRomPager},

	// SSH / generic identifiers last (least specific).
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
