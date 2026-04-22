package sip

import "strings"

// Vendor is a known PBX / SIP-stack brand we can identify from
// a Server or User-Agent header. The list is deliberately
// non-exhaustive — it captures the brands operators most often
// find exposed on the public internet.
type Vendor string

// Known vendors. The string value is the canonical short tag
// emitted in the finding's `factors` map + the dashboard
// protocol-risk chip.
const (
	VendorUnknown     Vendor = "unknown"
	VendorAsterisk    Vendor = "asterisk"
	VendorFreePBX     Vendor = "freepbx"
	VendorThreeCX     Vendor = "3cx"
	VendorCiscoUCM    Vendor = "cisco-ucm"
	VendorCiscoSIPGW  Vendor = "cisco-sipgw"
	VendorMitel       Vendor = "mitel"
	VendorAvaya       Vendor = "avaya"
	VendorYeastar     Vendor = "yeastar"
	VendorGrandstream Vendor = "grandstream"
	VendorFanvil      Vendor = "fanvil"
	VendorYealink     Vendor = "yealink"
	VendorKamailio    Vendor = "kamailio"
	VendorOpenSIPS    Vendor = "opensips"
	VendorFreeSWITCH  Vendor = "freeswitch"
	VendorSER         Vendor = "ser"
)

// vendorMatchers lists (canonical-lowercase substring, vendor)
// pairs in priority order. The first match wins, so more
// specific strings come first — "cisco-cucm" before "cisco".
var vendorMatchers = []struct {
	needle string
	vendor Vendor
}{
	{"asterisk pbx", VendorAsterisk},
	{"asterisk", VendorAsterisk},
	{"freepbx", VendorFreePBX},
	{"3cx phone system", VendorThreeCX},
	{"3cx", VendorThreeCX},
	{"cucm", VendorCiscoUCM}, // Cisco Unified Communications Manager
	{"cisco-cucm", VendorCiscoUCM},
	{"cisco-sipgateway", VendorCiscoSIPGW},
	{"mitel", VendorMitel},
	{"shoretel", VendorMitel}, // ShoreTel was bought by Mitel
	{"avaya", VendorAvaya},
	{"ip office", VendorAvaya},
	{"yeastar", VendorYeastar},
	{"grandstream", VendorGrandstream},
	{"fanvil", VendorFanvil},
	{"yealink", VendorYealink},
	{"kamailio", VendorKamailio},
	{"opensips", VendorOpenSIPS},
	{"freeswitch", VendorFreeSWITCH},
	{"sip express router", VendorSER},
	{" ser/", VendorSER},
}

// IdentifyVendor returns the most specific vendor matching the
// supplied Server / User-Agent strings. If both are non-empty
// they're both searched; Server takes precedence on a tie. The
// match is case-insensitive.
//
// VendorUnknown is returned when nothing matches OR both inputs
// are empty — callers can distinguish by also checking whether
// the SIP response had a valid SIP/2.0 status line (a vendor
// who strips identifying headers is still a SIP responder).
func IdentifyVendor(server, userAgent string) Vendor {
	haystacks := []string{
		strings.ToLower(server),
		strings.ToLower(userAgent),
	}
	for _, m := range vendorMatchers {
		for _, h := range haystacks {
			if h != "" && strings.Contains(h, m.needle) {
				return m.vendor
			}
		}
	}
	return VendorUnknown
}

// VendorRisk returns the protocol_risk factor for a vendor.
// All SIP responders sit at protocol_risk ≥ 70 because a PBX
// on the open internet is almost always a toll-fraud or
// hijack target; specific flavours with known exposure
// patterns score higher.
func VendorRisk(v Vendor) int {
	switch v { //nolint:exhaustive // VendorUnknown falls through to the default 70 at the bottom
	case VendorFreePBX, VendorThreeCX, VendorAsterisk:
		// Historically the most attacked PBX flavours; many
		// default-install deployments still on the internet.
		return 90
	case VendorCiscoUCM, VendorAvaya, VendorMitel:
		// Enterprise PBX — usually well-patched but high impact.
		return 85
	case VendorYeastar, VendorGrandstream, VendorFanvil, VendorYealink:
		// SOHO appliances. High exposure, usually shipped with
		// admin webs on the public side.
		return 80
	case VendorKamailio, VendorOpenSIPS, VendorFreeSWITCH, VendorSER, VendorCiscoSIPGW:
		// SIP proxy / gateway — valuable pivot for call routing
		// abuse but not a full PBX.
		return 75
	}
	return 70 // SIP server of unknown vendor — still high protocol_risk
}
