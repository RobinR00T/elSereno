// Package cwmp is the TR-069 / CWMP (CPE WAN Management Protocol,
// BroadbandForum TR-069) fingerprint. The ACS (Auto-Configuration
// Server) side listens on TCP 7547; CPE routers / set-top boxes
// contact it with SOAP-over-HTTP to register, fetch config, and
// report events.
//
// Exposure of an ACS on the public internet is a serious finding:
// a compromised ACS can push a malicious firmware update or
// configuration to every CPE in its fleet, often millions of
// devices. The 2016 Deutsche Telekom outage (Mirai variant
// exploiting CPE port 7547) is the canonical cautionary tale.
package cwmp

import "strings"

// Vendor identifies the ACS implementation behind an HTTP
// responder on 7547.
type Vendor string

// Known ACS vendors. The list grows as we see them in the wild.
const (
	VendorUnknown   Vendor = "unknown"
	VendorGenieACS  Vendor = "genieacs"   // open-source, Node.js
	VendorFreeACS   Vendor = "freeacs"    // open-source, Java
	VendorAxiros    Vendor = "axiros"     // commercial (AXACS / AX-MDM)
	VendorNokia     Vendor = "nokia"      // Altiplano
	VendorHuawei    Vendor = "huawei"     // FusionHome / FusionInsight
	VendorBroadcom  Vendor = "broadcom"   // BroadWorks-ACS
	VendorCisco     Vendor = "cisco"      // Prime / ASR-based
	VendorADB       Vendor = "adb"        // ADB Global ACS
	VendorFriendlyT Vendor = "friendly-t" // Friendly TR-069 Simulator (lab/test)
	VendorInteraCMS Vendor = "interacms"  // interaCMS
	VendorNetopia   Vendor = "netopia"    // legacy Motorola / ARRIS
	VendorCreate    Vendor = "create"     // create-net ACS
	VendorOpenACS   Vendor = "open-acs"   // generic open-source marker
	VendorTR069Test Vendor = "tr069-test" // catch-all "this IS cwmp" when unbranded
)

// vendorMatchers is a priority-ordered substring list. Needles
// are lowercase; matching folds case on the haystack.
var vendorMatchers = []struct {
	needle string
	vendor Vendor
}{
	// Most-specific product names first.
	{"genieacs", VendorGenieACS},
	{"genie-acs", VendorGenieACS},
	{"freeacs", VendorFreeACS},
	{"axiros", VendorAxiros},
	{"axacs", VendorAxiros},
	{"ax-mdm", VendorAxiros},
	{"altiplano", VendorNokia},
	{"nokia", VendorNokia},
	{"fusionhome", VendorHuawei},
	{"fusioninsight", VendorHuawei},
	{"huawei", VendorHuawei},
	{"broadworks", VendorBroadcom},
	{"broadcom", VendorBroadcom},
	{"cisco prime", VendorCisco},
	{"cisco", VendorCisco},
	{"adb tr069", VendorADB},
	{"adb acs", VendorADB},
	{"friendly tr-069", VendorFriendlyT},
	{"friendly tech", VendorFriendlyT},
	{"interacms", VendorInteraCMS},
	{"netopia", VendorNetopia},
	{"create-net", VendorCreate},
	// Generic CWMP / TR-069 markers — last-resort identification.
	{"tr-069", VendorTR069Test},
	{"tr069", VendorTR069Test},
	{"cwmp", VendorTR069Test},
	{"acs server", VendorOpenACS},
}

// IdentifyVendor returns the first vendor that matches any of
// the supplied haystacks (HTTP headers, body, SOAP fault string).
// Case-insensitive.
func IdentifyVendor(header, body string) Vendor {
	hs := []string{strings.ToLower(header), strings.ToLower(body)}
	for _, m := range vendorMatchers {
		for _, h := range hs {
			if h != "" && strings.Contains(h, m.needle) {
				return m.vendor
			}
		}
	}
	return VendorUnknown
}

// VendorRisk returns the protocol_risk factor for a CWMP vendor.
// All CWMP responders sit at protocol_risk ≥ 80 because an
// exposed ACS is a catastrophic finding regardless of brand —
// vendor recognition only bumps the score when specific CVE
// histories justify it.
func VendorRisk(v Vendor) int {
	switch v { //nolint:exhaustive // VendorUnknown + VendorTR069Test fall through to 80
	case VendorGenieACS, VendorFreeACS, VendorOpenACS:
		// Open-source ACS implementations — usually on consumer-
		// grade lab boxes OR open-source CPE fleets. High risk
		// because default installs expose admin paths.
		return 90
	case VendorAxiros, VendorNokia, VendorHuawei, VendorBroadcom, VendorCisco:
		// Enterprise / carrier ACS — very high impact per device
		// count, typically better-patched but historically
		// targeted by nation-state threat actors.
		return 85
	case VendorFriendlyT:
		// Lab / test deployment — still a finding (shouldn't be
		// on the public internet) but lower urgency.
		return 75
	}
	// Default for VendorUnknown / VendorTR069Test / any other
	// CWMP-shaped responder we haven't branded.
	return 80
}
