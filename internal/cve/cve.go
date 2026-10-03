// Package cve maps a device family that an identity probe has read off the
// wire (Siemens MLFB order number, EtherNet/IP vendor id + product name, or a
// firmware / model string) to a CURATED, NON-EXHAUSTIVE set of real, published
// CVEs, so a finding can turn "this is a Siemens S7-1500" into "...and this
// family carries CVE-2020-15782", or "this is a Rockwell 1756-EN2TR" into
// "...and that Ethernet module line carries CVE-2025-7353".
//
// Scope and honesty (important):
//   - Every record is a real, published CVE. No fabricated or guessed ids.
//   - The mapping is FAMILY-LEVEL, not firmware-exact: a match means "this
//     product family has this high-profile CVE", not "this exact firmware is
//     vulnerable". Pair it with NVD / the vendor advisory for the precise
//     firmware range before acting.
//   - It is a starter set of flagship ICS CVEs, deliberately small and
//     high-confidence, not a vulnerability database.
//
// It is offline and deterministic (no network at scan time), matching the
// read-only posture of the rest of elSereno. Output keys the map by the
// identity the probe already extracts, so no change to core.Finding.
package cve

import "strings"

// Record is one curated CVE for an identified product family.
type Record struct {
	ID      string  // published CVE identifier, e.g. "CVE-2020-15782"
	CVSS    float64 // NVD base score (CVSS v3.x where available)
	Affects string  // the product family the record applies to
}

// Score turns matched records into a cve_exposure scoring factor in [0,100].
// It is deliberately moderate because the match is family-level, not
// firmware-confirmed: a known flagship CVE in the family raises exposure but
// does not saturate the factor. 45 for any match, +10 per additional record,
// +15 when the worst match is critical (CVSS >= 9.0), capped at 90.
func Score(recs []Record) int {
	if len(recs) == 0 {
		return 0
	}
	score := 45 + 10*(len(recs)-1)
	maxCVSS := 0.0
	for _, r := range recs {
		if r.CVSS > maxCVSS {
			maxCVSS = r.CVSS
		}
	}
	if maxCVSS >= 9.0 {
		score += 15
	}
	if score > 90 {
		score = 90
	}
	return score
}

// IDs returns just the CVE identifiers, for a finding note or label.
func IDs(recs []Record) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.ID
	}
	return out
}

// Curated Siemens S7 CVEs, by CPU family.
var (
	s7_1200_1500 = []Record{
		// Claroty "memory protection bypass" on S7-1200/S7-1500 CPUs.
		{ID: "CVE-2020-15782", CVSS: 8.1, Affects: "Siemens SIMATIC S7-1200 / S7-1500"},
	}
	s7_300_400 = []Record{
		// Specially crafted packets put S7-300/400 CPUs into defect mode.
		{ID: "CVE-2016-9158", CVSS: 7.5, Affects: "Siemens SIMATIC S7-300 / S7-400"},
		// PROFINET DCE/RPC man-in-the-middle on S7-300/400.
		{ID: "CVE-2019-10929", CVSS: 6.8, Affects: "Siemens SIMATIC S7-300 / S7-400 (PROFINET)"},
	}
)

// S7Family classifies a Siemens MLFB order number (e.g. "6ES7 515-2AM01-0AB0")
// into a coarse CPU family string, or "" when the family is not unambiguous.
// The series digit after "6ES7 " selects the family: 2=S7-1200, 3=S7-300,
// 4=S7-400, 5=S7-1500. ET200 distributed CPUs ("6ES7 15x" / "6ES7 158...")
// are deliberately NOT classified: the IM151 (ET200S) is S7-300-class while
// the IM155 (ET200SP) is S7-1500-class, and one digit cannot tell them apart,
// so guessing would misattribute CVEs. Those return "".
func S7Family(orderNumber string) string {
	s := strings.ToUpper(strings.TrimSpace(orderNumber))
	s = strings.TrimPrefix(s, "6ES7")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	switch s[0] {
	case '2':
		return "s7-1200"
	case '3':
		return "s7-300"
	case '4':
		return "s7-400"
	case '5':
		return "s7-1500"
	default:
		return "" // ET200 (15x) and anything else: not unambiguous
	}
}

// ForS7 returns the curated CVEs for the family of a Siemens MLFB order
// number. Empty when the family is unknown or has no curated entry.
func ForS7(orderNumber string) []Record {
	switch S7Family(orderNumber) {
	case "s7-1200", "s7-1500":
		return s7_1200_1500
	case "s7-300", "s7-400":
		return s7_300_400
	default:
		return nil
	}
}

// Curated Rockwell Automation / Allen-Bradley CVEs, by product line. Rockwell
// is EtherNet/IP vendor id 1; the ListIdentity product name carries the module
// catalog number verbatim, so the match is catalog-exact rather than inferred.
var (
	// ControlLogix Ethernet communication modules (1756-EN2T, -EN2TR, -EN2TP,
	// -EN2F, -EN3TR) ship a web-based debug (WDB) agent that allows an
	// unauthenticated remote attacker to read/modify memory and control
	// execution. Firmware v11.004 and prior.
	enipControlLogixEthernet = []Record{
		{ID: "CVE-2025-7353", CVSS: 9.8, Affects: "Rockwell ControlLogix 1756-EN2x / -EN3TR Ethernet modules (WDB agent RCE)"},
	}
)

// ForENIP returns curated CVEs for a device identified by an EtherNet/IP
// ListIdentity response. It fires only for Rockwell Automation / Allen-Bradley
// (vendor id 1) and matches on the product-name catalog number, which carries
// the exact module line. The match is catalog-level, not firmware-confirmed:
// CVE-2025-7353 affects these modules at firmware v11.004 and prior, which the
// identity response does not reliably reveal, so pair it with the advisory.
// Product lines without a curated, catalog-exact CVE (the older 1756-ENBT, or
// Logix controllers whose generation cannot be read unambiguously from the
// product name) return nil rather than a guessed match.
func ForENIP(vendorID uint16, productName string) []Record {
	if vendorID != 1 {
		return nil
	}
	name := strings.ToUpper(productName)
	// 1756-EN2T, -EN2TR and -EN2TP all contain "EN2T"; -EN2F and -EN3TR are
	// matched explicitly. The older 1756-ENBT contains none of these tokens,
	// so it correctly receives no match.
	if strings.Contains(name, "EN2T") || strings.Contains(name, "EN2F") || strings.Contains(name, "EN3TR") {
		return enipControlLogixEthernet
	}
	return nil
}

// Curated Phoenix Contact CVEs for the ProConOS runtime that the PC WORX
// family (ILC / AXC / RFC controllers) runs. The PC WORX fingerprint confirms
// a Phoenix Contact controller speaking that runtime protocol; the runtime
// verifies no authentication and does not sign downloaded logic.
var pcworxProConOS = []Record{
	// OT:ICEFALL: an unauthenticated remote attacker uploads malicious logic
	// to ProConOS / ProConOS eCLR devices and gains full control.
	{ID: "CVE-2022-31800", CVSS: 9.8, Affects: "Phoenix Contact ProConOS / eCLR controllers: unauthenticated logic download (no code signing)"},
	// ProConOS and MULTIPROG require no authentication for control traffic.
	{ID: "CVE-2014-9195", CVSS: 10.0, Affects: "Phoenix Contact ProConOS / MULTIPROG: protocol requires no authentication (CVSS v2 base)"},
}

// ForPCWorx returns curated ProConOS-family CVEs once a PC WORX fingerprint has
// positively confirmed a Phoenix Contact controller (confirmed == true). This
// is a FAMILY-level match keyed on the runtime protocol, not a firmware-exact
// lookup: CVE-2022-31800 was fixed in later firmware that signs downloads, so
// pair it with the Phoenix Contact advisory for the device's firmware. An
// unconfirmed probe returns nil.
func ForPCWorx(confirmed bool) []Record {
	if !confirmed {
		return nil
	}
	return pcworxProConOS
}
