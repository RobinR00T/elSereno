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

// Curated Omron CVEs, by controller family. The FINS Controller Data Read
// returns a model string whose prefix names the family (e.g. "CJ2M-CPU33",
// "CP1L-EL20DR-D", "NX102-9000"), so the match is prefix-exact. The two
// families carry different advisories, so they are kept apart rather than
// over-attributing one family's CVE to the other.
var (
	// SYSMAC Nx machine-automation controllers (NJ / NX / NY / PMAC).
	omronSysmacNx = []Record{
		{ID: "CVE-2022-31206", CVSS: 9.8, Affects: "Omron SYSMAC NJ / NX / NY / PMAC: downloaded logic not cryptographically authenticated (RCE)"},
		{ID: "CVE-2022-34151", CVSS: 9.4, Affects: "Omron NJ / NX-series + Sysmac Studio: hard-coded credentials (PIPEDREAM/BADOMEN)"},
	}
	// Classic CJ / CS series.
	omronCJCS = []Record{
		{ID: "CVE-2019-18269", CVSS: 8.6, Affects: "Omron CS / CJ: unrestricted externally accessible lock (auth bypass)"},
		{ID: "CVE-2022-45790", CVSS: 7.5, Affects: "Omron CJ / CS / CP: FINS memory password has no brute-force rate limit"},
	}
	// Classic CP series (CP1L / CP1H / CP1E). CVE-2019-18269 lists only CS/CJ,
	// so it is deliberately NOT attributed here.
	omronCP = []Record{
		{ID: "CVE-2022-45790", CVSS: 7.5, Affects: "Omron CJ / CS / CP: FINS memory password has no brute-force rate limit"},
	}
)

// ForFINS returns curated Omron CVEs for the family named by the FINS model
// string's prefix. The match is FAMILY-level and not firmware-confirmed (e.g.
// CVE-2022-31206 affects SYSMAC Nx below a fixed firmware the model string does
// not reveal), so pair it with the Omron advisory. An empty or unrecognised
// model returns nil rather than a guessed match.
func ForFINS(model string) []Record {
	m := strings.ToUpper(strings.TrimSpace(model))
	switch {
	case strings.HasPrefix(m, "NX") || strings.HasPrefix(m, "NJ") ||
		strings.HasPrefix(m, "NY") || strings.HasPrefix(m, "PMAC"):
		return omronSysmacNx
	case strings.HasPrefix(m, "CJ") || strings.HasPrefix(m, "CS"):
		return omronCJCS
	case strings.HasPrefix(m, "CP"):
		return omronCP
	default:
		return nil
	}
}

// Curated GE / Emerson PACSystems CVEs. GE-SRTP is GE's proprietary PLC
// protocol; the GE-SRTP fingerprint reads a model hint that names the
// controller family. These two advisories are the flagship network-exploitable
// PACSystems RX3i CVEs: improper input validation and a remote halt-mode DoS.
// They are scoped to the modern PACSystems RX3i / RXi / RSTi-EP line and
// deliberately NOT attributed to the older Series 90-30 (IC693) / 90-70
// (IC697) or VersaMax (IC200), which these advisories do not list.
var gesrtpPACSystemsRX3i = []Record{
	{ID: "CVE-2018-8867", CVSS: 7.5, Affects: "GE PACSystems RX3i (CPE305/310/330/400) / RSTi-EP CPE100 / RXi CPU320/CRU320: improper input validation"},
	{ID: "CVE-2019-13524", CVSS: 7.5, Affects: "GE PACSystems RX3i (CPE100/115/302/305/310/330/400/410) / CRU320: crafted packets force halt-mode (DoS)"},
}

// ForGESRTP returns curated PACSystems CVEs for the GE PLC family named by a
// GE-SRTP model hint. The match fires only for the modern PACSystems RX3i line
// (model hint beginning "PACSystems", "RX3i", or the IC695 catalog prefix);
// the older Series 90 / VersaMax families and an empty hint return nil rather
// than a guessed match. FAMILY-level, not firmware-confirmed: pair with the GE
// advisory for the device's firmware range.
func ForGESRTP(modelHint string) []Record {
	m := strings.ToUpper(strings.TrimSpace(modelHint))
	switch {
	case strings.HasPrefix(m, "PACSYSTEMS") ||
		strings.HasPrefix(m, "RX3I") ||
		strings.HasPrefix(m, "IC695"):
		return gesrtpPACSystemsRX3i
	default:
		return nil
	}
}

// Curated Mitsubishi MELSEC CVEs, by controller series. SLMP is Mitsubishi's
// protocol and the SLMP fingerprint reads the CPU model name, whose prefix
// names the series: iQ-R CPUs are "R" + digit (e.g. R08CPU, R120SFCPU), iQ-F
// CPUs are "FX5" (e.g. FX5U, FX5UC). The two series carry different advisories,
// kept apart rather than over-attributing one series' CVE to the other.
var (
	// MELSEC iQ-R series CPU modules.
	slmpIQR = []Record{
		{ID: "CVE-2020-5668", CVSS: 7.5, Affects: "Mitsubishi MELSEC iQ-R series CPU modules: uncontrolled resource consumption (DoS)"},
	}
	// MELSEC iQ-F (FX5) series. CVE-2025-7731 is an SLMP-protocol issue
	// (cleartext SLMP lets a remote attacker read credentials and read/write).
	slmpIQF = []Record{
		{ID: "CVE-2025-7731", CVSS: 7.5, Affects: "Mitsubishi MELSEC iQ-F CPU module: cleartext SLMP lets a remote attacker intercept credentials and read/write"},
		{ID: "CVE-2024-8403", CVSS: 7.5, Affects: "Mitsubishi MELSEC iQ-F FX5-ENET / FX5-ENET/IP modules: improper input validation (Ethernet DoS)"},
	}
)

// ForSLMP returns curated MELSEC CVEs for the series named by the SLMP CPU
// model-name prefix: "FX5" -> iQ-F, "R" + digit -> iQ-R. Classic Q / L / legacy
// FX models and an empty model return nil rather than a guessed match (no
// network-exploitable flagship CVE for those was verified for this curated
// set). FAMILY-level, not firmware-confirmed: pair with the Mitsubishi
// advisory for the device's firmware range.
func ForSLMP(model string) []Record {
	m := strings.ToUpper(strings.TrimSpace(model))
	switch {
	case strings.HasPrefix(m, "FX5"):
		return slmpIQF
	case len(m) >= 2 && m[0] == 'R' && m[1] >= '0' && m[1] <= '9':
		return slmpIQR
	default:
		return nil
	}
}
