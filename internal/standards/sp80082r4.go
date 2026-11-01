// Package standards maps elSereno protocol plugins to the external
// security-standard vulnerabilities their findings evidence, so a run is
// auditable against the standard. The mapping is keyed by the plugin's
// protocol name (core.Finding.Protocol), which is why it needs no change
// to core.Finding or to the per-plugin finding builders.
//
// The mapping covers three references, each in its own file:
//   - NIST SP 800-82 Rev. 4 (Initial Public Draft, September 2026); see
//     docs/standards/nist-sp800-82r4.md.
//   - MITRE ATT&CK for ICS v20 techniques; see
//     docs/standards/mitre-attack-ics.md.
//   - ISA/IEC 62443-3-3 system requirements; see
//     docs/standards/iec62443-3-3.md.
//
// ForProtocol returns all three, in that order; ForProtocolIn one.
package standards

import "strings"

// Ref is a single traceable reference into an external standard. The JSON
// field names are the stable output contract; their meaning per standard:
// SP 800-82 r4 (Table = table, Vuln = vulnerability), ATT&CK for ICS
// (Table = technique ID, Vuln = technique name), ISA/IEC 62443-3-3
// (Table = SR number, Vuln = requirement title).
type Ref struct {
	Standard string `json:"standard"` // e.g. "NIST SP 800-82 r4"
	Table    string `json:"table"`    // e.g. "Table 16", "T0888", "SR 1.2"
	Vuln     string `json:"vuln"`     // the vulnerability, technique or requirement
}

// Standard keys accepted by ForProtocolIn.
const (
	KeyNIST     = "nist"
	KeyAttack   = "attack-ics"
	KeyIEC62443 = "iec62443"
)

// Keys lists the standard keys in output order.
func Keys() []string { return []string{KeyNIST, KeyAttack, KeyIEC62443} }

// byKey maps a standard key to its protocol table.
func byKey(key string) map[string][]Ref {
	switch key {
	case KeyNIST:
		return protocolRefs
	case KeyAttack:
		return attackRefs
	case KeyIEC62443:
		return iec62443Refs
	}
	return nil
}

const sp80082r4 = "NIST SP 800-82 r4"

// SP 800-82 r4 vulnerability shorthands reused across protocols.
var (
	refNoAuth               = Ref{sp80082r4, "Table 16", "Authentication of users, data, or devices is substandard or nonexistent"}
	refUnsecureOT           = Ref{sp80082r4, "Table 16", "Use of unsecure OT protocols"}
	refSecurityOffByDefault = Ref{sp80082r4, "Table 15", "Installed security capabilities are not enabled by default"}
	refPlaintext            = Ref{sp80082r4, "Table 16", "Standard, well-documented communication protocols are used in plaintext"}
	refUnneededPorts        = Ref{sp80082r4, "Table 13", "Poor configurations: unnecessary ports and protocols are open"}
)

// protocolRefs maps a plugin protocol name to the standard vulnerabilities
// its findings evidence. A protocol absent from the map has no claimed
// mapping (ForProtocol returns nil), so elSereno never over-claims.
var protocolRefs = map[string][]Ref{
	// S7: no authentication, and the CPU protection level is off by default.
	"s7":          {refUnsecureOT, refNoAuth},
	"s7-exposure": {refNoAuth, refSecurityOffByDefault},
	// OPC UA: anonymous / SecurityMode=None exposes unauthenticated access.
	"opcua":          {refNoAuth, refUnsecureOT},
	"opcua-exposure": {refNoAuth, refUnsecureOT},
	"opcuahttps":     {refNoAuth},
	// Unauthenticated OT protocols.
	"modbus":   {refUnsecureOT},
	"enip":     {refUnsecureOT},
	"dnp3":     {refUnsecureOT},
	"bacnet":   {refUnsecureOT},
	"iec104":   {refUnsecureOT},
	"mms":      {refUnsecureOT},
	"finsudp":  {refUnsecureOT},
	"slmp":     {refUnsecureOT},
	"melsoft":  {refUnsecureOT},
	"gesrtp":   {refUnsecureOT},
	"knxip":    {refUnsecureOT},
	"mbustcp":  {refUnsecureOT},
	"dlms":     {refUnsecureOT},
	"hartip":   {refUnsecureOT},
	"fox":      {refUnsecureOT},
	"pcworx":   {refUnsecureOT},
	"proconos": {refUnsecureOT},
	"codesys":  {refUnsecureOT},
	// codesys-active: the opt-in channel-open probe, same unauthenticated
	// runtime as codesys; mapped separately because its findings carry their
	// own protocol name (like s7-exposure / opcua-exposure).
	"codesys-active": {refUnsecureOT},
	"redlion":        {refUnsecureOT},
	"twincat":        {refUnsecureOT},
	"atg":            {refUnsecureOT},
	// MQTT brokers commonly allow anonymous connect: no authentication.
	"mqtt": {refNoAuth},
	// TriStation (Triconex SIS) and PROFINET CM: unauthenticated OT.
	"tristation":  {refUnsecureOT},
	"profinet-cm": {refUnsecureOT},
	// Legacy/management protocols that are plaintext by nature.
	"atmodem": {refPlaintext},
	"cwmp":    {refPlaintext},
	"sip":     {refPlaintext},
	"iax2":    {refPlaintext},
	"xot":     {refPlaintext},
	"pbxhttp": {refPlaintext},
	// IT remote-administration, database and directory services reached
	// on an OT segment (exposure.CategoryITManagement).
	"it-management": {refUnneededPorts},
}

// ForProtocol returns every reference a finding for the given protocol
// carries (SP 800-82 r4, then ATT&CK for ICS, then ISA/IEC 62443-3-3), or
// nil when the protocol has no mapping in any of them.
func ForProtocol(protocol string) []Ref {
	var out []Ref
	for _, k := range Keys() {
		out = append(out, byKey(k)[protocol]...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ForProtocolIn returns the references of one standard (see Keys) for the
// protocol, or nil. An unknown key returns nil.
func ForProtocolIn(key, protocol string) []Ref {
	refs := byKey(key)[protocol]
	if len(refs) == 0 {
		return nil
	}
	out := make([]Ref, len(refs))
	copy(out, refs)
	return out
}

// Summarise renders refs as a single "; "-joined string, for output formats
// that carry one flat field (CEF cs3, a syslog SD param) rather than a JSON
// array. Each ref reads "<standard> <table>: <vuln>". Empty when refs is
// empty, so a caller can omit the field entirely.
func Summarise(refs []Ref) string {
	if len(refs) == 0 {
		return ""
	}
	parts := make([]string, len(refs))
	for i, r := range refs {
		parts[i] = r.Standard + " " + r.Table + ": " + r.Vuln
	}
	return strings.Join(parts, "; ")
}

// Protocols returns the protocol names that have a standards mapping, so a
// catalog view can enumerate them.
func Protocols() []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range Keys() {
		for p := range byKey(k) {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}
