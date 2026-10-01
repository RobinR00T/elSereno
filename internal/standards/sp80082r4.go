// Package standards maps elSereno protocol plugins to the external
// security-standard vulnerabilities their findings evidence, so a run is
// auditable against the standard. The mapping is keyed by the plugin's
// protocol name (core.Finding.Protocol), which is why it needs no change
// to core.Finding or to the per-plugin finding builders.
//
// The current mapping covers NIST SP 800-82 Rev. 4 (Initial Public Draft,
// September 2026); see docs/standards/nist-sp800-82r4.md.
package standards

// Ref is a single traceable reference into an external standard.
type Ref struct {
	Standard string `json:"standard"` // e.g. "NIST SP 800-82 r4"
	Table    string `json:"table"`    // e.g. "Table 16"
	Vuln     string `json:"vuln"`     // the vulnerability the finding evidences
}

const sp80082r4 = "NIST SP 800-82 r4"

// SP 800-82 r4 vulnerability shorthands reused across protocols.
var (
	refNoAuth               = Ref{sp80082r4, "Table 16", "Authentication of users, data, or devices is substandard or nonexistent"}
	refUnsecureOT           = Ref{sp80082r4, "Table 16", "Use of unsecure OT protocols"}
	refSecurityOffByDefault = Ref{sp80082r4, "Table 15", "Installed security capabilities are not enabled by default"}
	refPlaintext            = Ref{sp80082r4, "Table 16", "Standard, well-documented communication protocols are used in plaintext"}
)

// protocolRefs maps a plugin protocol name to the standard vulnerabilities
// its findings evidence. A protocol absent from the map has no claimed
// mapping (ForProtocol returns nil), so elSereno never over-claims.
var protocolRefs = map[string][]Ref{
	// S7: no authentication, and the CPU protection level is off by default.
	"s7":          {refUnsecureOT, refNoAuth},
	"s7-exposure": {refNoAuth, refSecurityOffByDefault},
	// OPC UA: anonymous / SecurityMode=None exposes unauthenticated access.
	"opcua":      {refNoAuth, refUnsecureOT},
	"opcuahttps": {refNoAuth},
	// Unauthenticated OT protocols.
	"modbus":   {refUnsecureOT},
	"enip":     {refUnsecureOT},
	"dnp3":     {refUnsecureOT},
	"bacnet":   {refUnsecureOT},
	"iec104":   {refUnsecureOT},
	"mms":      {refUnsecureOT},
	"finsudp":  {refUnsecureOT},
	"slmp":     {refUnsecureOT},
	"gesrtp":   {refUnsecureOT},
	"knxip":    {refUnsecureOT},
	"mbustcp":  {refUnsecureOT},
	"dlms":     {refUnsecureOT},
	"hartip":   {refUnsecureOT},
	"fox":      {refUnsecureOT},
	"pcworx":   {refUnsecureOT},
	"proconos": {refUnsecureOT},
	"codesys":  {refUnsecureOT},
	"redlion":  {refUnsecureOT},
	"twincat":  {refUnsecureOT},
	"atg":      {refUnsecureOT},
	// MQTT brokers commonly allow anonymous connect: no authentication.
	"mqtt": {refNoAuth},
	// Legacy/management protocols that are plaintext by nature.
	"atmodem": {refPlaintext},
	"cwmp":    {refPlaintext},
	"sip":     {refPlaintext},
	"iax2":    {refPlaintext},
	"xot":     {refPlaintext},
	"pbxhttp": {refPlaintext},
}

// ForProtocol returns the standard vulnerabilities a finding for the given
// protocol evidences, or nil when the protocol has no mapping.
func ForProtocol(protocol string) []Ref {
	refs := protocolRefs[protocol]
	if len(refs) == 0 {
		return nil
	}
	out := make([]Ref, len(refs))
	copy(out, refs)
	return out
}

// Protocols returns the protocol names that have a standards mapping, so a
// catalog view can enumerate them.
func Protocols() []string {
	out := make([]string, 0, len(protocolRefs))
	for p := range protocolRefs {
		out = append(out, p)
	}
	return out
}
