package standards

// cie names the reference: the twelve principles of Cyber-Informed
// Engineering in the DOE/INL CIE Implementation Guide (INL/RPT-23-74072,
// Version 1.0, 7 August 2023, OSTI 1995796), the engineering approach the
// DOE CESER office pairs with SP 800-82 r4. Principle numbers and names
// were checked against that PDF.
const cie = "DOE CIE"

// CIE references. For these the Ref fields read: Table = "Principle N",
// Vuln = the principle name. CIE is a set of design principles, not a
// control catalogue: a mapping says "a finding for this protocol is a
// network-visible sign this principle was not applied to that system";
// it is elSereno's reading, not a statement by DOE or INL. elSereno only
// sees the network, so most principles (supply chain, information
// control, culture, planned resilience) have no mapping.
var (
	cieConsequence = Ref{cie, "Principle 1", "Consequence-Focused Design"}
	cieEngineered  = Ref{cie, "Principle 2", "Engineered Controls"}
	cieSecureInfo  = Ref{cie, "Principle 3", "Secure Information Architecture"}
	cieSimplify    = Ref{cie, "Principle 4", "Design Simplification"}
	cieLayered     = Ref{cie, "Principle 5", "Layered Defenses"}
	cieInterdepend = Ref{cie, "Principle 7", "Interdependency Evaluation"}
)

// cieUnauthOT is the CIE reading of an unauthenticated OT protocol
// reachable from the scanner: any client on the path can read or alter
// process data (Principle 3) and no layer in between stopped the scanner
// (Principle 5).
var cieUnauthOT = []Ref{cieSecureInfo, cieLayered}

// cieRemoteLink is the reading of a modem, TR-069 or similar link that
// ties the site to an outside party.
var cieRemoteLink = []Ref{cieInterdepend, cieLayered}

// cieRefs maps a plugin protocol name to the CIE principles its findings
// are a sign were not applied. The SIS protocol (TriStation) also carries
// Principles 1 and 2: a safety controller a network client can reach is
// the consequence CIE designs out first, and its protection is meant to
// be engineered (key switch, hardwired trips), not network-reachable.
var cieRefs = map[string][]Ref{
	"s7":             cieUnauthOT,
	"s7-exposure":    {cieEngineered, cieSecureInfo},
	"opcua":          cieUnauthOT,
	"opcua-exposure": {cieEngineered, cieSecureInfo},
	"modbus":         cieUnauthOT,
	"enip":           cieUnauthOT,
	"dnp3":           cieUnauthOT,
	"bacnet":         cieUnauthOT,
	"iec104":         cieUnauthOT,
	"mms":            cieUnauthOT,
	"finsudp":        cieUnauthOT,
	"slmp":           cieUnauthOT,
	"melsoft":        cieUnauthOT,
	"gesrtp":         cieUnauthOT,
	"knxip":          cieUnauthOT,
	"mbustcp":        cieUnauthOT,
	"dlms":           cieUnauthOT,
	"hartip":         cieUnauthOT,
	"fox":            cieUnauthOT,
	"pcworx":         cieUnauthOT,
	"proconos":       cieUnauthOT,
	"codesys":        cieUnauthOT,
	"codesys-active": cieUnauthOT,
	"redlion":        cieUnauthOT,
	"twincat":        cieUnauthOT,
	"atg":            cieUnauthOT,
	"profinet-cm":    cieUnauthOT,
	"tristation":     {cieConsequence, cieEngineered, cieSecureInfo, cieLayered},
	"mqtt":           {cieSecureInfo},
	"atmodem":        cieRemoteLink,
	"cwmp":           cieRemoteLink,
	"it-management":  {cieSimplify, cieInterdepend},
}
