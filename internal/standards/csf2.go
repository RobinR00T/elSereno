package standards

// csf2 names the framework the references point into: the NIST
// Cybersecurity Framework 2.0 (NIST CSWP 29, February 2024). SP 800-82 r4
// IPD is restructured around it, so these are the outcomes the draft's
// OT countermeasures are filed under. Subcategory IDs and their text were
// checked against the CSWP 29 PDF (nvlpubs.nist.gov); the text below is
// the subcategory statement, cut only where it runs past one line.
const csf2 = "NIST CSF 2.0"

// CSF 2.0 references. For these the Ref fields read: Table = the
// subcategory ID, Vuln = the subcategory outcome. A mapping says "a
// finding for this protocol is evidence this outcome is not achieved on
// that segment"; it is elSereno's reading, not a statement by NIST.
var (
	csfAuthenticated = Ref{csf2, "PR.AA-03", "Users, services, and hardware are authenticated"}
	csfAccessPolicy  = Ref{csf2, "PR.AA-05", "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed"}
	csfDataInTransit = Ref{csf2, "PR.DS-02", "The confidentiality, integrity, and availability of data-in-transit are protected"}
	csfConfigMgmt    = Ref{csf2, "PR.PS-01", "Configuration management practices are established and applied"}
	csfNetworkAccess = Ref{csf2, "PR.IR-01", "Networks and environments are protected from unauthorized logical access and usage"}
)

// csfUnauthOT is the CSF reading of an unauthenticated OT protocol
// reachable from the scanner: the device does not authenticate the client
// and the network let the client reach it.
var csfUnauthOT = []Ref{csfAuthenticated, csfNetworkAccess}

// csfPlaintextMgmt is the reading of a plaintext management or remote
// access protocol.
var csfPlaintextMgmt = []Ref{csfDataInTransit, csfNetworkAccess}

// csf2Refs maps a plugin protocol name to the CSF 2.0 outcomes its
// findings are evidence against.
var csf2Refs = map[string][]Ref{
	"s7":             csfUnauthOT,
	"s7-exposure":    {csfAccessPolicy, csfConfigMgmt},
	"opcua":          csfUnauthOT,
	"opcua-exposure": {csfAuthenticated, csfAccessPolicy},
	"opcuahttps":     {csfAuthenticated},
	"modbus":         csfUnauthOT,
	"enip":           csfUnauthOT,
	"dnp3":           csfUnauthOT,
	"bacnet":         csfUnauthOT,
	"iec104":         csfUnauthOT,
	"mms":            csfUnauthOT,
	"finsudp":        csfUnauthOT,
	"slmp":           csfUnauthOT,
	"melsoft":        csfUnauthOT,
	"gesrtp":         csfUnauthOT,
	"knxip":          csfUnauthOT,
	"mbustcp":        csfUnauthOT,
	"dlms":           csfUnauthOT,
	"hartip":         csfUnauthOT,
	"fox":            csfUnauthOT,
	"pcworx":         csfUnauthOT,
	"proconos":       csfUnauthOT,
	"codesys":        csfUnauthOT,
	"codesys-active": csfUnauthOT,
	"redlion":        csfUnauthOT,
	"twincat":        csfUnauthOT,
	"atg":            csfUnauthOT,
	"tristation":     csfUnauthOT,
	"profinet-cm":    csfUnauthOT,
	"mqtt":           {csfAuthenticated, csfAccessPolicy},
	"atmodem":        csfPlaintextMgmt,
	"cwmp":           csfPlaintextMgmt,
	"sip":            {csfDataInTransit},
	"iax2":           {csfDataInTransit},
	"xot":            {csfDataInTransit},
	"pbxhttp":        {csfDataInTransit},
	"it-management":  {csfNetworkAccess, csfConfigMgmt},
}
