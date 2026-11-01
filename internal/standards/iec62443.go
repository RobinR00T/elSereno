package standards

// iec62443 names the part of ISA/IEC 62443 the references point into:
// 62443-3-3 (system security requirements and security levels). Only
// the requirement number and its title are used.
const iec62443 = "ISA/IEC 62443-3-3"

// ISA/IEC 62443-3-3 system requirements. For these the Ref fields read:
// Table = the SR number, Vuln = the requirement title. A mapping says "a
// finding for this protocol is evidence against this requirement"; it is
// elSereno's reading, not a statement by ISA or IEC.
var (
	srDeviceAuth      = Ref{iec62443, "SR 1.2", "Software process and device identification and authentication"}
	srUntrustedAccess = Ref{iec62443, "SR 1.13", "Access via untrusted networks"}
	srAuthzEnforce    = Ref{iec62443, "SR 2.1", "Authorization enforcement"}
	srCommIntegrity   = Ref{iec62443, "SR 3.1", "Communication integrity"}
	srConfidentiality = Ref{iec62443, "SR 4.1", "Information confidentiality"}
	srSegmentation    = Ref{iec62443, "SR 5.1", "Network segmentation"}
	srLeastFunction   = Ref{iec62443, "SR 7.7", "Least functionality"}
)

// unauthOT is the 62443 reading of an unauthenticated OT protocol: no
// device or process authentication, no authorization enforcement, and a
// segment that lets the client reach it.
var unauthOT = []Ref{srDeviceAuth, srAuthzEnforce, srSegmentation}

// plaintextMgmt is the reading of a plaintext management protocol.
var plaintextMgmt = []Ref{srConfidentiality, srCommIntegrity, srUntrustedAccess}

// iec62443Refs maps a plugin protocol name to the 62443-3-3 requirements
// its findings are evidence against.
var iec62443Refs = map[string][]Ref{
	"s7":             unauthOT,
	"s7-exposure":    {srAuthzEnforce, srLeastFunction},
	"opcua":          unauthOT,
	"opcua-exposure": {srDeviceAuth, srAuthzEnforce},
	"opcuahttps":     {srDeviceAuth},
	"modbus":         unauthOT,
	"enip":           unauthOT,
	"dnp3":           unauthOT,
	"bacnet":         unauthOT,
	"iec104":         unauthOT,
	"mms":            unauthOT,
	"finsudp":        unauthOT,
	"slmp":           unauthOT,
	"melsoft":        unauthOT,
	"gesrtp":         unauthOT,
	"knxip":          unauthOT,
	"mbustcp":        unauthOT,
	"dlms":           unauthOT,
	"hartip":         unauthOT,
	"fox":            unauthOT,
	"pcworx":         unauthOT,
	"proconos":       unauthOT,
	"codesys":        unauthOT,
	"codesys-active": unauthOT,
	"redlion":        unauthOT,
	"twincat":        unauthOT,
	"atg":            unauthOT,
	"tristation":     unauthOT,
	"profinet-cm":    unauthOT,
	"mqtt":           {srDeviceAuth, srAuthzEnforce},
	"atmodem":        plaintextMgmt,
	"cwmp":           plaintextMgmt,
	"sip":            {srConfidentiality, srCommIntegrity},
	"iax2":           {srConfidentiality, srCommIntegrity},
	"xot":            {srConfidentiality, srCommIntegrity},
	"pbxhttp":        {srConfidentiality, srCommIntegrity},
	"it-management":  {srUntrustedAccess, srSegmentation},
}
