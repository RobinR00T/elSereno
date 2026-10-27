package exposure

import "sort"

// Category classifies a well-known port by what its presence on a network
// means for an OT/ICS assessment.
type Category string

const (
	// CategoryITCleartext is an IT protocol that carries its traffic in
	// plaintext and has a drop-in encrypted counterpart (http -> https).
	CategoryITCleartext Category = "it-cleartext"
	// CategoryITEncrypted is an IT protocol that already runs over TLS;
	// the check reports its TLS posture.
	CategoryITEncrypted Category = "it-encrypted"
	// CategoryITManagement is a remote-administration, database or
	// directory service (SSH, RDP, VNC, SMB, MS SQL, Kerberos, ...). Its
	// presence is the finding: on an OT segment it is the usual path an
	// attacker takes from IT into the plant (historians, engineering
	// workstations, domain controllers).
	CategoryITManagement Category = "it-management"
	// CategoryOT is an industrial protocol, cleartext by design: the
	// mitigation is segmentation, not a protocol swap.
	CategoryOT Category = "ot"
)

// Transports.
const (
	TransportTCP = "tcp"
	TransportUDP = "udp"
)

// PortEntry is one row of the well-known port catalogue.
type PortEntry struct {
	Port      int      `json:"port"`
	Transport string   `json:"transport"`
	Protocol  string   `json:"protocol"`
	Category  Category `json:"category"`
	// SecureAlternative names the encrypted counterpart when one exists;
	// empty for OT protocols and for services with their own encryption.
	SecureAlternative string `json:"secure_alternative,omitempty"`
	// TLSCheck is false for services whose encryption, if any, is not a
	// bare TLS handshake on connect (SSH, RDP, MS SQL TDS, SMB, VNC):
	// a failed ClientHello there does not mean cleartext, so the check
	// reports the service and never claims plaintext.
	TLSCheck bool `json:"tls_check"`
	// Note is a one-line operator hint shown with the result.
	Note string `json:"note,omitempty"`
}

// wellKnownPorts is the catalogue. Sources: the IANA service registry for
// the IT ports and each protocol plugin's DefaultPort for the OT ports
// (internal/protocols/<name>). UDP rows are listed so a UDP-only service
// is named instead of being reported unreachable over TCP.
var wellKnownPorts = []PortEntry{
	// IT plaintext protocols with an encrypted counterpart.
	{21, TransportTCP, "ftp", CategoryITCleartext, "ftps / sftp", true, ""},
	{23, TransportTCP, "telnet", CategoryITCleartext, "ssh", true, ""},
	{25, TransportTCP, "smtp", CategoryITCleartext, "smtps", true, ""},
	{69, TransportUDP, "tftp", CategoryITCleartext, "sftp", false, "TFTP has no authentication; often used to push PLC and switch firmware"},
	{80, TransportTCP, "http", CategoryITCleartext, "https", true, "web interfaces of HMIs, PLCs, SCADA and firewalls"},
	{110, TransportTCP, "pop3", CategoryITCleartext, "pop3s", true, ""},
	{143, TransportTCP, "imap", CategoryITCleartext, "imaps", true, ""},
	{161, TransportUDP, "snmp", CategoryITCleartext, "snmpv3", false, "SNMP v1/v2c community strings travel in plaintext"},
	{389, TransportTCP, "ldap", CategoryITCleartext, "ldaps", true, "a directory on an OT segment: check it is not the IT Active Directory"},
	{513, TransportTCP, "rlogin", CategoryITCleartext, "ssh", true, ""},
	{1883, TransportTCP, "mqtt", CategoryITCleartext, "mqtts (8883)", true, "M2M broker; anonymous connect is common"},
	{3268, TransportTCP, "ldap-global-catalog", CategoryITCleartext, "ldap-global-catalog-ssl (3269)", true, "Active Directory global catalog: a domain controller is reachable"},
	{5985, TransportTCP, "winrm-http", CategoryITCleartext, "winrm-https (5986)", true, "Windows remote management"},

	// IT protocols that already run over TLS: the check reports posture.
	{443, TransportTCP, "https", CategoryITEncrypted, "", true, "web interfaces of HMIs, PLCs, SCADA and firewalls"},
	{636, TransportTCP, "ldaps", CategoryITEncrypted, "", true, "a directory on an OT segment: check it is not the IT Active Directory"},
	{3269, TransportTCP, "ldap-global-catalog-ssl", CategoryITEncrypted, "", true, "Active Directory global catalog: a domain controller is reachable"},
	{5986, TransportTCP, "winrm-https", CategoryITEncrypted, "", true, "Windows remote management"},
	{8883, TransportTCP, "mqtts", CategoryITEncrypted, "", true, ""},

	// IT remote administration, database and directory services.
	{22, TransportTCP, "ssh", CategoryITManagement, "", false, "encrypted remote shell; check who can reach it from IT"},
	{88, TransportTCP, "kerberos", CategoryITManagement, "", false, "a domain controller is reachable; keep IT and OT forests separate, no trusts"},
	{135, TransportTCP, "msrpc", CategoryITManagement, "", false, "Windows RPC endpoint mapper (DCOM, OPC Classic)"},
	{139, TransportTCP, "netbios-ssn", CategoryITManagement, "", false, "legacy Windows file sharing"},
	{445, TransportTCP, "smb", CategoryITManagement, "", false, "Windows file sharing; the usual ransomware path into OT"},
	{1433, TransportTCP, "mssql", CategoryITManagement, "", false, "MS SQL Server: the usual backend of data historians"},
	{1521, TransportTCP, "oracle-tns", CategoryITManagement, "", false, "Oracle database listener (historians, MES)"},
	{3389, TransportTCP, "rdp", CategoryITManagement, "", false, "Remote Desktop to Windows HMIs, historians and engineering workstations"},
	{5900, TransportTCP, "vnc", CategoryITManagement, "", false, "classic VNC (RFB) does not encrypt the session; common on HMI panels"},

	// OT protocols: cleartext by design, mitigation is segmentation.
	{102, TransportTCP, "s7comm / iec61850-mms (iso-tsap)", CategoryOT, "", true, ""},
	{502, TransportTCP, "modbus", CategoryOT, "", true, ""},
	{789, TransportTCP, "redlion-crimson", CategoryOT, "", true, ""},
	{1217, TransportTCP, "codesys", CategoryOT, "", true, ""},
	{1502, TransportUDP, "tristation", CategoryOT, "", false, "Triconex safety controller (SIS); TRITON used this protocol"},
	{1911, TransportTCP, "niagara-fox", CategoryOT, "", true, ""},
	{1962, TransportTCP, "pcworx", CategoryOT, "", true, ""},
	{2222, TransportUDP, "ethernet-ip-io", CategoryOT, "", false, "CIP implicit (I/O) messaging"},
	{2404, TransportTCP, "iec-104", CategoryOT, "", true, ""},
	{3671, TransportUDP, "knxnet-ip", CategoryOT, "", false, ""},
	{4059, TransportTCP, "dlms-cosem", CategoryOT, "", true, ""},
	{4840, TransportTCP, "opc-ua-tcp", CategoryOT, "", true, "SecurityMode None is cleartext; Sign/SignAndEncrypt is not TLS, so read the endpoint list"},
	{4843, TransportTCP, "opc-ua-https", CategoryOT, "", true, ""},
	{5007, TransportTCP, "melsoft / melsec-slmp", CategoryOT, "", true, ""},
	{5094, TransportTCP, "hart-ip", CategoryOT, "", true, ""},
	{9600, TransportTCP, "omron-fins", CategoryOT, "", true, ""},
	{10001, TransportTCP, "atg (veeder-root)", CategoryOT, "", true, ""},
	{18245, TransportTCP, "ge-srtp", CategoryOT, "", true, ""},
	{20000, TransportTCP, "dnp3", CategoryOT, "", true, ""},
	{20547, TransportTCP, "proconos", CategoryOT, "", true, ""},
	{34964, TransportUDP, "profinet-cm (pnio dce/rpc)", CategoryOT, "", false, "PROFINET context manager; DCP discovery runs at layer 2"},
	{44818, TransportTCP, "ethernet-ip", CategoryOT, "", true, ""},
	{47808, TransportUDP, "bacnet", CategoryOT, "", false, ""},
	{48898, TransportTCP, "twincat-ads", CategoryOT, "", true, ""},
}

// Lookup returns the catalogue entry for port, preferring the TCP row when
// a port has both. ok is false when the port is not in the catalogue.
func Lookup(port int) (PortEntry, bool) {
	var udp *PortEntry
	for i := range wellKnownPorts {
		e := &wellKnownPorts[i]
		if e.Port != port {
			continue
		}
		if e.Transport == TransportTCP {
			return *e, true
		}
		udp = e
	}
	if udp != nil {
		return *udp, true
	}
	return PortEntry{}, false
}

// Ports returns a copy of the catalogue sorted by port, then transport.
func Ports() []PortEntry {
	out := make([]PortEntry, len(wellKnownPorts))
	copy(out, wellKnownPorts)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Transport < out[j].Transport
	})
	return out
}
