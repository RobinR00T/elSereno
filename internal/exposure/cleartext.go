// Package exposure holds cross-cutting, protocol-agnostic exposure checks
// that back elSereno's mapping to NIST SP 800-82 Rev. 4 (see
// docs/standards/nist-sp800-82r4.md).
//
// The cleartext transport check evidences SP 800-82 r4 Table 16,
// "Standard, well-documented communication protocols are used in
// plaintext" and "Use of unsecure OT protocols": it actively determines
// whether a reachable service negotiates TLS, and names the plaintext
// protocol and its secure alternative when the port is well known. It is
// read-only: it opens a connection and attempts a TLS handshake, nothing
// more.
package exposure

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

// TransportResult reports what the cleartext check learned about a target.
type TransportResult struct {
	// Reachable is true once the TCP connection opened.
	Reachable bool `json:"reachable"`
	// TLS is true when the service completed a TLS handshake.
	TLS bool `json:"tls"`
	// TLSVersion names the negotiated version when TLS is true.
	TLSVersion string `json:"tls_version,omitempty"`
	// Cleartext is the headline: the service is reachable and does NOT
	// negotiate TLS, so its transport is in plaintext (SP 800-82 r4
	// Table 16).
	Cleartext bool `json:"cleartext"`
	// Protocol is the best-effort well-known protocol for the port.
	Protocol string `json:"protocol,omitempty"`
	// SecureAlternative names the encrypted counterpart when one exists
	// (e.g. https for http); empty for OT protocols with no in-protocol
	// TLS, whose mitigation is network segmentation, not a protocol swap.
	SecureAlternative string `json:"secure_alternative,omitempty"`
}

// portInfo is a well-known plaintext service and its secure counterpart.
type portInfo struct {
	protocol  string
	secureAlt string // "" when the mitigation is segmentation, not a swap
}

// cleartextPorts maps well-known TCP ports that carry plaintext transport
// to their protocol name and secure alternative. IT protocols have a
// drop-in encrypted counterpart; OT protocols (Modbus, S7, ...) generally
// do not, so their secureAlt is empty and the mitigation is segmentation.
var cleartextPorts = map[int]portInfo{
	// IT plaintext protocols with an encrypted counterpart.
	21:  {"ftp", "ftps"},
	23:  {"telnet", "ssh"},
	25:  {"smtp", "smtps"},
	80:  {"http", "https"},
	110: {"pop3", "pop3s"},
	143: {"imap", "imaps"},
	161: {"snmp", "snmpv3"},
	389: {"ldap", "ldaps"},
	513: {"rlogin", "ssh"},
	// OT protocols: cleartext by design, mitigation is segmentation.
	102:   {"s7comm / iso-tsap", ""},
	502:   {"modbus", ""},
	1911:  {"niagara-fox", ""},
	2404:  {"iec-104", ""},
	4840:  {"opc-ua-tcp", ""},
	9600:  {"omron-fins", ""},
	18245: {"ge-srtp", ""},
	20000: {"dnp3", ""},
	44818: {"ethernet-ip", ""},
	47808: {"bacnet", ""},
}

// ProtocolForPort returns the well-known plaintext protocol name and its
// secure alternative for a TCP port, or ("", "") when the port is not in
// the cleartext table.
func ProtocolForPort(port int) (protocol, secureAlt string) {
	if pi, ok := cleartextPorts[port]; ok {
		return pi.protocol, pi.secureAlt
	}
	return "", ""
}

// tlsVersionName renders a tls.Version* constant.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// ProbeCleartext opens a TCP connection to target (host:port) and reports
// whether the service negotiates TLS. A reachable service that does not
// complete a TLS handshake is flagged Cleartext. It is read-only. A
// dial/timeout failure is not an error: Reachable stays false.
func ProbeCleartext(ctx context.Context, target string, timeout time.Duration) (TransportResult, error) {
	var res TransportResult
	if _, portStr, err := net.SplitHostPort(target); err == nil {
		if port, err := strconv.Atoi(portStr); err == nil {
			res.Protocol, res.SecureAlternative = ProtocolForPort(port)
		}
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return res, nil //nolint:nilerr // a dial failure means "unreachable" (Reachable stays false), not a probe error
	}
	res.Reachable = true

	// Offer a broad ClientHello (TLS 1.0+) so a service on any TLS version
	// is detected. InsecureSkipVerify: this only classifies transport, it
	// never trusts the peer or exchanges data.
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10} // #nosec G402 -- detection-only: classifies cleartext vs TLS, never trusts the peer
	tconn := tls.Client(conn, cfg)
	_ = tconn.SetDeadline(time.Now().Add(timeout))
	if herr := tconn.HandshakeContext(ctx); herr == nil {
		res.TLS = true
		res.TLSVersion = tlsVersionName(tconn.ConnectionState().Version)
		_ = tconn.Close()
		return res, nil
	}
	_ = conn.Close()

	// The port is open TCP but did not complete a TLS handshake: its
	// transport is cleartext.
	res.Cleartext = true
	return res, nil
}
