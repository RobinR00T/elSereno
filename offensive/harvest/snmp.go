//go:build offensive

package harvest

import (
	"context"
	"encoding/binary"
	"net"
	"time"
)

// SNMPProber sends a single SNMPv2c GetRequest for sysDescr.0
// (1.3.6.1.2.1.1.1.0) using each Credential.Community; a valid
// GetResponse with error-status == 0 signals the community is
// correct. The prober emits and parses the minimum ASN.1-BER bytes
// needed for this one OID — no third-party SNMP library.
type SNMPProber struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// NewSNMP returns a prober with conservative timeouts.
func NewSNMP() *SNMPProber {
	return &SNMPProber{DialTimeout: 3 * time.Second, IOTimeout: 2 * time.Second}
}

// Name implements Prober.
func (s *SNMPProber) Name() string { return "snmp" }

// DefaultPort implements Prober.
func (s *SNMPProber) DefaultPort() uint16 { return 161 }

// Probe implements Prober.
func (s *SNMPProber) Probe(ctx context.Context, target string, creds []Credential) (*Result, error) {
	for _, c := range creds {
		if c.Community == "" {
			continue
		}
		hit, banner, err := s.attempt(ctx, target, c.Community)
		if err != nil {
			continue
		}
		if hit {
			return &Result{
				Protocol:   s.Name(),
				Target:     target,
				Credential: Credential{Community: c.Community},
				Banner:     banner,
				At:         time.Now().UTC().Truncate(time.Microsecond),
			}, nil
		}
	}
	return nil, ErrNoHit
}

func (s *SNMPProber) attempt(ctx context.Context, target, community string) (bool, string, error) {
	d := net.Dialer{Timeout: s.DialTimeout}
	conn, err := d.DialContext(ctx, "udp", target)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(s.IOTimeout))
	reqID := uint32(time.Now().UnixNano() & 0x7FFFFFFF)
	pkt := BuildSNMPGetSysDescr(community, reqID)
	if _, err := conn.Write(pkt); err != nil {
		return false, "", err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, "", err
	}
	return ParseSNMPGetResponse(buf[:n], community)
}

// BuildSNMPGetSysDescr encodes an SNMPv2c GetRequest for
// 1.3.6.1.2.1.1.1.0 (sysDescr.0) with the given community and
// request id. The byte layout is hand-crafted — no third-party ASN.1
// library — because this is the only OID the harvester ever sends.
func BuildSNMPGetSysDescr(community string, requestID uint32) []byte {
	// VarBind: SEQ { OID 1.3.6.1.2.1.1.1.0, NULL }
	oidBytes := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	nullBytes := []byte{0x05, 0x00}
	varbind := append([]byte{}, oidBytes...)
	varbind = append(varbind, nullBytes...)
	varbindSeq := wrap(0x30, varbind)

	// VarBindList: SEQ { varbind }
	varbindList := wrap(0x30, varbindSeq)

	// PDU body: request-id INTEGER (4 bytes) + error-status INT 0 +
	// error-index INT 0 + varbindList
	var ridBuf [4]byte
	binary.BigEndian.PutUint32(ridBuf[:], requestID)
	ridField := wrap(0x02, ridBuf[:])
	zeroInt := []byte{0x02, 0x01, 0x00}
	pduBody := append([]byte{}, ridField...)
	pduBody = append(pduBody, zeroInt...)
	pduBody = append(pduBody, zeroInt...)
	pduBody = append(pduBody, varbindList...)

	// GetRequest PDU: context-specific [0] = 0xA0
	pdu := wrap(0xA0, pduBody)

	// Message: SEQ { version INT 1, community OCTET-STRING, pdu }
	version := []byte{0x02, 0x01, 0x01} // v2c
	communityField := wrap(0x04, []byte(community))
	msgBody := append([]byte{}, version...)
	msgBody = append(msgBody, communityField...)
	msgBody = append(msgBody, pdu...)

	return wrap(0x30, msgBody)
}

// wrap prepends `tag` + BER length to `body`.
func wrap(tag byte, body []byte) []byte {
	out := []byte{tag}
	n := len(body)
	switch {
	case n < 128:
		// #nosec G115 -- n < 128 always fits uint8
		out = append(out, byte(n))
	case n < 256:
		// #nosec G115 -- n < 256 always fits uint8
		out = append(out, 0x81, byte(n))
	default:
		// #nosec G115 -- len(body) bounded by SNMP frames (< 4 KiB)
		out = append(out, 0x82, byte(n>>8), byte(n&0xFF))
	}
	return append(out, body...)
}

// ParseSNMPGetResponse returns (ok, sysDescrValue, err).
//
// It does the minimum walking needed to classify a response:
//  1. Outermost SEQUENCE.
//  2. version INTEGER = 0 or 1.
//  3. community OCTET STRING must equal the requested community.
//  4. PDU tag 0xA2 (GetResponse).
//  5. error-status INTEGER == 0.
//  6. first VarBind value decoded as text if OCTET STRING.
func ParseSNMPGetResponse(pkt []byte, wantCommunity string) (bool, string, error) {
	pduBody, err := unwrapToPDU(pkt, wantCommunity)
	if err != nil {
		return false, "", err
	}
	if pduBody == nil {
		// Community mismatch — parse succeeded but wrong key.
		return false, "", nil
	}
	return readFirstVarBind(pduBody)
}

// unwrapToPDU walks the outer Message, verifies community, and
// returns the PDU body. (nil, nil) means a clean parse where the
// community did not match (caller treats as negative result).
func unwrapToPDU(pkt []byte, wantCommunity string) ([]byte, error) {
	body, err := unwrap(pkt, 0x30)
	if err != nil {
		return nil, err
	}
	version, body, err := takeField(body, 0x02)
	if err != nil {
		return nil, err
	}
	if len(version) != 1 || (version[0] != 0x00 && version[0] != 0x01) {
		return nil, errBadWire
	}
	community, body, err := takeField(body, 0x04)
	if err != nil {
		return nil, err
	}
	if string(community) != wantCommunity {
		return nil, nil
	}
	pduBody, _, err := takeField(body, 0xA2)
	if err != nil {
		return nil, err
	}
	// request-id, error-status, error-index.
	_, pduBody, err = takeField(pduBody, 0x02)
	if err != nil {
		return nil, err
	}
	errStatus, pduBody, err := takeField(pduBody, 0x02)
	if err != nil {
		return nil, err
	}
	if len(errStatus) != 1 || errStatus[0] != 0x00 {
		return nil, nil
	}
	_, pduBody, err = takeField(pduBody, 0x02)
	if err != nil {
		return nil, err
	}
	return pduBody, nil
}

// readFirstVarBind walks the varbind-list and decodes the first
// value as text when it is OCTET STRING.
func readFirstVarBind(pduBody []byte) (bool, string, error) {
	vbList, _, err := takeField(pduBody, 0x30)
	if err != nil {
		return false, "", err
	}
	vb, _, err := takeField(vbList, 0x30)
	if err != nil {
		return false, "", err
	}
	_, vb, err = takeField(vb, 0x06) // OID
	if err != nil {
		return false, "", err
	}
	if len(vb) < 2 {
		return true, "", nil
	}
	if vb[0] == 0x04 {
		val, _, verr := takeField(vb, 0x04)
		if verr != nil {
			return true, "", verr
		}
		return true, string(val), nil
	}
	return true, "", nil
}

// unwrap checks `tag` and returns the body of a single TLV.
func unwrap(b []byte, tag byte) ([]byte, error) {
	if len(b) < 2 || b[0] != tag {
		return nil, errBadWire
	}
	body, _, err := takeField(b, tag)
	return body, err
}

// takeField consumes one TLV with the given `tag` at the head of `b`
// and returns (value, remaining, error).
func takeField(b []byte, tag byte) ([]byte, []byte, error) {
	if len(b) < 2 || b[0] != tag {
		return nil, nil, errBadWire
	}
	off := 1
	var n int
	l := b[off]
	off++
	switch {
	case l < 0x80:
		n = int(l)
	case l == 0x81:
		if off >= len(b) {
			return nil, nil, errBadWire
		}
		n = int(b[off])
		off++
	case l == 0x82:
		if off+1 >= len(b) {
			return nil, nil, errBadWire
		}
		n = int(b[off])<<8 | int(b[off+1])
		off += 2
	default:
		return nil, nil, errBadWire
	}
	if off+n > len(b) {
		return nil, nil, errBadWire
	}
	return b[off : off+n], b[off+n:], nil
}

// errBadWire is returned by the ASN.1 helpers.
var errBadWire = snmpError("snmp: bad wire format")

// snmpError is a constant-string sentinel.
type snmpError string

func (e snmpError) Error() string { return string(e) }
