package wire

// OPC UA GetEndpoints codec for the HTTPS transport binding
// (OPC-UA Part 4 §5.4.4 service, Part 6 §5.2 binary encoding, §7.4
// HTTPS mapping).
//
// The HTTPS binding carries a UA message as the HTTP POST body with
// Content-Type application/octet-stream; HTTP+TLS replaces the opc.tcp
// / SecureChannel framing entirely (Part 6 §7.4.4). The body is the
// service message in UA Binary: the FourByte NodeId of the message's
// DefaultBinary encoding followed by the encoded fields — the same
// "message" encoding this package already parses for opc.tcp MSG
// bodies (ServiceTypeID) and that the UA-.NETStandard
// HttpsTransportChannel emits via BinaryEncoder.EncodeMessage.
//
// (§7.4.4's prose calls the body an "ExtensionObject"; the reference
// .NET stack — effectively the only one that ships the HTTPS binary
// binding — writes the message encoding, i.e. TypeId + body with no
// ExtensionObject length prefix, which is what real servers accept.
// We use that interoperable form; a capture against a specific server
// can confirm the variant it expects.)
//
// GetEndpoints is session-less and unauthenticated (Part 4 §5.4.4), so
// this is a read-only discovery probe: it never opens a SecureChannel,
// session, or write.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// GetEndpoints message TypeIds (namespace 0, DefaultBinary encoding
// NodeIds — verified against the OPC Foundation NodeIds.csv, the same
// convention as TypeIDWriteRequest=673).
const (
	TypeIDGetEndpointsRequest  uint16 = 428
	TypeIDGetEndpointsResponse uint16 = 431
)

// MessageSecurityMode values (Part 4 §7.15).
const (
	SecurityModeInvalid        uint32 = 0
	SecurityModeNone           uint32 = 1
	SecurityModeSign           uint32 = 2
	SecurityModeSignAndEncrypt uint32 = 3
)

// SecurityModeName renders a MessageSecurityMode for findings.
func SecurityModeName(m uint32) string {
	switch m {
	case SecurityModeNone:
		return "None"
	case SecurityModeSign:
		return "Sign"
	case SecurityModeSignAndEncrypt:
		return "SignAndEncrypt"
	default:
		return "Invalid"
	}
}

// EndpointDescription is the subset of Part 4 §7.10 that matters for
// fingerprinting an OPC UA server's exposed endpoints + security
// posture.
type EndpointDescription struct {
	EndpointURL         string
	ApplicationURI      string
	ProductURI          string
	ApplicationName     string
	SecurityMode        uint32
	SecurityPolicyURI   string
	TransportProfileURI string
	SecurityLevel       byte
}

// ---- encoding ------------------------------------------------------

func putU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

// putString appends a UA Binary String: Int32 length (LE, -1 = null)
// then the UTF-8 bytes.
func putString(b []byte, s string) []byte {
	if s == "" {
		// An empty (non-null) string is length 0; a null string is
		// length -1. GetEndpoints treats "" endpointUrl as valid, so
		// we send length 0, not null.
		return putU32(b, 0)
	}
	b = putU32(b, uint32(len(s))) // #nosec G115 -- endpointURL length fits uint32
	return append(b, s...)
}

// putNullString appends a null UA Binary String (length -1).
func putNullString(b []byte) []byte { return putU32(b, 0xFFFFFFFF) }

// putNullArray appends a null UA Binary array (Int32 count -1).
func putNullArray(b []byte) []byte { return putU32(b, 0xFFFFFFFF) }

// putFourByteNodeID appends a FourByte NodeId (encoding 0x01, ns u8,
// identifier u16 LE) — the form service message TypeIds use.
func putFourByteNodeID(b []byte, id uint16) []byte {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], id)
	return append(b, byte(NodeIDFourByte), 0x00, tmp[0], tmp[1])
}

// EncodeGetEndpointsRequest builds the UA Binary message body for a
// GetEndpointsRequest carrying endpointURL. This is the HTTP POST body
// for the HTTPS binding (no opc.tcp / SecureChannel header). The
// RequestHeader is minimal: null auth token, zero timestamp, handle 1,
// no diagnostics, null auditEntryId, no timeout, null additionalHeader.
func EncodeGetEndpointsRequest(endpointURL string) []byte {
	b := make([]byte, 0, 64+len(endpointURL))
	b = putFourByteNodeID(b, TypeIDGetEndpointsRequest)
	// RequestHeader (Part 4 §7.28).
	b = append(b, 0x00, 0x00)       // authenticationToken: null NodeId (TwoByte, id 0)
	b = putU32(b, 0)                // timestamp low 32 bits ...
	b = putU32(b, 0)                // ... DateTime is 8 bytes (ticks), zero = null
	b = putU32(b, 1)                // requestHandle
	b = putU32(b, 0)                // returnDiagnostics
	b = putNullString(b)            // auditEntryId
	b = putU32(b, 0)                // timeoutHint
	b = append(b, 0x00, 0x00, 0x00) // additionalHeader ExtensionObject: null NodeId + encoding 0x00
	// GetEndpointsRequest fields.
	b = putString(b, endpointURL) // endpointUrl
	b = putNullArray(b)           // localeIds (null)
	b = putNullArray(b)           // profileUris (null)
	return b
}

// ---- decoding ------------------------------------------------------

var (
	// ErrShortResponse means the response body ended mid-field.
	ErrShortResponse = errors.New("opcua/wire: GetEndpointsResponse truncated")
	// ErrWrongResponseType means the message TypeId was not a
	// GetEndpointsResponse.
	ErrWrongResponseType = errors.New("opcua/wire: not a GetEndpointsResponse")
	// ErrTooManyEndpoints guards against a hostile/garbage array count.
	ErrTooManyEndpoints = errors.New("opcua/wire: implausible endpoint array count")
)

// maxEndpoints caps the endpoints array so a bogus count can't drive a
// huge allocation. Real servers expose a handful.
const maxEndpoints = 256

// cur is a bounds-checked little-endian cursor over a response body.
type cur struct {
	b   []byte
	off int
	err error
}

func (c *cur) fail() bool { return c.err != nil }

func (c *cur) need(n int) bool {
	if c.err != nil {
		return false
	}
	if c.off+n > len(c.b) {
		c.err = ErrShortResponse
		return false
	}
	return true
}

func (c *cur) u8() byte {
	if !c.need(1) {
		return 0
	}
	v := c.b[c.off]
	c.off++
	return v
}

func (c *cur) u32() uint32 {
	if !c.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(c.b[c.off : c.off+4])
	c.off += 4
	return v
}

func (c *cur) i32() int32 { return int32(c.u32()) } // #nosec G115 -- UA Binary Int32 is the u32 bit pattern (reinterpret, not a bounded conversion).

func (c *cur) skip(n int) {
	if n < 0 {
		c.err = ErrShortResponse
		return
	}
	if c.need(n) {
		c.off += n
	}
}

// str reads a UA Binary String (Int32 length; -1 = null).
func (c *cur) str() string {
	n := c.i32()
	if c.fail() || n <= 0 {
		return ""
	}
	if !c.need(int(n)) {
		return ""
	}
	s := string(c.b[c.off : c.off+int(n)])
	c.off += int(n)
	return s
}

// byteString skips a UA Binary ByteString (Int32 length; -1 = null).
func (c *cur) byteString() {
	n := c.i32()
	if c.fail() || n <= 0 {
		return
	}
	c.skip(int(n))
}

// nullableArrayLen reads an array count and normalises -1 (null) to 0.
func (c *cur) arrayLen() int32 {
	n := c.i32()
	if n < 0 {
		return 0
	}
	return n
}

// nodeID skips a NodeId of any encoding form (Part 6 §5.2.2.9).
func (c *cur) nodeID() {
	enc := NodeIDEncoding(c.u8() & 0x0F)
	switch enc {
	case NodeIDTwoByte:
		c.skip(1)
	case NodeIDFourByte:
		c.skip(3)
	case NodeIDNumeric:
		c.skip(6) // ns u16 + id u32
	case NodeIDString, NodeIDByteString:
		c.skip(2) // ns u16
		c.byteString()
	case NodeIDGuid:
		c.skip(2 + 16) // ns u16 + guid
	default:
		c.err = ErrShortResponse
	}
}

// extensionObject skips an ExtensionObject (Part 6 §5.2.2.15).
func (c *cur) extensionObject() {
	c.nodeID()
	enc := c.u8()
	switch enc {
	case 0x00:
		// no body
	case 0x01, 0x02:
		c.byteString() // ByteString / XmlElement body (both Int32-len)
	default:
		c.err = ErrShortResponse
	}
}

// diagnosticInfo skips a DiagnosticInfo (Part 6 §5.2.2.12).
func (c *cur) diagnosticInfo() {
	mask := c.u8()
	if c.fail() {
		return
	}
	if mask&0x01 != 0 {
		c.skip(4) // symbolicId i32
	}
	if mask&0x02 != 0 {
		c.skip(4) // namespaceUri i32
	}
	if mask&0x04 != 0 {
		c.skip(4) // locale i32
	}
	if mask&0x08 != 0 {
		c.skip(4) // localizedText i32
	}
	if mask&0x10 != 0 {
		_ = c.str() // additionalInfo String
	}
	if mask&0x20 != 0 {
		c.skip(4) // innerStatusCode
	}
	if mask&0x40 != 0 {
		c.diagnosticInfo() // innerDiagnosticInfo (recursive)
	}
}

// localizedText reads a LocalizedText (Part 6 §5.2.2.14) and returns
// its text.
func (c *cur) localizedText() string {
	mask := c.u8()
	if c.fail() {
		return ""
	}
	if mask&0x01 != 0 {
		_ = c.str() // locale
	}
	var text string
	if mask&0x02 != 0 {
		text = c.str()
	}
	return text
}

// responseHeader skips a ResponseHeader (Part 4 §7.29).
func (c *cur) responseHeader() {
	c.skip(8)          // timestamp DateTime
	c.skip(4)          // requestHandle
	c.skip(4)          // serviceResult StatusCode
	c.diagnosticInfo() // serviceDiagnostics
	n := c.arrayLen()  // stringTable []String
	for i := int32(0); i < n && !c.fail(); i++ {
		_ = c.str()
	}
	c.extensionObject() // additionalHeader
}

// applicationDescription reads Part 4 §7.1 and returns the interesting
// identity fields.
func (c *cur) applicationDescription() (appURI, prodURI, appName string) {
	appURI = c.str()  // applicationUri
	prodURI = c.str() // productUri
	appName = c.localizedText()
	c.skip(4)         // applicationType enum
	_ = c.str()       // gatewayServerUri
	_ = c.str()       // discoveryProfileUri
	n := c.arrayLen() // discoveryUrls []String
	for i := int32(0); i < n && !c.fail(); i++ {
		_ = c.str()
	}
	return appURI, prodURI, appName
}

// userTokenPolicy skips one UserTokenPolicy (Part 4 §7.42).
func (c *cur) userTokenPolicy() {
	_ = c.str() // policyId
	c.skip(4)   // tokenType enum
	_ = c.str() // issuedTokenType
	_ = c.str() // issuerEndpointUrl
	_ = c.str() // securityPolicyUri
}

// endpointDescription reads one EndpointDescription (Part 4 §7.10).
func (c *cur) endpointDescription() EndpointDescription {
	var e EndpointDescription
	e.EndpointURL = c.str()
	e.ApplicationURI, e.ProductURI, e.ApplicationName = c.applicationDescription()
	c.byteString() // serverCertificate
	e.SecurityMode = c.u32()
	e.SecurityPolicyURI = c.str()
	n := c.arrayLen() // userIdentityTokens []UserTokenPolicy
	for i := int32(0); i < n && !c.fail(); i++ {
		c.userTokenPolicy()
	}
	e.TransportProfileURI = c.str()
	e.SecurityLevel = c.u8()
	return e
}

// DecodeGetEndpointsResponse parses the HTTPS-binding response body
// (message TypeId + ResponseHeader + EndpointDescription array) and
// returns the endpoint descriptions. It is defensive: every read is
// bounds-checked and the array count is capped.
func DecodeGetEndpointsResponse(body []byte) ([]EndpointDescription, error) {
	c := &cur{b: body}
	// Message TypeId: FourByte NodeId of GetEndpointsResponse.
	enc := NodeIDEncoding(c.u8())
	var typeID uint16
	switch enc {
	case NodeIDFourByte:
		if c.u8() != 0 { // namespace must be 0
			return nil, ErrWrongResponseType
		}
		typeID = uint16(c.u8()) | uint16(c.u8())<<8
	case NodeIDTwoByte:
		typeID = uint16(c.u8())
	default:
		return nil, ErrWrongResponseType
	}
	if c.fail() {
		return nil, c.err
	}
	if typeID != TypeIDGetEndpointsResponse {
		return nil, fmt.Errorf("%w: TypeId=%d", ErrWrongResponseType, typeID)
	}
	c.responseHeader()
	n := c.arrayLen()
	if n > maxEndpoints {
		return nil, fmt.Errorf("%w: %d", ErrTooManyEndpoints, n)
	}
	eps := make([]EndpointDescription, 0, n)
	for i := int32(0); i < n && !c.fail(); i++ {
		eps = append(eps, c.endpointDescription())
	}
	if c.fail() {
		return nil, c.err
	}
	return eps, nil
}
