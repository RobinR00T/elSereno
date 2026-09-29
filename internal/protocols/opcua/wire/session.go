package wire

import (
	"encoding/binary"
	"math"
)

// Session-establishment request encoders for the OPC UA anonymous-access
// exposure probe. These build the client-to-server messages needed to
// prove that an anonymous session actually opens on a SecurityPolicy#None
// endpoint (not just that None is advertised): OpenSecureChannel(None),
// CreateSession, ActivateSession(Anonymous).
//
// SecurityPolicy#None only: the probe targets the insecure endpoints an
// exposure auditor cares about, and None means no certificates, no
// signatures, no encryption, so the wire is plain and deterministic.
// Field order/values follow real captured requests (see the tests) and
// OPC-UA Part 4 (services) + Part 6 (binary encoding).

// SecurityPolicyURINone is the SecurityPolicy#None URI.
const SecurityPolicyURINone = "http://opcfoundation.org/UA/SecurityPolicy#None"

// putRequestHeader appends a minimal RequestHeader (Part 4 §7.33) whose
// authenticationToken is the given raw NodeId bytes (pass the 2-byte null
// TwoByte NodeId {0x00,0x00} before a session exists, or the token from
// CreateSessionResponse afterwards). Timestamp 0, handle 1, no
// diagnostics, null auditEntryId, no timeout, null additionalHeader.
func putRequestHeader(b, authToken []byte) []byte {
	b = append(b, authToken...)
	b = putU32(b, 0)                // Timestamp low ...
	b = putU32(b, 0)                // ... DateTime (8 bytes) = 0
	b = putU32(b, 1)                // RequestHandle
	b = putU32(b, 0)                // ReturnDiagnostics
	b = putNullString(b)            // AuditEntryId
	b = putU32(b, 0)                // TimeoutHint
	b = append(b, 0x00, 0x00, 0x00) // AdditionalHeader: null ExtensionObject
	return b
}

// nullAuthToken is the RequestHeader authenticationToken before a session
// exists: a null TwoByte NodeId (id 0).
var nullAuthToken = []byte{0x00, 0x00}

// EncodeOpenSecureChannelRequestNone builds an OPN OpenSecureChannelRequest
// for SecurityPolicy#None (requestType Issue, securityMode None, empty
// client nonce). seqNum/reqID go in the sequence header;
// requestedLifetime is the requested token lifetime in milliseconds.
func EncodeOpenSecureChannelRequestNone(seqNum, reqID, requestedLifetime uint32) []byte {
	var b []byte
	b = putU32(b, 0)                        // SecureChannelId = 0 (initial OPN)
	b = putString(b, SecurityPolicyURINone) // SecurityPolicyUri
	b = putNullString(b)                    // SenderCertificate (null)
	b = putNullString(b)                    // ReceiverCertificateThumbprint (null)
	b = putU32(b, seqNum)                   // SequenceNumber
	b = putU32(b, reqID)                    // RequestId
	b = putFourByteNodeID(b, TypeIDOpenSecureChannelRequest)
	b = putRequestHeader(b, nullAuthToken)
	// OpenSecureChannelRequest body:
	b = putU32(b, 0)                // ClientProtocolVersion
	b = putU32(b, 0)                // RequestType = Issue
	b = putU32(b, SecurityModeNone) // MessageSecurityMode = None
	b = putU32(b, 0)                // ClientNonce: empty ByteString (len 0)
	b = putU32(b, requestedLifetime)
	return wrap(MessageOpen, b)
}

// putDouble appends a little-endian IEEE-754 float64 (Part 6 §5.2.2.5).
func putDouble(b []byte, f float64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], math.Float64bits(f))
	return append(b, tmp[:]...)
}

// putByteString appends a UA Binary ByteString: Int32 length (-1 = null)
// then the bytes. A nil slice is encoded null.
func putByteString(b, data []byte) []byte {
	if data == nil {
		return putU32(b, 0xFFFFFFFF)
	}
	b = putU32(b, uint32(len(data))) // #nosec G115 -- probe nonces/certs are small
	return append(b, data...)
}

// putSymmetricHeader appends the MSG symmetric security header +
// sequence header: SecureChannelId + TokenId + SequenceNumber +
// RequestId (the 16-byte prefix every MSG body carries).
func putSymmetricHeader(channelID, tokenID, seqNum, reqID uint32) []byte {
	b := putU32(nil, channelID)
	b = putU32(b, tokenID)
	b = putU32(b, seqNum)
	return putU32(b, reqID)
}

// elSereno's client identity in the ApplicationDescription. A benign,
// honest identity for authorised scanning (not stealth).
const (
	clientAppURI  = "urn:elsereno:opcua-probe"
	clientProdURI = "urn:elsereno"
	clientAppName = "elsereno"
)

// putClientDescription appends the client's ApplicationDescription
// (Part 4 §7.1) with applicationType Client.
func putClientDescription(b []byte) []byte {
	b = putString(b, clientAppURI)
	b = putString(b, clientProdURI)
	b = putLocalizedText(b, clientAppName)
	b = putU32(b, 1)     // applicationType = Client
	b = putNullString(b) // gatewayServerUri
	b = putNullString(b) // discoveryProfileUri
	b = putNullArray(b)  // discoveryUrls
	return b
}

// EncodeCreateSessionRequest builds a CreateSessionRequest MSG on an open
// secure channel. clientNonce should be 32 random bytes (crypto/rand);
// clientCertificate is null (SecurityPolicy#None).
func EncodeCreateSessionRequest(channelID, tokenID, seqNum, reqID uint32, endpointURL, sessionName string, clientNonce []byte) []byte {
	b := putSymmetricHeader(channelID, tokenID, seqNum, reqID)
	b = putFourByteNodeID(b, TypeIDCreateSessionRequest)
	b = putRequestHeader(b, nullAuthToken)
	// CreateSessionRequest body (Part 4 §5.6.2):
	b = putClientDescription(b)
	b = putNullString(b)              // ServerUri
	b = putString(b, endpointURL)     // EndpointUrl
	b = putString(b, sessionName)     // SessionName
	b = putByteString(b, clientNonce) // ClientNonce
	b = putByteString(b, nil)         // ClientCertificate: null (None)
	b = putDouble(b, 60000)           // RequestedSessionTimeout (ms)
	b = putU32(b, 0)                  // MaxResponseMessageSize (0 = no limit)
	return wrap(MessageMessage, b)
}

// anonymousIdentityTokenBinaryID is the NodeId of
// AnonymousIdentityToken_Encoding_DefaultBinary (ns=0, i=321).
const anonymousIdentityTokenBinaryID uint16 = 321

// EncodeActivateSessionRequestAnonymous builds an ActivateSessionRequest
// that authenticates as the anonymous user. authToken is the raw
// AuthenticationToken NodeId from CreateSessionResponse; policyID is the
// PolicyId the endpoint advertised for its anonymous UserTokenPolicy
// (servers differ: "0", "anonymous", ...), so it must come from
// GetEndpoints. All signatures are null (SecurityPolicy#None).
func EncodeActivateSessionRequestAnonymous(channelID, tokenID, seqNum, reqID uint32, authToken []byte, policyID string) []byte {
	b := putSymmetricHeader(channelID, tokenID, seqNum, reqID)
	b = putFourByteNodeID(b, TypeIDActivateSessionRequest)
	b = putRequestHeader(b, authToken)
	// ActivateSessionRequest body (Part 4 §5.6.3):
	b = putNullString(b)      // clientSignature.algorithm
	b = putByteString(b, nil) // clientSignature.signature
	b = putU32(b, 0)          // clientSoftwareCertificates: empty array
	b = putU32(b, 0)          // localeIds: empty array
	// userIdentityToken: ExtensionObject(AnonymousIdentityToken).
	var tok []byte
	tok = putString(tok, policyID) // AnonymousIdentityToken.policyId
	b = putFourByteNodeID(b, anonymousIdentityTokenBinaryID)
	b = append(b, 0x01)             // Encoding: ByteString body
	b = putU32(b, uint32(len(tok))) // #nosec G115 -- policyId is short
	b = append(b, tok...)
	b = putNullString(b)      // userTokenSignature.algorithm
	b = putByteString(b, nil) // userTokenSignature.signature
	return wrap(MessageMessage, b)
}

// EncodeGetEndpointsRequestTCP wraps the bare GetEndpointsRequest in a MSG
// on an open secure channel (symmetric security + sequence header), so the
// endpoint list, and the anonymous PolicyId inside it, can be read over
// opc.tcp. (EncodeGetEndpointsRequest alone is the bare body for the HTTPS
// binding.)
func EncodeGetEndpointsRequestTCP(channelID, tokenID, seqNum, reqID uint32, endpointURL string) []byte {
	b := putSymmetricHeader(channelID, tokenID, seqNum, reqID)
	b = append(b, EncodeGetEndpointsRequest(endpointURL)...)
	return wrap(MessageMessage, b)
}
