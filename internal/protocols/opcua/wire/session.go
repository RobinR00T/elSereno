package wire

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
