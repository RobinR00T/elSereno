package wire

import "encoding/binary"

// Category groups HART-IP message IDs for the proxy allow/deny
// matrix (ADR-040). Session-management IDs (Initiate / Close /
// Keepalive) are read-category — they do not touch process
// variables. TokenPassPDU carries a HART command frame that can be
// a read OR a write depending on the inner HART command; the
// default treats it as Write and the offensive build substitutes a
// HART-command-aware handler.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback. Proxy refuses by default.
	CategoryUnknown Category = iota
	// CategoryRead covers session-management messages.
	CategoryRead
	// CategoryWrite covers TokenPassPDU (mutations possible inside).
	CategoryWrite
)

// Classify returns the Category for a parsed HART-IP header.
func Classify(h Header) Category {
	switch h.MsgID {
	case IDSessionInitiate, IDSessionClose, IDKeepAlive:
		return CategoryRead
	case IDTokenPassPDU:
		return CategoryWrite
	default:
		return CategoryUnknown
	}
}

// BuildRefusal returns a HART-IP session-close response (MsgID
// 0x01, MsgType 0x01, Status 0x04 "Unsupported command") echoing
// the request's sequence so a client can correlate the refusal.
func BuildRefusal(req Header) []byte {
	out := make([]byte, HeaderLen)
	out[0] = Version
	out[1] = MsgResponse
	out[2] = IDSessionClose
	out[3] = 0x04 // Unsupported command
	binary.BigEndian.PutUint16(out[4:6], req.Sequence)
	binary.BigEndian.PutUint16(out[6:8], HeaderLen)
	return out
}
