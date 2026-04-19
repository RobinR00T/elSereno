package wire

// Category groups EIP commands for the proxy allow/deny matrix.
//
// The default-build policy is: allow session-management and list-
// identity traffic (read-only), refuse SendRRData / SendUnitData
// (the envelopes that carry CIP service requests — and therefore the
// vector for writes). Proper CIP-service-level classification lands
// with the offensive write plugin (F5) that actually speaks CIP.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback. Proxy refuses by default.
	CategoryUnknown Category = iota
	// CategoryRead covers handshake + listing commands.
	CategoryRead
	// CategoryWrite covers any command that may encapsulate a CIP
	// service request (because those can mutate the device).
	CategoryWrite
)

// Classify returns the Category for an EIP command code.
func Classify(cmd uint16) Category {
	switch cmd {
	case CmdListServices, CmdListIdentity, CmdListInterfaces,
		CmdRegisterSession, CmdUnregisterSess:
		return CategoryRead
	case CmdSendRRData, CmdSendUnitData:
		return CategoryWrite
	default:
		return CategoryUnknown
	}
}

// BuildRefusal returns a CIP encapsulation reply echoing the request
// command code with status 0x0001 (Invalid/unsupported command) —
// the closest the protocol has to "service not supported" at the
// encapsulation layer.
func BuildRefusal(req Header) []byte {
	h := Header{
		Command:       req.Command,
		Length:        0,
		SessionHandle: req.SessionHandle,
		Status:        0x00000001, // Invalid or unsupported command
		SenderContext: req.SenderContext,
		Options:       req.Options,
	}
	buf := MarshalHeader(h)
	return buf[:]
}
