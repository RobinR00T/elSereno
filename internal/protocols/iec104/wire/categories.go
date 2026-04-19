package wire

// Category groups IEC 60870-5-104 APCI frame types for the proxy
// allow/deny matrix (ADR-040). I-format frames carry ASDUs with
// type IDs that include command-family codes 45..64 (single/double/
// regulating/bitstring/setpoint/control operation). Classifying at
// the ASDU level means parsing the ASDU header inside the I-frame
// payload; the default build refuses *all* I-frames and forwards
// only S-format (supervisory acks) and U-format (TESTFR/STARTDT/
// STOPDT activation+confirmation) which do not carry process data.
//
// The offensive build substitutes a handler that parses the ASDU
// and routes Control-family ASDUs through the triple-confirm
// wrapper.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback. Proxy refuses by default.
	CategoryUnknown Category = iota
	// CategoryRead covers supervisory (S) and unnumbered (U) frames.
	CategoryRead
	// CategoryWrite covers information (I) frames.
	CategoryWrite
)

// Classify returns the Category for a parsed APCI header.
func Classify(a APCI) Category {
	switch a.Type() {
	case FrameS, FrameU:
		return CategoryRead
	case FrameI:
		return CategoryWrite
	default:
		return CategoryUnknown
	}
}

// BuildRefusal returns a STOPDT_act U-format APDU (Control 0x13).
// Per IEC 60870-5-104 §5.4 this tells the master to cease I-frame
// transmission. A master that retries will hit the same refusal.
func BuildRefusal() []byte {
	return []byte{Start, 0x04, 0x13, 0x00, 0x00, 0x00}
}
