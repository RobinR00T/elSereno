package wire

// Category groups DNP3 link-layer primary functions for the proxy
// allow/deny matrix (ADR-040).
//
// The default proxy is conservative: the only primary functions that
// forward untouched are the two that only inspect link state (Test
// Link + Request Link Status). User-data frames may carry an
// application-layer write (IEEE 1815 application function 2 "Write",
// 5 "Direct Operate", 6 "DO-NR", 13 "Cold Restart", 14 "Warm
// Restart", 18 "Stop Application"), so the default treats them as
// Write. The offensive build adds application-layer classification
// via a dedicated write plugin.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback. Proxy refuses by default.
	CategoryUnknown Category = iota
	// CategoryRead covers link-layer read-only primitives.
	CategoryRead
	// CategoryWrite covers user-data frames and link-reset frames.
	CategoryWrite
)

// Primary link-layer function codes (IEEE 1815 §9.2.4.1.3). Only
// the ones we classify here are named; others fall into
// CategoryUnknown.
const (
	PrimaryResetLinkStates  uint8 = 0
	PrimaryTestLinkStates   uint8 = 1
	PrimaryConfirmedData    uint8 = 3
	PrimaryUnconfirmedData  uint8 = 4
	PrimaryRequestLinkState uint8 = 9
)

// ClassifyControl returns the Category for a DNP3 link-layer control
// byte. Only PRM=1 (primary) frames are classified; PRM=0 frames
// are always allowed (they are responses from the outstation that
// the master is reading, not commands into the outstation).
func ClassifyControl(ctrl uint8) Category {
	// PRM = bit 6 (0x40).
	if ctrl&0x40 == 0 {
		return CategoryRead
	}
	fc := ctrl & 0x0F
	switch fc {
	case PrimaryTestLinkStates, PrimaryRequestLinkState:
		return CategoryRead
	case PrimaryResetLinkStates, PrimaryConfirmedData, PrimaryUnconfirmedData:
		return CategoryWrite
	default:
		return CategoryUnknown
	}
}

// BuildRefusal returns a DNP3 link-layer secondary "Not Supported"
// frame (FC 15, PRM=0) echoing the request's source and destination
// swapped. CRC is zeroed: proxy refusal frames do not need to pass
// an outstation's CRC check — a legitimate master that sees CRC
// failure simply retries, which the proxy will refuse again.
func BuildRefusal(req Header) []byte {
	out := make([]byte, HeaderLen)
	out[0], out[1] = StartBytes[0], StartBytes[1]
	out[2] = 0x05 // length
	out[3] = 0x0F // control: DIR=0, PRM=0, DFC=0, FC=15 (Not Supported)
	out[4] = byte(req.Src & 0xFF)
	out[5] = byte(req.Src >> 8)
	out[6] = byte(req.Dest & 0xFF)
	out[7] = byte(req.Dest >> 8)
	return out
}
