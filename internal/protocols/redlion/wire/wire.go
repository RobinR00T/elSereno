// Package wire implements the minimum subset of Red Lion's
// Crimson / RLN (Red Lion Net) protocol needed for read-only
// fingerprinting on TCP/789. RLN is the proprietary protocol
// used by Red Lion Controls' G3 / G3 Kadet / Graphite / FlexEdge
// / DA-50N HMI families and by the Sixnet RTU-stripped variants
// after the 2017 Red Lion acquisition.
//
// Public protocol documentation is sparse; this package's
// classifier is reverse-engineered from Shodan banner data and
// public Crimson 3 firmware captures.
//
// This package implements ONLY a banner-substring classifier.
// The full RLN tag-length-value frame layout (3-byte handshake
// + variable-length TLV body) is out of scope for v1.22 chunk
// 3 — banner classification covers the common Internet-exposed
// shape (HMI gateways with default Crimson 3 firmware that
// announce themselves on connect).
//
// No service-request frames are issued; v1.22 chunk 3 is
// read-only by design.
package wire

import (
	"bytes"
	"errors"
)

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface
// on the dashboard).
var (
	// ErrShortFrame means the response is shorter than the 4-
	// byte minimum we'll bother to classify (any reasonable
	// banner has more than 4 bytes).
	ErrShortFrame = errors.New("redlion: response shorter than 4-byte minimum")
	// ErrNotRedLion means the response doesn't carry any of the
	// canonical Red Lion banner substrings.
	ErrNotRedLion = errors.New("redlion: response is not a recognisable Red Lion banner")
)

// RedLionBannerSubstrings are the canonical banner substrings
// the classifier looks for. Order matters slightly (most
// specific first) so the matched substring in the finding note
// is informative.
var RedLionBannerSubstrings = [][]byte{
	[]byte("Red Lion Controls"),
	[]byte("Red Lion"),
	[]byte("Crimson 3"),
	[]byte("CRIMSON 3"),
	[]byte("Crimson 2"),
	[]byte("FlexEdge"),
	[]byte("Graphite"),
	[]byte("DA-50N"),
	[]byte("DA50N"),
	[]byte("G3 Kadet"),
	[]byte("G3 HMI"),
	[]byte("Sixnet"), // Sixnet RTUs (acquired 2010, rebadged Red Lion 2017)
}

// BuildHello returns a 3-byte minimal probe. RLN servers
// typically send a banner on connect or after the first 3-byte
// handshake; sending zero bytes is enough to elicit the
// banner from many gateways.
//
// We send 3 zero bytes deliberately: most RLN dialects ignore
// zero-padded handshakes and respond with their default
// banner. This is intentionally minimal — no live state is
// established, no session is opened.
func BuildHello() []byte {
	return []byte{0x00, 0x00, 0x00}
}

// Classify validates a candidate Red Lion response. On success
// it returns a short note describing which banner substring
// matched; on failure the appropriate sentinel is returned.
func Classify(buf []byte) (string, error) {
	if len(buf) < 4 {
		return "", ErrShortFrame
	}
	for _, sub := range RedLionBannerSubstrings {
		if bytes.Contains(buf, sub) {
			return "banner=" + string(sub), nil
		}
	}
	return "", ErrNotRedLion
}

// IsRedLionBanner returns true iff the buffer contains any of
// the canonical Red Lion banner substrings.
func IsRedLionBanner(buf []byte) bool {
	for _, sub := range RedLionBannerSubstrings {
		if bytes.Contains(buf, sub) {
			return true
		}
	}
	return false
}
