package render

import (
	"strings"
	"unicode/utf8"
)

// SafeBytes converts a potentially adversarial byte slice to a string
// suitable for terminal, log, and web rendering.
//
// Invariants:
//   - Valid UTF-8 codepoints other than C0/C1 control characters, DEL,
//     and the ANSI CSI introducer (ESC) are preserved.
//   - Invalid UTF-8 is replaced with the replacement character U+FFFD.
//   - C0 (0x00–0x1F) and C1 (0x80–0x9F) control characters and DEL
//     (0x7F) are rendered as their Unicode control-picture equivalents
//     (U+2400–U+2421 for C0; U+FFFD for C1) so they remain visible
//     without emitting control sequences.
//   - TAB (0x09) and LF (0x0A) are preserved to keep multi-line banners
//     readable; the rest of C0 is replaced.
//   - ANSI CSI (ESC = 0x1B) is replaced with U+241B regardless of what
//     follows.
//
// SafeBytes does not wrap or truncate; truncation is an evidence-layer
// concern (evidence.max_payload_bytes).
func SafeBytes(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))

	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune('\uFFFD')
			i++
			continue
		}

		switch {
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r == 0x7F:
			b.WriteRune('\u2421') // symbol for DELETE
		case r == 0x1B:
			b.WriteRune('\u241B') // symbol for ESCAPE
		case r < 0x20:
			// C0 picture block: U+2400 + r.
			b.WriteRune(0x2400 + r)
		case r >= 0x80 && r <= 0x9F:
			b.WriteRune('\uFFFD')
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}
