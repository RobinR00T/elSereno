package telemetry

import "strings"

// SafeField escapes characters that could inject log lines or break
// structured fields. It is the string-at-the-log-boundary complement to
// internal/render.SafeBytes (conventions.md).
func SafeField(name, value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case 0:
			b.WriteString(`\x00`)
		default:
			if r < 0x20 || (r >= 0x7F && r <= 0x9F) {
				b.WriteString(`\x`)
				const hex = "0123456789abcdef"
				// r is guaranteed <= 0x9F here, so truncation to byte is safe.
				c := byte(r & 0xff) // #nosec G115 -- range-bounded above.
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0x0f])
			} else {
				b.WriteRune(r)
			}
		}
	}
	_ = name // reserved for future per-field-name policy.
	return b.String()
}
