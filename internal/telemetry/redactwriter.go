package telemetry

import (
	"io"
	"regexp"
)

// keyedSecretRe matches "key=value", "key: value" and "key":"value" (or
// 'key':'value') where key names a secret. The value runs to the next
// space, comma, quote or ampersand, so a URL query (key=v&next=...) or a
// JSON field is redacted without eating the rest of the line. The key
// list mirrors RedactionPatterns and the header forms the input
// providers use (X-Key, API-KEY).
var keyedSecretRe = regexp.MustCompile(
	`(?i)\b(api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?key|session[_-]?key|encryption[_-]?key|auth[_-]?token|refresh[_-]?token|bearer[_-]?token|bearer|password|passphrase|secret|authorization|cookie|api-key|x-key)\b(["']?\s*[:=]\s*["']?)([^\s,"'&]+)`,
)

// bearerRe matches "Bearer <token>" (the Authorization header form),
// which has no key=value shape.
var bearerRe = regexp.MustCompile(`(?i)\b(bearer\s+)([A-Za-z0-9._~+/\-]{6,}=*)`)

// bareTokenRe isolates the runs of token characters the entropy
// heuristic then judges one by one, so punctuation and separators in a
// log line are left alone.
var bareTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_.\-]{21,}`)

// RedactWriter wraps an io.Writer and redacts each line before it is
// written: a secret named by a key (key=VALUE) and any bare
// high-entropy token (a credential logged on its own). It is installed
// on the standard logger at startup so every log.Printf in the binary
// is redacted at the sink, not at each call site (PITF-099; the design
// in telemetry/doc.go was never wired). Redaction here is defence in
// depth: code that handles a secret still must not log it in the clear
// on purpose. It is not exhaustive: a low-entropy token such as a hex
// key (<=4.0 bits/byte) does not cross the 4.5-bit bare-token threshold,
// a secret under 21 characters is below bareTokenRe's floor, and a
// direct fmt.Fprint to os.Stderr never reaches this sink. Upstream
// inputs.RedactQuery stays the primary defence.
type RedactWriter struct {
	w io.Writer
}

// NewRedactWriter wraps w. A nil w is treated as io.Discard by the
// caller; NewRedactWriter does not guard it.
func NewRedactWriter(w io.Writer) *RedactWriter { return &RedactWriter{w: w} }

// Write redacts p and forwards it. It always reports len(p) written on
// success, as an io.Writer must, even though the redacted form may be a
// different length.
func (rw *RedactWriter) Write(p []byte) (int, error) {
	out := RedactLine(string(p))
	if _, err := io.WriteString(rw.w, out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// RedactLine redacts a single log line (or any string): first the
// keyed-secret forms, then any remaining bare high-entropy token.
func RedactLine(line string) string {
	line = bearerRe.ReplaceAllString(line, "${1}"+RedactedPlaceholder)
	line = keyedSecretRe.ReplaceAllString(line, "${1}${2}"+RedactedPlaceholder)
	return bareTokenRe.ReplaceAllStringFunc(line, func(tok string) string {
		if uuidRe.MatchString(tok) {
			return tok
		}
		if ShannonEntropy(tok) > EntropyThresholdBitsPerByte {
			return RedactedPlaceholder
		}
		return tok
	})
}
