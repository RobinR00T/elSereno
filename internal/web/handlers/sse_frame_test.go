package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/web/stream"
)

// TestWriteSSEEvent_NewlineCannotInject pins L8: a newline in the
// event kind or payload must not break SSE framing or let an attacker
// inject extra fields or whole events. The kind is stripped of CR/LF
// and every payload line is carried as its own `data:` field, so no
// line reaches the wire unframed.
func TestWriteSSEEvent_NewlineCannotInject(t *testing.T) {
	rec := httptest.NewRecorder()
	ev := stream.Event{
		ID:      7,
		Kind:    stream.EventKind("finding\nevent: injected"),
		Payload: []byte("{\"a\":1}\nevent: injected\ndata: nope"),
	}
	if err := writeSSEEvent(rec, ev); err != nil {
		t.Fatal(err)
	}
	out := rec.Body.String()

	eventLines := 0
	for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		switch {
		case ln == "":
			// blank separator line
		case strings.HasPrefix(ln, "event:"):
			eventLines++
		case strings.HasPrefix(ln, "id:"), strings.HasPrefix(ln, "data:"):
			// framed field
		default:
			t.Fatalf("unframed line leaked onto the wire: %q\nfull:\n%s", ln, out)
		}
	}
	if eventLines != 1 {
		t.Fatalf("want exactly one event: framing line, got %d:\n%s", eventLines, out)
	}
}
