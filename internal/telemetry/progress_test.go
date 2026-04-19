package telemetry_test

import (
	"bytes"
	"strings"
	"testing"

	"local/elsereno/internal/telemetry"
)

func TestProgressNonTTYEmitsLines(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	p := telemetry.NewProgress(&buf, 10)
	for i := 0; i < 10; i++ {
		p.Inc(1)
	}
	p.Done()
	out := buf.String()
	if !strings.Contains(out, "progress ") {
		t.Fatalf("expected 'progress ' in output, got %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("Done() should emit trailing newline; got %q", out[max(0, len(out)-40):])
	}
}

func TestProgressIndeterminate(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	p := telemetry.NewProgress(&buf, 0)
	p.Inc(42)
	p.Done()
	if !strings.Contains(buf.String(), "42 items") {
		t.Fatalf("indeterminate mode missing item count: %q", buf.String())
	}
}
