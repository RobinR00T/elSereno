//go:build offensive

package main

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"local/elsereno/offensive/replay"
	bacwrite "local/elsereno/offensive/write/bacnet"
	cwmpwrite "local/elsereno/offensive/write/cwmp"
	enipwrite "local/elsereno/offensive/write/enip"
	iaxwrite "local/elsereno/offensive/write/iax2"
	mmswrite "local/elsereno/offensive/write/mms"
	modwrite "local/elsereno/offensive/write/modbus"
	opwrite "local/elsereno/offensive/write/opcua"
	pbxwrite "local/elsereno/offensive/write/pbxhttp"
	pcworxwrite "local/elsereno/offensive/write/pcworx"
	s7write "local/elsereno/offensive/write/s7"
	sipwrite "local/elsereno/offensive/write/sip"
)

// TestAttachRecorder_AllSupportedHandlers — pin that every
// gated-proxy handler type that ships a Recorder field is
// covered by attachRecorder. v1.30 chunk 1 wired the original
// 7; v1.35 chunk 1 added pcworx + mms + enip + s7. A new
// plugin that ships a Recorder field but doesn't get added
// to the type-switch will fail this test.
func TestAttachRecorder_AllSupportedHandlers(t *testing.T) {
	dir := t.TempDir()
	rec, err := replay.Open(filepath.Join(dir, "rec.ndjson"), "test", "x:1")
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	cases := []struct {
		name string
		h    gatedProxyHandler
	}{
		{"sip", &sipwrite.WriteGatedHandler{}},
		{"iax2", &iaxwrite.WriteGatedHandler{}},
		{"pbxhttp", &pbxwrite.WriteGatedHandler{}},
		{"modbus", &modwrite.WriteGatedHandler{}},
		{"opcua", &opwrite.WriteGatedHandler{}},
		{"bacnet", &bacwrite.WriteGatedHandler{}},
		{"cwmp", &cwmpwrite.WriteGatedHandler{}},
		{"pcworx", &pcworxwrite.WriteGatedHandler{}},
		{"mms", &mmswrite.WriteGatedHandler{}},
		{"enip", &enipwrite.WriteGatedHandler{}},
		{"s7", &s7write.WriteGatedHandler{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !attachRecorder(c.h, rec) {
				t.Fatalf("attachRecorder returned false for %T; expected true", c.h)
			}
		})
	}
}

// TestAttachRecorder_UnsupportedTypeReturnsFalse — the
// fall-through default branch returns false for any type
// that's not in the switch. We verify by passing a typed
// zero-value of a different shape (a pointer to a string).
func TestAttachRecorder_UnsupportedTypeReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	rec, err := replay.Open(filepath.Join(dir, "rec.ndjson"), "test", "x:1")
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	// stringHandler intentionally satisfies neither the
	// gatedProxyHandler interface nor any of the gated types
	// — but for the type-switch we just need a pointer-to-
	// something concrete. Using a stub gated-proxy type
	// would be cleaner; for now this is a structural smoke
	// test.
	var stub fakeHandler
	if attachRecorder(&stub, rec) {
		t.Errorf("attachRecorder returned true for unknown type; expected false")
	}
}

// fakeHandler implements gatedProxyHandler but is none of the
// concrete types attachRecorder knows. Used to verify the
// default-branch behaviour.
type fakeHandler struct{}

func (*fakeHandler) Authorise(_ context.Context) error                  { return nil }
func (*fakeHandler) Handle(_ context.Context, _, _ io.ReadWriter) error { return nil }
