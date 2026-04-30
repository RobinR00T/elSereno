//go:build offensive

package replay_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"local/elsereno/offensive/replay"
)

// fakeRW is an io.ReadWriter wrapping a bytes.Buffer (writes)
// and a separate buffer (reads). Used to drive Wrap*-based
// recorder tests without a real network.
type fakeRW struct {
	in  *bytes.Buffer // bytes the test side wants the wrapper to "Read" from
	out *bytes.Buffer // bytes the wrapper "Wrote" — test inspects after
}

func (f *fakeRW) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *fakeRW) Write(p []byte) (int, error) { return f.out.Write(p) }

func TestOpen_RejectsEmptyArgs(t *testing.T) {
	if _, err := replay.Open("", "sip", "h:p"); err == nil {
		t.Error("empty path should error")
	}
	if _, err := replay.Open("/tmp/x.ndjson", "", "h:p"); err == nil {
		t.Error("empty protocol should error")
	}
	if _, err := replay.Open("/tmp/x.ndjson", "sip", ""); err == nil {
		t.Error("empty target should error")
	}
}

func TestOpen_WritesHeaderAtMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.ndjson")
	rec, err := replay.Open(path, "sip", "pbx.example:5060")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("perms %v, want no group/world bits", info.Mode().Perm())
	}

	hdr, err := replay.SeekHeader(path)
	if err != nil {
		t.Fatalf("SeekHeader: %v", err)
	}
	if hdr.Schema != replay.Schema {
		t.Errorf("schema = %q, want %q", hdr.Schema, replay.Schema)
	}
	if hdr.Protocol != "sip" {
		t.Errorf("protocol = %q, want sip", hdr.Protocol)
	}
	if hdr.Target != "pbx.example:5060" {
		t.Errorf("target = %q", hdr.Target)
	}
	if hdr.Dir != replay.DirHeader {
		t.Errorf("dir = %q, want %q", hdr.Dir, replay.DirHeader)
	}
}

func TestWrap_RecordsReadsAndWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.ndjson")
	rec, err := replay.Open(path, "sip", "pbx.example:5060")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	in := bytes.NewBufferString("hello-from-upstream")
	out := &bytes.Buffer{}
	rw := &fakeRW{in: in, out: out}
	wrapped := rec.Wrap(rw)

	// Read drains in → captured as DirUpstreamToClient.
	got := make([]byte, 32)
	n, _ := wrapped.Read(got)
	if string(got[:n]) != "hello-from-upstream" {
		t.Errorf("read passthrough: got %q", string(got[:n]))
	}
	// Write puts bytes in out → captured as DirClientToUpstream.
	if _, err := wrapped.Write([]byte("hello-from-client")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if out.String() != "hello-from-client" {
		t.Errorf("write passthrough: got %q", out.String())
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Replay should yield: header + 1 read event + 1 write event.
	var got2 []replay.ChunkEvent
	err = replay.Replay(context.Background(), path, func(ev replay.ChunkEvent) error {
		got2 = append(got2, ev)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(got2) != 3 {
		t.Fatalf("Replay yielded %d events, want 3 (header + read + write)", len(got2))
	}
	if got2[0].Dir != replay.DirHeader {
		t.Errorf("event[0] dir = %q, want header", got2[0].Dir)
	}
	if got2[1].Dir != replay.DirUpstreamToClient {
		t.Errorf("event[1] dir = %q, want upstream_to_client", got2[1].Dir)
	}
	if got2[2].Dir != replay.DirClientToUpstream {
		t.Errorf("event[2] dir = %q, want client_to_upstream", got2[2].Dir)
	}

	// Decode the read event's bytes — should match what we put in.
	b, err := got2[1].DecodeBytes()
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if string(b) != "hello-from-upstream" {
		t.Errorf("decoded read = %q", string(b))
	}
}

func TestWrapClient_DirectionTags(t *testing.T) {
	// WrapClient: reads are operator-tool → proxy bytes (so
	// readDir == DirClientToUpstream). Writes are proxy →
	// operator-tool bytes (writeDir == DirUpstreamToClient).
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.ndjson")
	rec, _ := replay.Open(path, "modbus", "plc:502")
	defer func() { _ = rec.Close() }()

	rw := &fakeRW{in: bytes.NewBufferString("client-bytes"), out: &bytes.Buffer{}}
	wrapped := rec.WrapClient(rw)

	got := make([]byte, 32)
	if _, err := wrapped.Read(got); err != nil {
		t.Fatalf("read: %v", err)
	}
	_, _ = wrapped.Write([]byte("server-bytes"))
	_ = rec.Close()

	var events []replay.ChunkEvent
	_ = replay.Replay(context.Background(), path, func(ev replay.ChunkEvent) error {
		if ev.Dir != replay.DirHeader {
			events = append(events, ev)
		}
		return nil
	})
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	if events[0].Dir != replay.DirClientToUpstream {
		t.Errorf("WrapClient.Read should tag client_to_upstream, got %q", events[0].Dir)
	}
	if events[1].Dir != replay.DirUpstreamToClient {
		t.Errorf("WrapClient.Write should tag upstream_to_client, got %q", events[1].Dir)
	}
}

func TestReplay_RejectsBadSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.ndjson")
	if err := os.WriteFile(path, []byte(`{"schema":"wrong","dir":"header","started_at":"2026-01-01T00:00:00Z","protocol":"sip","target":"x"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	_, err := replay.SeekHeader(path)
	if err == nil {
		t.Fatal("expected schema error")
	}
}

func TestReplay_RespectsContextCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.ndjson")
	rec, _ := replay.Open(path, "sip", "h:p")
	rw := &fakeRW{in: bytes.NewBufferString("xxx"), out: &bytes.Buffer{}}
	w := rec.Wrap(rw)
	got := make([]byte, 32)
	_, _ = w.Read(got)
	_, _ = w.Write([]byte("yyy"))
	_ = rec.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before iteration
	err := replay.Replay(ctx, path, func(_ replay.ChunkEvent) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestRecorder_RoundTripWithRealNetPipe(t *testing.T) {
	// End-to-end-ish: wrap a real net.Pipe pair and verify the
	// recording captures both directions accurately.
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.ndjson")
	rec, err := replay.Open(path, "modbus", "plc.lab:502")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()

	wrapped := rec.WrapUpstream(a)
	go func() { _, _ = b.Write([]byte{0x00, 0x01, 0x02}) }()
	got := make([]byte, 3)
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	go func() { _, _ = b.Read(make([]byte, 16)) }()
	if _, err := wrapped.Write([]byte{0xFF, 0xFE}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = rec.Close()

	hdr, err := replay.SeekHeader(path)
	if err != nil {
		t.Fatalf("SeekHeader: %v", err)
	}
	if hdr.Protocol != "modbus" || hdr.Target != "plc.lab:502" {
		t.Errorf("header mismatch: %+v", hdr)
	}
}
