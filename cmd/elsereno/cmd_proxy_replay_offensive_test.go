//go:build offensive

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"local/elsereno/offensive/replay"
)

// TestProxyReplay_RendersHeaderAndChunks drives the replay verb
// against a capture written by replay.Recorder. Asserts the
// header preamble + at least one chunk line round-trips through
// the formatter.
func TestProxyReplay_RendersHeaderAndChunks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.ndjson")
	rec, err := replay.Open(path, "modbus", "10.0.0.1:502")
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	// Write one client→upstream chunk via the recording wrapper
	// to produce a realistic file.
	cw := rec.WrapClient(&blackHole{})
	if _, err := cw.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x10, 0xBE, 0xEF}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cmd := newProxyReplayCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := out.String()
	want := []string{
		"# capture " + path,
		"# protocol  modbus",
		"# target    10.0.0.1:502",
		"c→u",
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("output missing %q\n--- output ---\n%s", w, got)
		}
	}
}

// TestProxyReplay_DirFilter — `--dir client` skips upstream
// chunks. We can't easily get bidirectional chunks without
// running the full proxy, so this test asserts the parser:
// the formatter is symmetrical, so testing one direction is
// enough.
func TestProxyReplay_DirFilter(t *testing.T) {
	cases := []struct {
		flag   string
		client bool
		upstrm bool
	}{
		{"client", true, false},
		{"c", true, false},
		{"upstream", false, true},
		{"u", false, true},
		{"both", true, true},
		{"", true, true},
		{"garbage", true, true},
	}
	for _, c := range cases {
		gotC, gotU := parseDirFilter(c.flag)
		if gotC != c.client || gotU != c.upstrm {
			t.Errorf("parseDirFilter(%q) = (%v, %v), want (%v, %v)",
				c.flag, gotC, gotU, c.client, c.upstrm)
		}
	}
}

// TestProxyReplay_FormatChunkArrows pins the directional arrow.
// Operators rely on c→u / u→c being unambiguous in scrollback.
func TestProxyReplay_FormatChunkArrows(t *testing.T) {
	c := replay.ChunkEvent{Dir: replay.DirClientToUpstream, Len: 1, Hex: "ab"}
	if !strings.Contains(formatChunk(c, 0), "c→u") {
		t.Errorf("c→u missing: %q", formatChunk(c, 0))
	}
	u := replay.ChunkEvent{Dir: replay.DirUpstreamToClient, Len: 1, Hex: "ab"}
	if !strings.Contains(formatChunk(u, 0), "u→c") {
		t.Errorf("u→c missing: %q", formatChunk(u, 0))
	}
}

// TestProxyReplay_HexLimitTruncates pins the hex-preview cap.
// Default 32 bytes = 64 hex chars + ellipsis when the chunk is
// longer.
func TestProxyReplay_HexLimitTruncates(t *testing.T) {
	long := strings.Repeat("ab", 100) // 200 hex chars = 100 bytes
	c := replay.ChunkEvent{Dir: replay.DirClientToUpstream, Len: 100, Hex: long}
	got := formatChunk(c, 32)
	// 32 bytes = 64 hex chars; ellipsis appended.
	if !strings.HasSuffix(got, "…") {
		t.Errorf("expected ellipsis, got %q", got)
	}
	if strings.Count(got, "ab") > 33 {
		t.Errorf("hex not truncated: %q", got)
	}
	// hexLimit=0 leaves the hex untouched.
	got = formatChunk(c, 0)
	if !strings.HasSuffix(got, long) {
		t.Errorf("hexLimit=0 should not truncate: %q", got)
	}
}

// blackHole satisfies io.ReadWriter for the recorder fixture
// when we only care about Write side.
type blackHole struct{}

func (blackHole) Read(_ []byte) (int, error)  { return 0, nil }
func (blackHole) Write(p []byte) (int, error) { return len(p), nil }

// _ keep the cobra import if any future helper drops it.
var _ = cobra.Command{}
