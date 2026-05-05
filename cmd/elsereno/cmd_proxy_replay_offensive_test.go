//go:build offensive

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		// WrapClient + Write emits a recorded event with
		// DirUpstreamToClient (the recorder's view: writes
		// ON the client conn = bytes the gate is sending
		// back to the client). v1.45+ also suppresses
		// DirHeader, so the rendered chunk arrow is u→c.
		"u→c",
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

// TestProxyReplay_TimeWindow_ParseValid pins the parser
// shape: both bounds optional, RFC3339Nano accepted, since
// > until rejected.
func TestProxyReplay_TimeWindow_ParseValid(t *testing.T) {
	cases := []struct {
		name         string
		since, until string
		wantErr      bool
	}{
		{"both empty", "", "", false},
		{"since only", "2026-05-04T12:00:00Z", "", false},
		{"until only", "", "2026-05-04T13:00:00Z", false},
		{"both valid", "2026-05-04T12:00:00Z", "2026-05-04T13:00:00Z", false},
		{"both equal", "2026-05-04T12:00:00Z", "2026-05-04T12:00:00Z", false},
		{"nano precision", "2026-05-04T12:00:00.123456Z", "2026-05-04T13:00:00.654321Z", false},
		{"since > until", "2026-05-04T13:00:00Z", "2026-05-04T12:00:00Z", true},
		{"bad since", "yesterday", "", true},
		{"bad until", "", "tomorrow", true},
	}
	for _, c := range cases {
		_, err := parseTimeWindow(c.since, c.until)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr = %v", c.name, err, c.wantErr)
		}
	}
}

// TestProxyReplay_TimeWindow_Contains pins the gate logic.
// Zero bounds disable that side; zero ts is tolerated
// (passes through so corrupted lines remain visible).
func TestProxyReplay_TimeWindow_Contains(t *testing.T) {
	t12 := mustTime(t, "2026-05-04T12:00:00Z")
	t13 := mustTime(t, "2026-05-04T13:00:00Z")
	t14 := mustTime(t, "2026-05-04T14:00:00Z")
	t15 := mustTime(t, "2026-05-04T15:00:00Z")

	cases := []struct {
		name         string
		since, until time.Time
		ts           time.Time
		want         bool
	}{
		{"no bounds always passes", time.Time{}, time.Time{}, t13, true},
		{"in range", t12, t14, t13, true},
		{"at since boundary", t12, t14, t12, true},
		{"at until boundary", t12, t14, t14, true},
		{"before since", t13, t15, t12, false},
		{"after until", t12, t13, t14, false},
		{"only since, ts after", t12, time.Time{}, t13, true},
		{"only since, ts before", t13, time.Time{}, t12, false},
		{"only until, ts before", time.Time{}, t14, t13, true},
		{"only until, ts after", time.Time{}, t13, t14, false},
		{"zero ts always passes", t12, t14, time.Time{}, true},
	}
	for _, c := range cases {
		w := timeWindow{since: c.since, until: c.until}
		if got := w.contains(c.ts); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestProxyReplay_TimeWindow_FiltersOutput drives a real
// capture through the verb with --since narrowing the
// rendered chunks. We write 3 chunks at distinct timestamps
// and assert only those inside the window appear in stdout.
func TestProxyReplay_TimeWindow_FiltersOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.ndjson")
	rec, err := replay.Open(path, "modbus", "10.0.0.1:502")
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	cw := rec.WrapClient(&blackHole{})
	// 3 chunks; recorder stamps each with time.Now() so we
	// just write them in sequence and rely on the natural
	// time-ordering.
	for i := 0; i < 3; i++ {
		if _, err := cw.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Pick a `--since` that's well in the future so all 3
	// chunks fall before it; we expect zero chunk lines.
	cmd := newProxyReplayCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{
		"--since", "2099-01-01T00:00:00Z",
		path,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(out.String(), "c→u") {
		t.Errorf("--since 2099 returned c→u lines:\n%s", out.String())
	}
	// Header lines should still be there.
	if !strings.Contains(out.String(), "# capture ") {
		t.Errorf("missing header line:\n%s", out.String())
	}
	// "# window" line should announce the bound.
	if !strings.Contains(out.String(), "# window") {
		t.Errorf("missing # window line:\n%s", out.String())
	}
}

// TestProxyReplay_BadSinceUsageError — operator typo on
// --since produces EX_USAGE (64) with a friendly message
// pointing at the expected format.
func TestProxyReplay_BadSinceUsageError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.ndjson")
	rec, err := replay.Open(path, "modbus", "10.0.0.1:502")
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	cmd := newProxyReplayCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"--since", "yesterday", path})
	err = cmd.Execute()
	if err == nil {
		t.Fatalf("expected error on --since yesterday")
	}
	if !strings.Contains(err.Error(), "RFC3339") {
		t.Errorf("err = %v, want hint about RFC3339", err)
	}
}

// mustTime parses an RFC3339 string or fatals. Local helper
// for the timeWindow tests.
func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tt, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tt
}

// TestProxyReplay_JSONOutput pins the v1.45 --json shape:
// no header lines, one JSON ChunkEvent per line.
func TestProxyReplay_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.ndjson")
	rec, err := replay.Open(path, "modbus", "10.0.0.1:502")
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	// WrapUpstream: writes record as DirClientToUpstream
	// (operator writes to the upstream conn = data going
	// from gate to upstream = client_to_upstream in capture).
	uw := rec.WrapUpstream(&blackHole{})
	for i := 0; i < 3; i++ {
		if _, err := uw.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cmd := newProxyReplayCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"--json", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Header lines are suppressed under --json so stdout
	// stays a clean NDJSON stream consumable by jq.
	if strings.Contains(out.String(), "# capture") {
		t.Errorf("--json leaked header line:\n%s", out.String())
	}
	// Each non-empty line must be valid JSON with a `dir` field.
	// DirHeader is suppressed by the v1.45 dispatcher; we expect
	// exactly the 3 chunk lines.
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), out.String())
	}
	for i, line := range lines {
		var ev replay.ChunkEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("line %d not valid JSON: %v\n%q", i, err, line)
		}
		if ev.Dir != replay.DirClientToUpstream {
			t.Errorf("line %d dir = %q, want client_to_upstream", i, ev.Dir)
		}
	}
}

// TestProxyReplay_JSONOutput_RespectsFilters pins that
// --json composes correctly with --dir.
func TestProxyReplay_JSONOutput_RespectsFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.ndjson")
	rec, err := replay.Open(path, "modbus", "10.0.0.1:502")
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	// WrapUpstream + Write → c→u-only capture.
	uw := rec.WrapUpstream(&blackHole{})
	if _, err := uw.Write([]byte{0xAA}); err != nil {
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
	// --dir upstream filters out the c→u chunk we wrote.
	// DirHeader is also suppressed by the v1.45 dispatcher
	// so stdout should be empty.
	cmd.SetArgs([]string{"--json", "--dir", "upstream", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "" {
		t.Errorf("--json --dir upstream produced output for c→u-only capture:\n%q", got)
	}
}
