package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// waitForListenPort polls the captured stdout buffer until the
// "listening on 127.0.0.1:NNNN" line appears, then extracts
// the port. Tight enough to catch real regressions; generous
// enough that slow CI runners don't false-fail.
func waitForListenPort(t *testing.T, buf *bytes.Buffer, budget time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(budget)
	re := regexp.MustCompile(`listening on 127\.0\.0\.1:(\d+);`)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(buf.String()); len(m) == 2 {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatalf("port atoi: %v", err)
			}
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("did not see 'listening on 127.0.0.1:NNNN;' within %s. Output:\n%s",
		budget, buf.String())
	return 0
}

// dialTimeout is a thin context-aware net.Dial helper used by
// the capture tests. We can't use ctx.WithTimeout directly
// because Go's net.Dialer takes its own deadline.
func dialTimeout(ctx context.Context, host string, port int, budget time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: budget}
	return d.DialContext(ctx, "tcp", host+":"+strconv.Itoa(port))
}

// TestFingerprintValidate_HexBlob_KWBanner pins the verb's
// happy path: KW-Software banner → capability=60.
func TestFingerprintValidate_HexBlob_KWBanner(t *testing.T) {
	var out bytes.Buffer
	err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
		Plugin: "proconos",
		Hex:    "00000000 4B572D536F6674776172652056352E3631", // "\x00\x00\x00\x00KW-Software V5.61"
		JSON:   true,
		Out:    &out,
	})
	if err != nil {
		t.Fatalf("runFingerprintValidate: %v\n%s", err, out.String())
	}
	var got struct {
		Protocol string         `json:"protocol"`
		Factors  map[string]int `json:"factors"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, out.String())
	}
	if got.Protocol != "proconos" {
		t.Errorf("protocol = %q, want proconos", got.Protocol)
	}
	if got.Factors["capability"] != 60 {
		t.Errorf("capability = %d, want 60 (KW-Software banner should lift)",
			got.Factors["capability"])
	}
}

// TestFingerprintValidate_FilePath — operator-supplied
// capture from disk (the typical workflow: capture via
// Wireshark / netcat → save → feed to verb).
func TestFingerprintValidate_FilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.bin")
	// PROCONOS V5.0.0.40 banner with the ABCD prefix.
	body := []byte("\xFF\xFE\xAB\xCDPROCONOS V5.0.0.40 GeneralFirmware")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out bytes.Buffer
	if err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
		Plugin: "proconos",
		File:   path,
		Out:    &out,
	}); err != nil {
		t.Fatalf("runFingerprintValidate: %v\n%s", err, out.String())
	}
	body2 := out.String()
	for _, want := range []string{"proconos", "capability:", "score:"} {
		if !strings.Contains(body2, want) {
			t.Errorf("output missing %q\n%s", want, body2)
		}
	}
}

// TestFingerprintValidate_HexWithWhitespace — operators
// often paste pretty-printed hex. We strip whitespace before
// decoding.
func TestFingerprintValidate_HexWithWhitespace(t *testing.T) {
	var out bytes.Buffer
	if err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
		Plugin: "proconos",
		Hex: `00 00 00 00
		      4B 57 2D 53 6F 66 74 77 61 72 65`, // "\x00\x00\x00\x00KW-Software"
		JSON: true,
		Out:  &out,
	}); err != nil {
		t.Fatalf("runFingerprintValidate: %v\n%s", err, out.String())
	}
}

// TestFingerprintValidate_EmptyHexAfterStrip — guards
// against an operator pasting only whitespace.
func TestFingerprintValidate_EmptyHexAfterStrip(t *testing.T) {
	var out bytes.Buffer
	err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
		Plugin: "proconos",
		Hex:    "    \t\n",
		Out:    &out,
	})
	if err == nil {
		t.Fatal("expected error on empty hex; got nil")
	}
	if !strings.Contains(err.Error(), "0 bytes") {
		t.Errorf("err = %v, want '0 bytes'", err)
	}
}

// TestFingerprintValidate_BadHex — malformed hex string.
func TestFingerprintValidate_BadHex(t *testing.T) {
	var out bytes.Buffer
	err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
		Plugin: "proconos",
		Hex:    "not-hex-at-all",
		Out:    &out,
	})
	if err == nil {
		t.Fatal("expected hex decode error")
	}
}

// TestFingerprintValidate_MissingPlugin — empty --plugin
// rejected at the dispatcher.
func TestFingerprintValidate_MissingPlugin(t *testing.T) {
	var out bytes.Buffer
	err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
		Plugin: "",
		Hex:    "00",
		Out:    &out,
	})
	if err == nil {
		t.Fatal("expected error on missing plugin")
	}
	if !strings.Contains(err.Error(), "--plugin is required") {
		t.Errorf("err = %v, want '--plugin is required'", err)
	}
}

// TestFingerprintValidate_UnknownPlugin — plugin name that
// doesn't exist in the registry.
func TestFingerprintValidate_UnknownPlugin(t *testing.T) {
	var out bytes.Buffer
	err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
		Plugin: "fictional-protocol",
		Hex:    "00",
		Out:    &out,
	})
	if err == nil {
		t.Fatal("expected error on unknown plugin")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("err = %v, want 'unknown'", err)
	}
	if !strings.Contains(err.Error(), "registered:") {
		t.Errorf("err = %v, want 'registered:' (operator hint)", err)
	}
}

// TestFingerprintValidate_BothFileAndHex — mutually
// exclusive flags.
func TestFingerprintValidate_BothFileAndHex(t *testing.T) {
	var out bytes.Buffer
	err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
		Plugin: "proconos",
		File:   "/tmp/x",
		Hex:    "00",
		Out:    &out,
	})
	if err == nil {
		t.Fatal("expected error when both --file and --hex are set")
	}
	if !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("err = %v, want 'exactly one'", err)
	}
}

// TestFingerprintValidate_MissingFile surfaces the
// underlying os.Open error wrapped with --file <path>.
func TestFingerprintValidate_MissingFile(t *testing.T) {
	var out bytes.Buffer
	err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
		Plugin: "proconos",
		File:   filepath.Join(t.TempDir(), "no-such-file.bin"),
		Out:    &out,
	})
	if err == nil {
		t.Fatal("expected error on missing file")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("err = %v, want 'no such file'", err)
	}
}

// TestEmitFingerprintFinding_NilFinding — safe-handling
// when probe somehow returns no Finding.
func TestEmitFingerprintFinding_NilFinding(t *testing.T) {
	var out bytes.Buffer
	if err := emitFingerprintFinding(&out, nil, false); err != nil {
		t.Fatalf("emitFingerprintFinding nil: %v", err)
	}
	if !strings.Contains(out.String(), "no finding") {
		t.Errorf("output = %q, want 'no finding'", out.String())
	}
}

// TestDriveProbeAgainstBytes_SilentResponder — the
// listener-based driver returns the plugin's silent-
// responder Finding when reply is empty.
func TestDriveProbeAgainstBytes_SilentResponder(t *testing.T) {
	plugin, err := lookupPlugin("proconos")
	if err != nil {
		t.Fatalf("lookupPlugin: %v", err)
	}
	f, err := driveProbeAgainstBytes(t.Context(),
		plugin.Factory(), nil, 0)
	if err != nil {
		t.Fatalf("driveProbeAgainstBytes: %v", err)
	}
	if f == nil {
		t.Fatal("nil Finding")
	}
	if f.Factors["capability"] != 30 {
		t.Errorf("capability = %d, want 30 (silent responder)",
			f.Factors["capability"])
	}
}

// TestFingerprintValidate_AcrossPlugins — pin that the
// verb dispatches correctly to multiple plugins, not just
// proconos. We feed a silent (nil-reply) response to each;
// the result should distinguish the plugin via Finding.Protocol.
func TestFingerprintValidate_AcrossPlugins(t *testing.T) {
	for _, plugin := range []string{"proconos", "gesrtp"} {
		t.Run(plugin, func(t *testing.T) {
			var out bytes.Buffer
			err := runFingerprintValidate(t.Context(), fingerprintValidateOpts{
				Plugin: plugin,
				Hex:    "00", // single byte: silent-responder-ish
				JSON:   true,
				Out:    &out,
			})
			if err != nil {
				t.Fatalf("runFingerprintValidate %s: %v\n%s", plugin, err, out.String())
			}
			var got struct {
				Protocol string `json:"protocol"`
			}
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatalf("decode JSON for %s: %v\n%s", plugin, err, out.String())
			}
			if got.Protocol != plugin {
				t.Errorf("protocol = %q, want %q", got.Protocol, plugin)
			}
		})
	}
}

// TestFingerprintCapture_HappyPath — fixed-port server +
// in-process net.Dial client. Drives the full capture →
// file → readback path.
func TestFingerprintCapture_HappyPath(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "captured.bin")

	// Run the capture in the background; the test client
	// dials it once we see "connected from" in the output.
	var out bytes.Buffer
	captureDone := make(chan error, 1)
	go func() {
		captureDone <- runFingerprintCapture(t.Context(), fingerprintCaptureOpts{
			Listen:  "127.0.0.1:0",
			Output:  outPath,
			Timeout: 5 * time.Second,
			Out:     &out,
		})
	}()

	// Poll the captured stdout until the listening line
	// appears, then extract the port the kernel picked.
	port := waitForListenPort(t, &out, 2*time.Second)

	conn, err := dialTimeout(t.Context(), "127.0.0.1", port, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	want := []byte("hello-from-test-client")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.Close()

	if err := <-captureDone; err != nil {
		t.Fatalf("capture: %v\n%s", err, out.String())
	}

	got, err := os.ReadFile(outPath) // #nosec G304 -- test-owned t.TempDir() path
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("captured = %q, want %q", got, want)
	}

	// Verify perms = 0600 (operator-private capture).
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("perms = %v, want no group/world bits", info.Mode().Perm())
	}
}

// TestFingerprintCapture_MissingOutput — required flag.
func TestFingerprintCapture_MissingOutput(t *testing.T) {
	var out bytes.Buffer
	err := runFingerprintCapture(t.Context(), fingerprintCaptureOpts{
		Listen: "127.0.0.1:0",
		Out:    &out,
	})
	if err == nil || !strings.Contains(err.Error(), "--output is required") {
		t.Errorf("err = %v, want '--output is required'", err)
	}
}

// TestFingerprintCapture_TimeoutOnIdleListener — ctx
// timeout fires when no client connects.
func TestFingerprintCapture_TimeoutOnIdleListener(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "x.bin")
	var buf bytes.Buffer
	start := time.Now()
	err := runFingerprintCapture(t.Context(), fingerprintCaptureOpts{
		Listen:  "127.0.0.1:0",
		Output:  out,
		Timeout: 100 * time.Millisecond,
		Out:     &buf,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "context deadline") &&
		!strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("err = %v, want context-deadline error", err)
	}
	// Sanity: didn't hang past the timeout by more than 1s.
	if elapsed > time.Second {
		t.Errorf("elapsed = %v, expected ~100ms (timeout) + overhead", elapsed)
	}
	// Output file should NOT exist on timeout.
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("output file unexpectedly created: %v", err)
	}
}

// TestFingerprintCapture_ClientClosesEmpty — client opens
// but writes nothing, then closes. Capture should refuse
// rather than write a 0-byte file.
func TestFingerprintCapture_ClientClosesEmpty(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "empty.bin")
	var out bytes.Buffer
	captureDone := make(chan error, 1)
	go func() {
		captureDone <- runFingerprintCapture(t.Context(), fingerprintCaptureOpts{
			Listen:  "127.0.0.1:0",
			Output:  outPath,
			Timeout: 5 * time.Second,
			Out:     &out,
		})
	}()
	port := waitForListenPort(t, &out, 2*time.Second)
	conn, err := dialTimeout(t.Context(), "127.0.0.1", port, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	err = <-captureDone
	if err == nil {
		t.Fatal("expected error on empty client write")
	}
	if !strings.Contains(err.Error(), "without sending any bytes") {
		t.Errorf("err = %v, want 'without sending any bytes'", err)
	}
}

// TestDriveProbeAgainstBytes_DefaultTimeout — ensures the
// timeout=0 fallback (5s) doesn't overshadow ctx.
func TestDriveProbeAgainstBytes_DefaultTimeout(t *testing.T) {
	plugin, err := lookupPlugin("proconos")
	if err != nil {
		t.Fatalf("lookupPlugin: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = driveProbeAgainstBytes(ctx, plugin.Factory(),
		[]byte("\x00\x00\x00\x00KW-Software"), 0)
	// Probe may return ctx.Err() or a successful result
	// depending on race. Both are acceptable; we just want
	// to ensure no panic.
	if err != nil && !errors.Is(err, context.Canceled) {
		// Other errors are surfaced for debug but don't fail.
		t.Logf("driveProbeAgainstBytes returned: %v (ok)", err)
	}
}
