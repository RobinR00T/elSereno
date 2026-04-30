//go:build offensive

package pcworx_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
	pcwrite "local/elsereno/offensive/write/pcworx"
)

const testDeriverKey = "test-key-32-byte-long--------"

type fakeDeriver struct{ key []byte }

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	copy(out, f.key)
	return nil
}

type fakeAuditor struct {
	mu     sync.Mutex
	events []confirm.AuditEvent
}

func (f *fakeAuditor) Record(_ context.Context, ev confirm.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func mintToken(t *testing.T, target string, allowed []pcwrite.AllowedIntent) string {
	t.Helper()
	m := pcwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(m, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatalf("ExpectedToken: %v", err)
	}
	return tok
}

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []pcwrite.AllowedIntent{{Description: "post-commission reset"}, {Description: "live config update"}}
	b := []pcwrite.AllowedIntent{{Description: "live config update"}, {Description: "post-commission reset"}}
	if pcwrite.AllowlistHash("ilc:1962", a) != pcwrite.AllowlistHash("ilc:1962", b) {
		t.Error("hash should be insensitive to input order")
	}
}

func TestAllowlistHash_CaseFolded(t *testing.T) {
	a := []pcwrite.AllowedIntent{{Description: "Reset"}}
	b := []pcwrite.AllowedIntent{{Description: "reset"}}
	if pcwrite.AllowlistHash("ilc:1962", a) != pcwrite.AllowlistHash("ilc:1962", b) {
		t.Error("hash should fold case")
	}
}

func TestAllowlistHash_TargetSensitive(t *testing.T) {
	intents := []pcwrite.AllowedIntent{{Description: "reset"}}
	if pcwrite.AllowlistHash("a:1962", intents) == pcwrite.AllowlistHash("b:1962", intents) {
		t.Error("hash should vary by target")
	}
}

func TestAuthorise_HappyPath(t *testing.T) {
	target := "ilc.lab.example:1962"
	allowed := []pcwrite.AllowedIntent{{Description: "post-commission factory reset"}}
	h := &pcwrite.WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, allowed),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	// Idempotent.
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("second Authorise: %v", err)
	}
}

func TestAuthorise_RejectsEmptyIntent(t *testing.T) {
	target := "ilc:1962"
	h := &pcwrite.WriteGatedHandler{
		Target:         target,
		Allowed:        []pcwrite.AllowedIntent{}, // empty
		Deriver:        &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:        &fakeAuditor{},
		SessionConfirm: confirm.Confirm{AcceptsWrites: true, ConfirmTarget: target, ConfirmToken: "anything"},
	}
	err := h.Authorise(context.Background())
	if err == nil {
		t.Fatal("expected Authorise to reject empty allowlist")
	}
	if !strings.Contains(err.Error(), "AllowedIntent") {
		t.Errorf("error should mention AllowedIntent: %v", err)
	}
}

func TestAuthorise_RejectsBadToken(t *testing.T) {
	target := "ilc:1962"
	allowed := []pcwrite.AllowedIntent{{Description: "reset"}}
	h := &pcwrite.WriteGatedHandler{
		Target:         target,
		Allowed:        allowed,
		Deriver:        &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:        &fakeAuditor{},
		SessionConfirm: confirm.Confirm{AcceptsWrites: true, ConfirmTarget: target, ConfirmToken: "wrong-token"},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("expected bad-token error")
	}
}

func TestHandle_UnauthorisedErrors(t *testing.T) {
	h := &pcwrite.WriteGatedHandler{Target: "ilc:1962"}
	err := h.Handle(context.Background(), &ioPair{}, &ioPair{})
	if !errors.Is(err, pcwrite.ErrSessionNotAuthorised) {
		t.Fatalf("err = %v, want ErrSessionNotAuthorised", err)
	}
}

type ioPair struct{}

func (*ioPair) Read(_ []byte) (int, error)  { return 0, errors.New("not used in this test") }
func (*ioPair) Write(b []byte) (int, error) { return len(b), nil }

func TestHandle_RelaysBytesAfterAuthorise(t *testing.T) {
	target := "ilc:1962"
	allowed := []pcwrite.AllowedIntent{{Description: "test relay"}}
	h := &pcwrite.WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, allowed),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise: %v", err)
	}

	clientPipe, handlerClient := net.Pipe()
	upstreamReader, handlerUpstream := net.Pipe()
	t.Cleanup(func() {
		_ = clientPipe.Close()
		_ = handlerClient.Close()
		_ = upstreamReader.Close()
		_ = handlerUpstream.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() { _ = h.Handle(ctx, handlerClient, handlerUpstream); close(done) }()

	// Write some bytes from the client; expect them on the upstream side.
	want := []byte{0x01, 0x01, 0x00, 0x1C, 'I', 'B', 'E', 'T', 'H', '0', '1', 0x00}
	go func() { _, _ = clientPipe.Write(want) }()
	got := make([]byte, len(want))
	_ = upstreamReader.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := upstreamReader.Read(got); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	for i, b := range want {
		if got[i] != b {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, got[i], b)
		}
	}
}

func TestDescription_NonEmpty(t *testing.T) {
	h := &pcwrite.WriteGatedHandler{
		Target:  "ilc:1962",
		Allowed: []pcwrite.AllowedIntent{{Description: "x"}},
	}
	if d := h.Description(); !strings.Contains(d, "session-level") {
		t.Errorf("Description should mention session-level scope: %q", d)
	}
}

// TestHandle_RecordsBytesWhenRecorderSet — v1.28 chunk 3
// proof-of-concept: setting the Recorder field on the gate
// captures every byte that crosses Handle into an NDJSON file.
// On nil Recorder the gate behaves identically to v1.27.
func TestHandle_RecordsBytesWhenRecorderSet(t *testing.T) {
	target := "ilc:1962"
	allowed := []pcwrite.AllowedIntent{{Description: "v1.28 chunk-3 record-replay POC"}}

	dir := t.TempDir()
	recPath := filepath.Join(dir, "session.ndjson")
	rec, err := replay.Open(recPath, "pcworx", target)
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	h := &pcwrite.WriteGatedHandler{
		Target:   target,
		Allowed:  allowed,
		Deriver:  &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:  &fakeAuditor{},
		Recorder: rec,
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, allowed),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise: %v", err)
	}

	clientPipe, handlerClient := net.Pipe()
	upstreamReader, handlerUpstream := net.Pipe()
	t.Cleanup(func() {
		_ = clientPipe.Close()
		_ = handlerClient.Close()
		_ = upstreamReader.Close()
		_ = handlerUpstream.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx, handlerClient, handlerUpstream) }()

	clientToUpstream := []byte{0x01, 0x01, 0x00, 0x1C, 'I', 'B', 'E', 'T', 'H', '0', '1', 0x00}
	go func() { _, _ = clientPipe.Write(clientToUpstream) }()
	got := make([]byte, len(clientToUpstream))
	_ = upstreamReader.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := upstreamReader.Read(got); err != nil {
		t.Fatalf("upstream read: %v", err)
	}

	// Close the recorder so the NDJSON file is finalised before
	// we replay it.
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify the file exists, has 0600 perms, and the recording
	// contains at least one ChunkEvent in the
	// client_to_upstream direction.
	info, err := os.Stat(recPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("recording perms = %v, want no group/world bits", info.Mode().Perm())
	}

	hdr, err := replay.SeekHeader(recPath)
	if err != nil {
		t.Fatalf("SeekHeader: %v", err)
	}
	if hdr.Protocol != "pcworx" {
		t.Errorf("recorded protocol = %q", hdr.Protocol)
	}

	var sawClientToUpstream bool
	_ = replay.Replay(context.Background(), recPath, func(ev replay.ChunkEvent) error {
		if ev.Dir == replay.DirClientToUpstream && ev.Len > 0 {
			sawClientToUpstream = true
		}
		return nil
	})
	if !sawClientToUpstream {
		t.Errorf("recording did not capture a client_to_upstream chunk")
	}
}
