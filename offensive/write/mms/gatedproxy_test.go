//go:build offensive

package mms_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	mmswrite "local/elsereno/offensive/write/mms"
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

func mintToken(t *testing.T, target string, allowed []mmswrite.AllowedIntent) string {
	t.Helper()
	m := mmswrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(m, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatalf("ExpectedToken: %v", err)
	}
	return tok
}

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []mmswrite.AllowedIntent{{Description: "breaker test seq"}, {Description: "setpoint update"}}
	b := []mmswrite.AllowedIntent{{Description: "setpoint update"}, {Description: "breaker test seq"}}
	if mmswrite.AllowlistHash("relay:102", a) != mmswrite.AllowlistHash("relay:102", b) {
		t.Error("hash should be insensitive to input order")
	}
}

func TestAllowlistHash_CaseFolded(t *testing.T) {
	a := []mmswrite.AllowedIntent{{Description: "Reset"}}
	b := []mmswrite.AllowedIntent{{Description: "reset"}}
	if mmswrite.AllowlistHash("relay:102", a) != mmswrite.AllowlistHash("relay:102", b) {
		t.Error("hash should fold case")
	}
}

func TestAllowlistHash_TargetSensitive(t *testing.T) {
	intents := []mmswrite.AllowedIntent{{Description: "reset"}}
	if mmswrite.AllowlistHash("a:1962", intents) == mmswrite.AllowlistHash("b:1962", intents) {
		t.Error("hash should vary by target")
	}
}

func TestAuthorise_HappyPath(t *testing.T) {
	target := "relay.subst.lab:102"
	allowed := []mmswrite.AllowedIntent{{Description: "breaker control test sequence"}}
	h := &mmswrite.WriteGatedHandler{
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
	target := "relay:102"
	h := &mmswrite.WriteGatedHandler{
		Target:         target,
		Allowed:        []mmswrite.AllowedIntent{}, // empty
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
	target := "relay:102"
	allowed := []mmswrite.AllowedIntent{{Description: "reset"}}
	h := &mmswrite.WriteGatedHandler{
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
	h := &mmswrite.WriteGatedHandler{Target: "relay:102"}
	err := h.Handle(context.Background(), &ioPair{}, &ioPair{})
	if !errors.Is(err, mmswrite.ErrSessionNotAuthorised) {
		t.Fatalf("err = %v, want ErrSessionNotAuthorised", err)
	}
}

type ioPair struct{}

func (*ioPair) Read(_ []byte) (int, error)  { return 0, errors.New("not used in this test") }
func (*ioPair) Write(b []byte) (int, error) { return len(b), nil }

func TestHandle_RelaysBytesAfterAuthorise(t *testing.T) {
	target := "relay:102"
	allowed := []mmswrite.AllowedIntent{{Description: "test relay"}}
	h := &mmswrite.WriteGatedHandler{
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
	h := &mmswrite.WriteGatedHandler{
		Target:  "relay:102",
		Allowed: []mmswrite.AllowedIntent{{Description: "x"}},
	}
	if d := h.Description(); !strings.Contains(d, "session-level") {
		t.Errorf("Description should mention session-level scope: %q", d)
	}
}
