//go:build offensive

package gesrtp_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/gesrtp/wire"
	"local/elsereno/offensive/confirm"
	gewrite "local/elsereno/offensive/write/gesrtp"
)

type fakeDeriver struct{ key []byte }

func (f *fakeDeriver) Derive(_ string, out []byte) error { copy(out, f.key); return nil }

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

const (
	testDeriverKey = "test-key-32-byte-long--------"
	testTarget     = "gesrtp.test:18245"
)

func mintToken(t *testing.T, allowed []gewrite.AllowedService) string {
	t.Helper()
	mut := gewrite.SessionMutation(testTarget, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, allowed []gewrite.AllowedService) *gewrite.WriteGatedHandler {
	t.Helper()
	h := &gewrite.WriteGatedHandler{
		Target:  testTarget,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: testTarget,
			ConfirmToken:  mintToken(t, allowed),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

type mailboxRecorder struct {
	mu   sync.Mutex
	data [][]byte
}

func (r *mailboxRecorder) run(conn net.Conn) {
	for {
		mb, err := wire.ReadMailbox(conn)
		if len(mb) > 0 {
			r.mu.Lock()
			r.data = append(r.data, mb)
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (r *mailboxRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.data)
}

func driveSession(t *testing.T, allowed []gewrite.AllowedService) (net.Conn, *mailboxRecorder, <-chan error) {
	t.Helper()
	h := newHandler(t, allowed)
	clientIn, handlerClientSide := net.Pipe()
	handlerUpstreamSide, upstreamSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientIn.Close()
		_ = handlerClientSide.Close()
		_ = handlerUpstreamSide.Close()
		_ = upstreamSide.Close()
	})
	rec := &mailboxRecorder{}
	go rec.run(upstreamSide)
	done := make(chan error, 1)
	go func() { done <- h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientIn, rec, done
}

// buildMailbox crafts a 56-byte SHORT (or EXTENDED) client mailbox
// with the given service code.
func buildMailbox(svc byte, extended bool) []byte {
	m := make([]byte, wire.MailboxLen)
	m[0] = 0x02 // pkt type REQ
	if extended {
		m[31] = 0x80
		m[50] = svc
	} else {
		m[31] = 0xC0
		m[42] = svc
	}
	return m
}

func waitForOne(t *testing.T, r *mailboxRecorder) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if r.count() >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("recorder saw 0 mailboxes; wanted >= 1")
}

func TestReadServicePasses(t *testing.T) {
	client, rec, _ := driveSession(t, nil) // empty allowlist
	if _, err := client.Write(buildMailbox(byte(wire.SvcReadSysMem), false)); err != nil {
		t.Fatal(err)
	}
	waitForOne(t, rec)
}

func TestExtendedReadServicePasses(t *testing.T) {
	// The EXTENDED mailbox form carries the service code at offset 50
	// (vs 42 for SHORT); a read must classify + pass identically.
	client, rec, _ := driveSession(t, nil)
	if _, err := client.Write(buildMailbox(byte(wire.SvcReadSysMem), true)); err != nil {
		t.Fatal(err)
	}
	waitForOne(t, rec)
}

func TestAllowedWritePasses(t *testing.T) {
	allow := []gewrite.AllowedService{{Code: byte(wire.SvcWriteSysMem)}}
	client, rec, _ := driveSession(t, allow)
	if _, err := client.Write(buildMailbox(byte(wire.SvcWriteSysMem), false)); err != nil {
		t.Fatal(err)
	}
	waitForOne(t, rec)
}

func TestNonAllowedWriteRefusedClosesSession(t *testing.T) {
	client, rec, done := driveSession(t, nil) // empty allowlist
	// SET_PLC_RUN (0x23) is a control op, not allowlisted -> refuse.
	if _, err := client.Write(buildMailbox(byte(wire.SvcSetPLCRun), false)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, gewrite.ErrRefused) {
			t.Fatalf("Handle returned %v, want ErrRefused", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Handle did not return after a refused mailbox")
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("a refused write leaked %d mailbox(es) upstream", n)
	}
}

func TestChangePrivRefused(t *testing.T) {
	// 0x21: the nmap-vs-dissector conflict. The gate must refuse it
	// (it is not in the read set), never forward.
	client, rec, done := driveSession(t, nil)
	if _, err := client.Write(buildMailbox(byte(wire.SvcChangePriv), false)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, gewrite.ErrRefused) {
			t.Fatalf("Handle returned %v, want ErrRefused", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Handle did not return")
	}
	if rec.count() != 0 {
		t.Fatal("CHANGE_PRIV leaked upstream")
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &gewrite.WriteGatedHandler{Target: testTarget}
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close(); _ = u1.Close(); _ = u2.Close() })
	if err := h.Handle(context.Background(), c2, u1); !errors.Is(err, gewrite.ErrSessionNotAuthorised) {
		t.Fatalf("Handle without Authorise = %v, want ErrSessionNotAuthorised", err)
	}
}
