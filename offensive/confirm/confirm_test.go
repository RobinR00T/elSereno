//go:build offensive

package confirm

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// stubDeriver is a KeyDeriver backed by a static master key so tests
// are fully deterministic. Real vault behaviour is exercised in
// internal/creds/vault_test.go.
type stubDeriver struct {
	master []byte
	fail   error
}

func newStubDeriver(master string) *stubDeriver {
	return &stubDeriver{master: []byte(master)}
}

func (s *stubDeriver) Derive(info string, out []byte) error {
	if s.fail != nil {
		return s.fail
	}
	r := hkdf.New(sha256.New, s.master, nil, []byte(info))
	_, err := io.ReadFull(r, out)
	return err
}

// captureAuditor records every event in order. Mismatches in the test
// reveal a wrapper that silently swallowed a denial.
type captureAuditor struct {
	events []AuditEvent
	fail   error
}

func (c *captureAuditor) Record(_ context.Context, ev AuditEvent) error {
	if c.fail != nil {
		return c.fail
	}
	c.events = append(c.events, ev)
	return nil
}

func baseMutation() Mutation {
	m := Mutation{
		Category:  CategoryWrite,
		Protocol:  "modbus",
		Operation: "write_single_register",
		Target:    "10.0.0.1:502",
	}
	m.PayloadHash = sha256.Sum256([]byte("addr=0x0001,value=0x1234"))
	return m
}

func TestAuthorize_HappyPath(t *testing.T) {
	d := newStubDeriver("master-key-bytes-for-test")
	a := &captureAuditor{}
	m := baseMutation()
	tok, err := ExpectedToken(m, d)
	if err != nil {
		t.Fatalf("ExpectedToken: %v", err)
	}
	c := Confirm{AcceptsWrites: true, ConfirmTarget: m.Target, ConfirmToken: tok}
	if err := Authorize(context.Background(), m, c, d, a); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if len(a.events) != 1 || a.events[0].EventType != "offensive_allowed" {
		t.Fatalf("expected one allowed event, got %+v", a.events)
	}
	if a.events[0].Target != m.Target || a.events[0].Operation != m.Operation {
		t.Fatalf("audit event fields mismatch: %+v", a.events[0])
	}
}

func TestAuthorize_MissingAcceptWrites(t *testing.T) {
	d := newStubDeriver("k")
	a := &captureAuditor{}
	m := baseMutation()
	c := Confirm{ConfirmTarget: m.Target, ConfirmToken: "ignored"}
	err := Authorize(context.Background(), m, c, d, a)
	if !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("want ErrNotAccepted, got %v", err)
	}
	if len(a.events) != 1 || a.events[0].EventType != "offensive_denied" {
		t.Fatalf("expected one denied event, got %+v", a.events)
	}
}

func TestAuthorize_TargetMismatch(t *testing.T) {
	d := newStubDeriver("k")
	a := &captureAuditor{}
	m := baseMutation()
	c := Confirm{AcceptsWrites: true, ConfirmTarget: "10.0.0.2:502", ConfirmToken: "ignored"}
	err := Authorize(context.Background(), m, c, d, a)
	if !errors.Is(err, ErrTargetMismatch) {
		t.Fatalf("want ErrTargetMismatch, got %v", err)
	}
	if a.events[0].Reason != ErrTargetMismatch.Error() {
		t.Fatalf("audit reason mismatch: %q", a.events[0].Reason)
	}
}

func TestAuthorize_BadToken(t *testing.T) {
	d := newStubDeriver("k")
	a := &captureAuditor{}
	m := baseMutation()
	c := Confirm{AcceptsWrites: true, ConfirmTarget: m.Target, ConfirmToken: "deadbeef"}
	err := Authorize(context.Background(), m, c, d, a)
	if !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("want ErrTokenMismatch, got %v", err)
	}
	if len(a.events) != 1 || a.events[0].EventType != "offensive_denied" {
		t.Fatalf("expected denied event, got %+v", a.events)
	}
}

func TestAuthorize_VaultLocked(t *testing.T) {
	d := newStubDeriver("k")
	d.fail = errors.New("locked")
	a := &captureAuditor{}
	m := baseMutation()
	c := Confirm{AcceptsWrites: true, ConfirmTarget: m.Target, ConfirmToken: "xxx"}
	err := Authorize(context.Background(), m, c, d, a)
	if !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("want ErrVaultLocked, got %v", err)
	}
	if len(a.events) != 1 || a.events[0].EventType != "offensive_failed" {
		t.Fatalf("expected failed event, got %+v", a.events)
	}
}

func TestAuthorize_BadCategory(t *testing.T) {
	d := newStubDeriver("k")
	a := &captureAuditor{}
	m := baseMutation()
	m.Category = Category("nope")
	c := Confirm{AcceptsWrites: true, ConfirmTarget: m.Target, ConfirmToken: "xxx"}
	err := Authorize(context.Background(), m, c, d, a)
	if !errors.Is(err, ErrBadCategory) {
		t.Fatalf("want ErrBadCategory, got %v", err)
	}
	if len(a.events) != 1 || a.events[0].EventType != "offensive_failed" {
		t.Fatalf("expected failed event, got %+v", a.events)
	}
}

func TestAuthorize_DiffMasterKeyDiffToken(t *testing.T) {
	// Two different vault master keys must produce distinct tokens,
	// so a token minted on machine A does not authorise on machine B.
	d1 := newStubDeriver("key-A")
	d2 := newStubDeriver("key-B")
	m := baseMutation()
	t1, err := ExpectedToken(m, d1)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := ExpectedToken(m, d2)
	if err != nil {
		t.Fatal(err)
	}
	if t1 == t2 {
		t.Fatalf("tokens must differ across master keys; both = %s", t1)
	}
}

func TestAuthorize_DiffPayloadDiffToken(t *testing.T) {
	d := newStubDeriver("k")
	m1 := baseMutation()
	m2 := baseMutation()
	m2.PayloadHash = sha256.Sum256([]byte("addr=0x0001,value=0xDEAD"))
	t1, err := ExpectedToken(m1, d)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := ExpectedToken(m2, d)
	if err != nil {
		t.Fatal(err)
	}
	if t1 == t2 {
		t.Fatalf("payload change must change token")
	}
}

func TestAuthorize_AuditWriteFailBlocks(t *testing.T) {
	// If the audit chain itself refuses the allowed event, Authorize
	// must return an error so the caller refuses to fire.
	d := newStubDeriver("k")
	a := &captureAuditor{fail: errors.New("chain broken")}
	m := baseMutation()
	tok, err := ExpectedToken(m, d)
	if err != nil {
		t.Fatal(err)
	}
	c := Confirm{AcceptsWrites: true, ConfirmTarget: m.Target, ConfirmToken: tok}
	err = Authorize(context.Background(), m, c, d, a)
	if err == nil {
		t.Fatalf("expected error when audit write fails")
	}
}
