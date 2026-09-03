//go:build offensive

package modbus

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	mbwire "local/elsereno/internal/protocols/modbus/wire"
	"local/elsereno/offensive/confirm"
)

// diagTarget is the fixed upstream all the gate-decision tests point at.
const diagTarget = "t:502"

// diagFrame builds an FC 8 request carrying sub-function `sub`.
func diagFrame(sub uint16) mbwire.Frame {
	return mbwire.Frame{
		MBAP: mbwire.MBAP{TxID: 1, Protocol: mbwire.ProtocolID, Unit: 1},
		PDU: []byte{
			byte(mbwire.FCDiagnostics),
			byte(sub >> 8), byte(sub & 0xFF),
			0x00, 0x00,
		},
	}
}

// buildGatedHandlerDiag mints a session token that binds the diag
// sub-function allowlist (no write entries) and pre-authorises the
// handler so shouldForward / Handle can run.
func buildGatedHandlerDiag(t *testing.T, diag []mbwire.DiagSubFunction) *WriteGatedHandler {
	t.Helper()
	d := &diagStubDeriver{master: []byte("k")}
	m := SessionMutationWithDiag(diagTarget, nil, 0, diag)
	tok, err := confirm.ExpectedToken(m, d)
	if err != nil {
		t.Fatal(err)
	}
	h := &WriteGatedHandler{
		Target:      diagTarget,
		AllowedDiag: diag,
		Deriver:     d,
		Auditor:     &diagCaptureAudit{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: diagTarget,
			ConfirmToken:  tok,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	return h
}

type diagStubDeriver struct{ master []byte }

func (s *diagStubDeriver) Derive(info string, out []byte) error {
	r := hkdf.New(sha256.New, s.master, nil, []byte(info))
	_, err := io.ReadFull(r, out)
	return err
}

type diagCaptureAudit struct{ events []confirm.AuditEvent }

func (c *diagCaptureAudit) Record(_ context.Context, ev confirm.AuditEvent) error {
	c.events = append(c.events, ev)
	return nil
}

// TestShouldForward_DiagReadOnlyAlwaysForwards proves a read/echo/
// counter sub-function forwards even with an empty diag allowlist.
func TestShouldForward_DiagReadOnlyAlwaysForwards(t *testing.T) {
	t.Parallel()
	h := buildGatedHandlerDiag(t, nil)
	for _, sub := range []uint16{0x0000, 0x0002, 0x000B, 0x0012} {
		if !h.shouldForward(diagFrame(sub)) {
			t.Errorf("read-only diag 0x%04x refused; must always forward", sub)
		}
	}
}

// TestShouldForward_DiagMutatingRefusedByDefault proves the DoS/mutating
// sub-functions refuse without an explicit allowlist entry.
func TestShouldForward_DiagMutatingRefusedByDefault(t *testing.T) {
	t.Parallel()
	h := buildGatedHandlerDiag(t, nil)
	for _, sub := range []uint16{
		0x0001, // Restart Communications
		0x0003, // Change ASCII Delimiter
		0x0004, // Force Listen Only (DoS)
		0x000A, // Clear Counters (anti-forensic)
		0x0014, // Clear Overrun Counter
		0x00FF, // reserved / vendor → default-deny
	} {
		if h.shouldForward(diagFrame(sub)) {
			t.Errorf("mutating diag 0x%04x forwarded with empty allowlist; must refuse", sub)
		}
	}
}

// TestShouldForward_DiagMutatingForwardsWhenAllowlisted proves the
// allowlist opens exactly the authorised sub-function and nothing else.
func TestShouldForward_DiagMutatingForwardsWhenAllowlisted(t *testing.T) {
	t.Parallel()
	// Authorise only Force Listen Only (0x04).
	diag := []mbwire.DiagSubFunction{mbwire.DiagForceListenOnly}
	h := buildGatedHandlerDiag(t, diag)
	if !h.shouldForward(diagFrame(0x0004)) {
		t.Fatal("allowlisted Force Listen Only (0x04) refused")
	}
	// A different mutating sub-function stays refused.
	if h.shouldForward(diagFrame(0x000A)) {
		t.Fatal("Clear Counters (0x0A) forwarded but only 0x04 was allowlisted")
	}
}

// TestShouldForward_DiagMalformedRefused proves a truncated FC 8 (no
// 16-bit sub-function) fails closed.
func TestShouldForward_DiagMalformedRefused(t *testing.T) {
	t.Parallel()
	h := buildGatedHandlerDiag(t, nil)
	short := mbwire.Frame{
		MBAP: mbwire.MBAP{TxID: 1, Protocol: mbwire.ProtocolID, Unit: 1},
		PDU:  []byte{byte(mbwire.FCDiagnostics), 0x00}, // one sub byte only
	}
	if h.shouldForward(short) {
		t.Fatal("malformed FC 8 forwarded; must fail closed")
	}
}

// TestAllowlistHashWithDiag_EmptyMatchesGeneration proves backwards-
// compat: an empty diag allowlist yields a digest byte-identical to
// AllowlistHashWithGeneration, so every pre-existing token stays valid.
func TestAllowlistHashWithDiag_EmptyMatchesGeneration(t *testing.T) {
	t.Parallel()
	target := "10.0.0.1:502"
	allowed := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleRegister}}
	for _, gen := range []uint32{0, 1, 42} {
		want := AllowlistHashWithGeneration(target, allowed, gen)
		got := AllowlistHashWithDiag(target, allowed, gen, nil)
		if got != want {
			t.Fatalf("gen=%d: WithDiag(nil) != WithGeneration", gen)
		}
	}
}

// TestAllowlistHashWithDiag_NonEmptyChangesHash proves adding a diag
// entry mints a distinct token (operator must re-authorise).
func TestAllowlistHashWithDiag_NonEmptyChangesHash(t *testing.T) {
	t.Parallel()
	target := "10.0.0.1:502"
	allowed := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleRegister}}
	base := AllowlistHashWithGeneration(target, allowed, 0)
	withDiag := AllowlistHashWithDiag(target, allowed, 0,
		[]mbwire.DiagSubFunction{mbwire.DiagForceListenOnly})
	if base == withDiag {
		t.Fatal("adding a diag sub-function must change the token hash")
	}
}

// TestAllowlistHashWithDiag_OrderAndDupInsensitive proves the diag
// allowlist is sorted + de-duplicated before hashing, so flag order and
// accidental repeats do not shift the token.
func TestAllowlistHashWithDiag_OrderAndDupInsensitive(t *testing.T) {
	t.Parallel()
	target := "10.0.0.1:502"
	var allowed []AllowedWrite
	a := AllowlistHashWithDiag(target, allowed, 0, []mbwire.DiagSubFunction{0x04, 0x0A})
	b := AllowlistHashWithDiag(target, allowed, 0, []mbwire.DiagSubFunction{0x0A, 0x04, 0x04})
	if a != b {
		t.Fatal("diag allowlist hash must be order- and duplicate-insensitive")
	}
}
