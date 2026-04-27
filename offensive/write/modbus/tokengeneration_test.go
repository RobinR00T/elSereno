//go:build offensive

package modbus

import (
	"bytes"
	"context"
	"testing"

	mbwire "local/elsereno/internal/protocols/modbus/wire"
	"local/elsereno/offensive/confirm"
)

// testDeriverKey is the deriver key shared with the chunk-3
// token-generation tests in this file (internal package).
const testDeriverKey = "test-key-32-byte-long--------"

// fakeDeriver is a deterministic key deriver for tests.
type fakeDeriver struct{ key []byte }

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	if len(out) > len(f.key) {
		copy(out, f.key)
		return nil
	}
	copy(out, f.key[:len(out)])
	return nil
}

// TestModbusAllowlistHashWithGeneration_ZeroMatchesV12 — gen=0
// must equal AllowlistHash byte-for-byte.
func TestModbusAllowlistHashWithGeneration_ZeroMatchesV12(t *testing.T) {
	target := "plc.test:502"
	allowed := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleRegister, StartAddr: 0, EndAddr: 0}}
	hPrev := AllowlistHash(target, allowed)
	hNew := AllowlistHashWithGeneration(target, allowed, 0)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("gen=0 must equal v1.2 hash:\n%x\n%x", hNew, hPrev)
	}
}

// TestModbusAllowlistHashWithGeneration_NonZeroChangesHash —
// bumping gen perturbs the hash.
func TestModbusAllowlistHashWithGeneration_NonZeroChangesHash(t *testing.T) {
	target := "plc.test:502"
	allowed := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleRegister}}
	hZero := AllowlistHashWithGeneration(target, allowed, 0)
	hOne := AllowlistHashWithGeneration(target, allowed, 1)
	if bytes.Equal(hZero[:], hOne[:]) {
		t.Fatal("gen=1 must differ from gen=0")
	}
}

// TestModbusGate_TokenGeneration_StaleTokenRejected — stale
// token rejected when handler bumps gen.
func TestModbusGate_TokenGeneration_StaleTokenRejected(t *testing.T) {
	target := "plc.test:502"
	allowed := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleRegister}}

	mutOld := SessionMutationWithGeneration(target, allowed, 0)
	tokOld, err := confirm.ExpectedToken(mutOld, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &WriteGatedHandler{
		Target:          target,
		Allowed:         allowed,
		TokenGeneration: 1,
		Deriver:         &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:         &captureAudit{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokOld,
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("Authorise() with stale (gen=0) token must fail when handler.TokenGeneration=1")
	}
}

// TestModbusGate_TokenGeneration_FreshTokenAccepted — fresh
// gen-bumped token works.
func TestModbusGate_TokenGeneration_FreshTokenAccepted(t *testing.T) {
	target := "plc.test:502"
	allowed := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleRegister}}

	mutNew := SessionMutationWithGeneration(target, allowed, 1)
	tokNew, err := confirm.ExpectedToken(mutNew, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &WriteGatedHandler{
		Target:          target,
		Allowed:         allowed,
		TokenGeneration: 1,
		Deriver:         &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:         &captureAudit{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokNew,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() with fresh (gen=1) token must succeed: %v", err)
	}
}

// TestModbusGate_TokenGeneration_DefaultPreservesOldTokens —
// default gen=0 preserves v1.2 tokens.
func TestModbusGate_TokenGeneration_DefaultPreservesOldTokens(t *testing.T) {
	target := "plc.test:502"
	allowed := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleRegister}}

	mutV12 := SessionMutation(target, allowed)
	tokV12, err := confirm.ExpectedToken(mutV12, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &captureAudit{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokV12,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() with v1.2 token + gen=0 must succeed (backwards-compat): %v", err)
	}
}
