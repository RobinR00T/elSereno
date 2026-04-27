//go:build offensive

package iax2_test

import (
	"bytes"
	"context"
	"testing"

	"local/elsereno/internal/protocols/iax2/wire"
	"local/elsereno/offensive/confirm"
	iaxwrite "local/elsereno/offensive/write/iax2"
)

// TestIAX2AllowlistHashWithGeneration_ZeroMatchesV15 — gen=0
// must equal AllowlistHash byte-for-byte.
func TestIAX2AllowlistHashWithGeneration_ZeroMatchesV15(t *testing.T) {
	target := "pbx.test:4569"
	allowed := []iaxwrite.AllowedSubclass{{Subclass: wire.IAXNew}}
	hPrev := iaxwrite.AllowlistHash(target, allowed)
	hNew := iaxwrite.AllowlistHashWithGeneration(target, allowed, 0)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("gen=0 must equal v1.5 hash:\n%x\n%x", hNew, hPrev)
	}
}

// TestIAX2AllowlistHashWithGeneration_NonZeroChangesHash — gen
// bump perturbs hash.
func TestIAX2AllowlistHashWithGeneration_NonZeroChangesHash(t *testing.T) {
	target := "pbx.test:4569"
	allowed := []iaxwrite.AllowedSubclass{{Subclass: wire.IAXNew}}
	hZero := iaxwrite.AllowlistHashWithGeneration(target, allowed, 0)
	hOne := iaxwrite.AllowlistHashWithGeneration(target, allowed, 1)
	if bytes.Equal(hZero[:], hOne[:]) {
		t.Fatal("gen=1 must differ from gen=0")
	}
}

// TestIAX2Gate_TokenGeneration_StaleTokenRejected — stale
// token rejected when handler bumps gen.
func TestIAX2Gate_TokenGeneration_StaleTokenRejected(t *testing.T) {
	target := "pbx.test:4569"
	allowed := []iaxwrite.AllowedSubclass{{Subclass: wire.IAXNew}}

	mutOld := iaxwrite.SessionMutationWithGeneration(target, allowed, 0)
	tokOld, err := confirm.ExpectedToken(mutOld, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &iaxwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         allowed,
		TokenGeneration: 1,
		Deriver:         &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:         &fakeAuditor{},
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

// TestIAX2Gate_TokenGeneration_FreshTokenAccepted — fresh gen
// token works.
func TestIAX2Gate_TokenGeneration_FreshTokenAccepted(t *testing.T) {
	target := "pbx.test:4569"
	allowed := []iaxwrite.AllowedSubclass{{Subclass: wire.IAXNew}}

	mutNew := iaxwrite.SessionMutationWithGeneration(target, allowed, 1)
	tokNew, err := confirm.ExpectedToken(mutNew, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &iaxwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         allowed,
		TokenGeneration: 1,
		Deriver:         &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:         &fakeAuditor{},
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

// TestIAX2Gate_TokenGeneration_DefaultPreservesOldTokens —
// default gen=0 preserves v1.5 tokens.
func TestIAX2Gate_TokenGeneration_DefaultPreservesOldTokens(t *testing.T) {
	target := "pbx.test:4569"
	allowed := []iaxwrite.AllowedSubclass{{Subclass: wire.IAXNew}}

	mutV15 := iaxwrite.SessionMutation(target, allowed)
	tokV15, err := confirm.ExpectedToken(mutV15, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &iaxwrite.WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokV15,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() with v1.5 token + gen=0 must succeed (backwards-compat): %v", err)
	}
}
