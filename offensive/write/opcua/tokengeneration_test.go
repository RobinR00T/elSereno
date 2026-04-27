//go:build offensive

package opcua_test

import (
	"bytes"
	"context"
	"testing"

	"local/elsereno/offensive/confirm"
	opwrite "local/elsereno/offensive/write/opcua"
)

// testDeriverKey is the deriver key used by all token-generation
// tests. Mirrors the inline string used in gatedproxy_test.go.
const testDeriverKey = "test-key-32-byte-long--------"

// TestOPCUAAllowlistHashWithGeneration_ZeroMatchesV12Chunk6 —
// gen=0 must equal AllowlistHashWithCallMethods byte-for-byte.
func TestOPCUAAllowlistHashWithGeneration_ZeroMatchesV12Chunk6(t *testing.T) {
	target := "plc.test:4840"
	services := []opwrite.AllowedService{{TypeID: 673}}
	hPrev := opwrite.AllowlistHashWithCallMethods(target, services, nil, nil, nil)
	hNew := opwrite.AllowlistHashWithGeneration(target, services, nil, nil, nil, 0)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("gen=0 must equal v1.12 chunk-6 hash:\n%x\n%x", hNew, hPrev)
	}
}

// TestOPCUAAllowlistHashWithGeneration_NonZeroChangesHash.
func TestOPCUAAllowlistHashWithGeneration_NonZeroChangesHash(t *testing.T) {
	target := "plc.test:4840"
	services := []opwrite.AllowedService{{TypeID: 673}}
	hZero := opwrite.AllowlistHashWithGeneration(target, services, nil, nil, nil, 0)
	hOne := opwrite.AllowlistHashWithGeneration(target, services, nil, nil, nil, 1)
	if bytes.Equal(hZero[:], hOne[:]) {
		t.Fatal("gen=1 must differ from gen=0")
	}
}

// TestOPCUAGate_TokenGeneration_StaleTokenRejected.
func TestOPCUAGate_TokenGeneration_StaleTokenRejected(t *testing.T) {
	target := "plc.test:4840"
	services := []opwrite.AllowedService{{TypeID: 673}}

	mutOld := opwrite.SessionMutationWithGeneration(target, services, nil, nil, nil, 0)
	tokOld, err := confirm.ExpectedToken(mutOld, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &opwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         services,
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

// TestOPCUAGate_TokenGeneration_FreshTokenAccepted.
func TestOPCUAGate_TokenGeneration_FreshTokenAccepted(t *testing.T) {
	target := "plc.test:4840"
	services := []opwrite.AllowedService{{TypeID: 673}}

	mutNew := opwrite.SessionMutationWithGeneration(target, services, nil, nil, nil, 1)
	tokNew, err := confirm.ExpectedToken(mutNew, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &opwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         services,
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

// TestOPCUAGate_TokenGeneration_DefaultPreservesOldTokens —
// chunk-6 token validates with default gen=0.
func TestOPCUAGate_TokenGeneration_DefaultPreservesOldTokens(t *testing.T) {
	target := "plc.test:4840"
	services := []opwrite.AllowedService{{TypeID: 673}}

	mutCh6 := opwrite.SessionMutationWithCallMethods(target, services, nil, nil, nil)
	tokCh6, err := confirm.ExpectedToken(mutCh6, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &opwrite.WriteGatedHandler{
		Target:  target,
		Allowed: services,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokCh6,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() with chunk-6 token + gen=0 must succeed (backwards-compat): %v", err)
	}
}
