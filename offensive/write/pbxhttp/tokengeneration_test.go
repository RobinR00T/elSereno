//go:build offensive

package pbxhttp_test

import (
	"bytes"
	"context"
	"testing"

	"local/elsereno/offensive/confirm"
	pbxwrite "local/elsereno/offensive/write/pbxhttp"
)

// TestPBXHTTPAllowlistHashWithGeneration_ZeroMatchesV14 — gen=0
// must equal AllowlistHash byte-for-byte.
func TestPBXHTTPAllowlistHashWithGeneration_ZeroMatchesV14(t *testing.T) {
	target := "pbx.test:443"
	allowed := []pbxwrite.AllowedWrite{{Method: "POST", Path: "/admin/config.php"}}
	hPrev := pbxwrite.AllowlistHash(target, allowed)
	hNew := pbxwrite.AllowlistHashWithGeneration(target, allowed, 0)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("gen=0 must equal v1.4 hash:\n%x\n%x", hNew, hPrev)
	}
}

// TestPBXHTTPAllowlistHashWithGeneration_NonZeroChangesHash —
// gen bump perturbs hash.
func TestPBXHTTPAllowlistHashWithGeneration_NonZeroChangesHash(t *testing.T) {
	target := "pbx.test:443"
	allowed := []pbxwrite.AllowedWrite{{Method: "POST", Path: "/admin/config.php"}}
	hZero := pbxwrite.AllowlistHashWithGeneration(target, allowed, 0)
	hOne := pbxwrite.AllowlistHashWithGeneration(target, allowed, 1)
	if bytes.Equal(hZero[:], hOne[:]) {
		t.Fatal("gen=1 must differ from gen=0")
	}
}

// TestPBXHTTPGate_TokenGeneration_StaleTokenRejected.
func TestPBXHTTPGate_TokenGeneration_StaleTokenRejected(t *testing.T) {
	target := "pbx.test:443"
	allowed := []pbxwrite.AllowedWrite{{Method: "POST", Path: "/admin"}}

	mutOld := pbxwrite.SessionMutationWithGeneration(target, allowed, 0)
	tokOld, err := confirm.ExpectedToken(mutOld, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &pbxwrite.WriteGatedHandler{
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

// TestPBXHTTPGate_TokenGeneration_FreshTokenAccepted.
func TestPBXHTTPGate_TokenGeneration_FreshTokenAccepted(t *testing.T) {
	target := "pbx.test:443"
	allowed := []pbxwrite.AllowedWrite{{Method: "POST", Path: "/admin"}}

	mutNew := pbxwrite.SessionMutationWithGeneration(target, allowed, 1)
	tokNew, err := confirm.ExpectedToken(mutNew, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &pbxwrite.WriteGatedHandler{
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

// TestPBXHTTPGate_TokenGeneration_DefaultPreservesOldTokens.
func TestPBXHTTPGate_TokenGeneration_DefaultPreservesOldTokens(t *testing.T) {
	target := "pbx.test:443"
	allowed := []pbxwrite.AllowedWrite{{Method: "POST", Path: "/admin"}}

	mutV14 := pbxwrite.SessionMutation(target, allowed)
	tokV14, err := confirm.ExpectedToken(mutV14, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &pbxwrite.WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokV14,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() with v1.4 token + gen=0 must succeed (backwards-compat): %v", err)
	}
}
