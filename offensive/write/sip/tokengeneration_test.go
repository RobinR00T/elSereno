//go:build offensive

package sip_test

import (
	"bytes"
	"context"
	"testing"

	"local/elsereno/offensive/confirm"
	sipwrite "local/elsereno/offensive/write/sip"
)

// ---- Hash ladder: token-generation cookie degrades --------

// TestSIPAllowlistHashWithGeneration_ZeroMatchesV12Chunk5 — the
// v1.17 chunk-2 hash with generation=0 must equal the v1.12
// chunk-5 (FromDomains) hash. Backwards-compat ladder step 1:
// every v1.4 → v1.12-chunk-5 confirm-token still validates
// when the operator hasn't bumped the generation.
func TestSIPAllowlistHashWithGeneration_ZeroMatchesV12Chunk5(t *testing.T) {
	target := "pbx.test:5060"
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}, {Method: "REGISTER"}}
	prefixes := []sipwrite.AllowedToURIPrefix{{Prefix: "+34"}}
	aors := []sipwrite.AllowedAOR{{AOR: "sip:alice@pbx.internal"}}
	fromDomains := []sipwrite.AllowedFromDomain{{Domain: "pbx.internal"}}

	hPrev := sipwrite.AllowlistHashWithFromDomains(target, methods, prefixes, aors, fromDomains)
	hNew := sipwrite.AllowlistHashWithGeneration(target, methods, prefixes, aors, fromDomains, 0)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-2 hash with generation=0 must equal chunk-5 hash:\n%x\n%x", hNew, hPrev)
	}
}

// TestSIPAllowlistHashWithGeneration_NonZeroChangesHash —
// bumping the generation must perturb the hash.
func TestSIPAllowlistHashWithGeneration_NonZeroChangesHash(t *testing.T) {
	target := "pbx.test:5060"
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	hZero := sipwrite.AllowlistHashWithGeneration(target, methods, nil, nil, nil, 0)
	hOne := sipwrite.AllowlistHashWithGeneration(target, methods, nil, nil, nil, 1)
	if bytes.Equal(hZero[:], hOne[:]) {
		t.Fatal("chunk-2 hash with generation=1 must differ from generation=0")
	}
}

// TestSIPAllowlistHashWithGeneration_DifferentGenerationsDiffer —
// every distinct generation produces a distinct hash.
func TestSIPAllowlistHashWithGeneration_DifferentGenerationsDiffer(t *testing.T) {
	target := "pbx.test:5060"
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	gens := []uint32{1, 2, 100, 0xFFFFFFFF}
	hashes := make(map[[32]byte]uint32, len(gens))
	for _, g := range gens {
		h := sipwrite.AllowlistHashWithGeneration(target, methods, nil, nil, nil, g)
		if prev, dup := hashes[h]; dup {
			t.Fatalf("collision: gen=%d and gen=%d produced same hash %x", prev, g, h)
		}
		hashes[h] = g
	}
}

// TestSIPAllowlistHashWithGeneration_StableForSameGeneration —
// the hash is deterministic.
func TestSIPAllowlistHashWithGeneration_StableForSameGeneration(t *testing.T) {
	target := "pbx.test:5060"
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	h1 := sipwrite.AllowlistHashWithGeneration(target, methods, nil, nil, nil, 42)
	h2 := sipwrite.AllowlistHashWithGeneration(target, methods, nil, nil, nil, 42)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatalf("chunk-2 hash not deterministic: %x vs %x", h1, h2)
	}
}

// ---- E2E gate: TokenGeneration flowed through Authorise ------

// TestSIPGate_TokenGeneration_StaleTokenRejected — operator
// originally minted a token at gen=0; bumps allow-file + gen;
// the bumped session refuses the old token.
func TestSIPGate_TokenGeneration_StaleTokenRejected(t *testing.T) {
	target := "pbx.test:5060"
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}

	mutOld := sipwrite.SessionMutationWithGeneration(target, methods, nil, nil, nil, 0)
	tokOld, err := confirm.ExpectedToken(mutOld, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}

	h := &sipwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         methods,
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

// TestSIPGate_TokenGeneration_FreshTokenAccepted — operator
// bumps the generation AND mints a new token; Authorise OK.
func TestSIPGate_TokenGeneration_FreshTokenAccepted(t *testing.T) {
	target := "pbx.test:5060"
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}

	mutNew := sipwrite.SessionMutationWithGeneration(target, methods, nil, nil, nil, 1)
	tokNew, err := confirm.ExpectedToken(mutNew, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}

	h := &sipwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         methods,
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

// TestSIPGate_TokenGeneration_DefaultPreservesOldTokens —
// when operator does NOT bump, v1.4 → v1.12 tokens minted via
// chunk-5 helpers continue to validate.
func TestSIPGate_TokenGeneration_DefaultPreservesOldTokens(t *testing.T) {
	target := "pbx.test:5060"
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}

	mutCh5 := sipwrite.SessionMutationWithFromDomains(target, methods, nil, nil, nil)
	tokCh5, err := confirm.ExpectedToken(mutCh5, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}

	h := &sipwrite.WriteGatedHandler{
		Target:  target,
		Allowed: methods,
		// TokenGeneration: 0 (default)
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokCh5,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() with chunk-5 token + gen=0 must succeed (backwards-compat): %v", err)
	}
}
