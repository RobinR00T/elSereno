//go:build offensive

package cwmp_test

import (
	"bytes"
	"context"
	"testing"

	"local/elsereno/offensive/confirm"
	cwmpwrite "local/elsereno/offensive/write/cwmp"
)

// ---- Hash ladder: token-generation cookie degrades --------

// TestCWMPAllowlistHashWithGeneration_ZeroMatchesV12Chunk10 —
// the v1.17 chunk-1 hash with generation=0 must equal the
// v1.12 chunk-10 (Firmware) hash. Backwards-compat ladder
// step 1: every v1.11 → v1.12 confirm-token still validates
// when the operator hasn't bumped the generation.
func TestCWMPAllowlistHashWithGeneration_ZeroMatchesV12Chunk10(t *testing.T) {
	target := "acs.test:7547"
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}
	paths := []cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice."}}
	fws := []cwmpwrite.AllowedFirmware{{URL: "https://acs.example/fw.bin"}}

	hPrev := cwmpwrite.AllowlistHashWithFirmware(target, rpcs, paths, fws)
	hNew := cwmpwrite.AllowlistHashWithGeneration(target, rpcs, paths, fws, 0)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-1 hash with generation=0 must equal chunk-10 hash:\n%x\n%x", hNew, hPrev)
	}
}

// TestCWMPAllowlistHashWithGeneration_NonZeroChangesHash —
// bumping the generation must perturb the hash so a stale
// confirm-token (minted at the prior generation) is rejected.
func TestCWMPAllowlistHashWithGeneration_NonZeroChangesHash(t *testing.T) {
	target := "acs.test:7547"
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}
	hZero := cwmpwrite.AllowlistHashWithGeneration(target, rpcs, nil, nil, 0)
	hOne := cwmpwrite.AllowlistHashWithGeneration(target, rpcs, nil, nil, 1)
	if bytes.Equal(hZero[:], hOne[:]) {
		t.Fatal("chunk-1 hash with generation=1 must differ from generation=0")
	}
}

// TestCWMPAllowlistHashWithGeneration_DifferentGenerationsDiffer
// — every distinct generation produces a distinct hash. Pin
// the cryptographic property the operator's reload workflow
// depends on (each bump → fresh token).
func TestCWMPAllowlistHashWithGeneration_DifferentGenerationsDiffer(t *testing.T) {
	target := "acs.test:7547"
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}
	gens := []uint32{1, 2, 100, 0xFFFFFFFF}
	hashes := make(map[[32]byte]uint32, len(gens))
	for _, g := range gens {
		h := cwmpwrite.AllowlistHashWithGeneration(target, rpcs, nil, nil, g)
		if prev, dup := hashes[h]; dup {
			t.Fatalf("collision: gen=%d and gen=%d produced same hash %x", prev, g, h)
		}
		hashes[h] = g
	}
}

// TestCWMPAllowlistHashWithGeneration_StableForSameGeneration —
// the hash is deterministic; same input → same output across
// invocations.
func TestCWMPAllowlistHashWithGeneration_StableForSameGeneration(t *testing.T) {
	target := "acs.test:7547"
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}
	h1 := cwmpwrite.AllowlistHashWithGeneration(target, rpcs, nil, nil, 42)
	h2 := cwmpwrite.AllowlistHashWithGeneration(target, rpcs, nil, nil, 42)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatalf("chunk-1 hash not deterministic: %x vs %x", h1, h2)
	}
}

// ---- E2E gate: TokenGeneration flowed through Authorise ------

// TestCWMPGate_TokenGeneration_StaleTokenRejected — operator
// originally minted a token at Generation=0; bumps allow-file
// + Generation; the bumped session refuses the old token.
func TestCWMPGate_TokenGeneration_StaleTokenRejected(t *testing.T) {
	target := "acs.test:7547"
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}

	mutOld := cwmpwrite.SessionMutationWithGeneration(target, rpcs, nil, nil, 0)
	tokOld, err := confirm.ExpectedToken(mutOld, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}

	h := &cwmpwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         rpcs,
		TokenGeneration: 1, // bumped
		Deriver:         &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:         &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokOld, // stale — minted at generation=0
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("Authorise() with stale (generation=0) confirm-token must fail when handler.TokenGeneration=1")
	}
}

// TestCWMPGate_TokenGeneration_FreshTokenAccepted — operator
// bumps the generation AND mints a new token at the same
// generation; Authorise succeeds. Pins the happy path.
func TestCWMPGate_TokenGeneration_FreshTokenAccepted(t *testing.T) {
	target := "acs.test:7547"
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}

	mutNew := cwmpwrite.SessionMutationWithGeneration(target, rpcs, nil, nil, 1)
	tokNew, err := confirm.ExpectedToken(mutNew, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}

	h := &cwmpwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         rpcs,
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
		t.Fatalf("Authorise() with fresh (generation=1) token must succeed: %v", err)
	}
}

// TestCWMPGate_TokenGeneration_DefaultPreservesOldTokens — the
// dual: when operator does NOT bump (generation stays 0),
// v1.11 → v1.12 tokens minted with the prior helpers continue
// to validate. Pins the backwards-compat promise.
func TestCWMPGate_TokenGeneration_DefaultPreservesOldTokens(t *testing.T) {
	target := "acs.test:7547"
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}

	// Mint a token using the v1.12-chunk-10 mutation (no
	// generation field, equivalent to generation=0).
	mutCh10 := cwmpwrite.SessionMutationWithFirmware(target, rpcs, nil, nil)
	tokCh10, err := confirm.ExpectedToken(mutCh10, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}

	// Authorise via the chunk-1 mutation with generation=0.
	h := &cwmpwrite.WriteGatedHandler{
		Target:  target,
		Allowed: rpcs,
		// TokenGeneration: 0 (default)
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokCh10,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() with chunk-10 token + generation=0 must succeed (backwards-compat): %v", err)
	}
}
