//go:build offensive

package bacnet_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	bwire "local/elsereno/internal/protocols/bacnet/wire"
	"local/elsereno/offensive/confirm"
	bwrite "local/elsereno/offensive/write/bacnet"
)

// ---- Hash ladder: token-generation cookie degrades --------

// TestAllowlistHashWithGeneration_ZeroMatchesV16Chunk3 — the
// v1.16 chunk-4 hash with Generation=0 must equal the v1.16
// chunk-3 hash. Backwards-compat ladder step 1: every v1.4 →
// v1.16-chunk-3 confirm-token still validates when the
// operator hasn't bumped the generation.
func TestAllowlistHashWithGeneration_ZeroMatchesV16Chunk3(t *testing.T) {
	target := "bms.test:47808"
	al := bwrite.Allowlists{
		Services: []bwrite.AllowedService{{ServiceChoice: 27}},
		LSOOperations: []bwrite.AllowedLSOOperation{
			{Operation: bwire.LSOOpUnsilence},
		},
	}
	hPrev := bwrite.AllowlistHashWithLSOTargets(target, al)
	hNew := bwrite.AllowlistHashWithGeneration(target, al)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-4 hash with Generation=0 must equal chunk-3 hash:\n%x\n%x", hNew, hPrev)
	}
}

// TestAllowlistHashWithGeneration_NonZeroChangesHash — bumping
// the generation must perturb the hash so a stale confirm-
// token (minted at the prior generation) is rejected.
func TestAllowlistHashWithGeneration_NonZeroChangesHash(t *testing.T) {
	target := "bms.test:47808"
	base := bwrite.Allowlists{
		Services: []bwrite.AllowedService{{ServiceChoice: 27}},
	}
	hZero := bwrite.AllowlistHashWithGeneration(target, base)

	bumped := base
	bumped.Generation = 1
	hOne := bwrite.AllowlistHashWithGeneration(target, bumped)
	if bytes.Equal(hZero[:], hOne[:]) {
		t.Fatal("chunk-4 hash with Generation=1 must differ from Generation=0")
	}
}

// TestAllowlistHashWithGeneration_DifferentGenerationsDiffer —
// every distinct generation produces a distinct hash. Pin
// the cryptographic property that the operator's reload
// workflow depends on (each bump → fresh token).
func TestAllowlistHashWithGeneration_DifferentGenerationsDiffer(t *testing.T) {
	target := "bms.test:47808"
	base := bwrite.Allowlists{
		Services: []bwrite.AllowedService{{ServiceChoice: 27}},
	}
	gens := []uint32{1, 2, 100, 0xFFFFFFFF}
	hashes := make(map[[32]byte]uint32, len(gens))
	for _, g := range gens {
		al := base
		al.Generation = g
		h := bwrite.AllowlistHashWithGeneration(target, al)
		if prev, dup := hashes[h]; dup {
			t.Fatalf("collision: Generation=%d and Generation=%d produced the same hash %x", prev, g, h)
		}
		hashes[h] = g
	}
}

// TestAllowlistHashWithGeneration_StableForSameGeneration — the
// hash is deterministic; same input → same output across
// invocations.
func TestAllowlistHashWithGeneration_StableForSameGeneration(t *testing.T) {
	target := "bms.test:47808"
	al := bwrite.Allowlists{
		Services:   []bwrite.AllowedService{{ServiceChoice: 27}},
		Generation: 42,
	}
	h1 := bwrite.AllowlistHashWithGeneration(target, al)
	h2 := bwrite.AllowlistHashWithGeneration(target, al)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatalf("chunk-4 hash not deterministic: %x vs %x", h1, h2)
	}
}

// ---- E2E gate: TokenGeneration flowed through Authorise ------

// TestGateBACnet_TokenGeneration_StaleTokenRejected — operator
// originally minted a token at Generation=0; bumps allow-file
// + Generation; the bumped session refuses the old token. End-
// to-end verification that the chunk-4 hash flips invalidate
// stale tokens at the Authorise layer.
func TestGateBACnet_TokenGeneration_StaleTokenRejected(t *testing.T) {
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	ops := []bwrite.AllowedLSOOperation{{Operation: bwire.LSOOpUnsilence}}

	// Mint a token at Generation=0 (the v1.16-chunk-3-equivalent
	// state).
	mutOld := bwrite.SessionMutationWithGeneration(target, bwrite.Allowlists{
		Services:      svcs,
		LSOOperations: ops,
		Generation:    0,
	})
	tokOld, err := confirm.ExpectedToken(mutOld, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}

	// Operator now bumps the generation and tries to authorise
	// the proxy with the *old* token. Authorise must fail.
	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedLSOOperations: ops,
		TokenGeneration:      1, // bumped
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokOld, // stale — minted at Generation=0
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("Authorise() with stale (Generation=0) confirm-token must fail when handler.TokenGeneration=1")
	}
}

// TestGateBACnet_TokenGeneration_FreshTokenAccepted — operator
// bumps the generation AND mints a new token at the same
// generation; Authorise succeeds. Pins the happy path.
func TestGateBACnet_TokenGeneration_FreshTokenAccepted(t *testing.T) {
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	ops := []bwrite.AllowedLSOOperation{{Operation: bwire.LSOOpUnsilence}}

	// Mint a fresh token at the bumped generation.
	mutNew := bwrite.SessionMutationWithGeneration(target, bwrite.Allowlists{
		Services:      svcs,
		LSOOperations: ops,
		Generation:    1,
	})
	tokNew, err := confirm.ExpectedToken(mutNew, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}

	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedLSOOperations: ops,
		TokenGeneration:      1,
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokNew,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() with fresh (Generation=1) token must succeed: %v", err)
	}
}

// TestGateBACnet_TokenGeneration_DefaultPreservesOldTokens — the
// dual of the stale-rejection test: when operator does NOT
// bump (Generation stays 0), v1.4 → v1.16-chunk-3 tokens
// continue to validate. Pins the backwards-compat promise.
func TestGateBACnet_TokenGeneration_DefaultPreservesOldTokens(t *testing.T) {
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	ops := []bwrite.AllowedLSOOperation{{Operation: bwire.LSOOpUnsilence}}

	// Mint a token using the v1.16-chunk-3 mutation (no
	// generation field, equivalent to Generation=0).
	mutCh3 := bwrite.SessionMutationWithLSOTargets(target, bwrite.Allowlists{
		Services:      svcs,
		LSOOperations: ops,
	})
	tokCh3, err := confirm.ExpectedToken(mutCh3, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}

	// Authorise via the chunk-4 mutation with Generation=0.
	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedLSOOperations: ops,
		// TokenGeneration: 0 (default)
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tokCh3,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() with chunk-3 token + Generation=0 must succeed (backwards-compat): %v", err)
	}
}

// ---- E2E gate: chunk-4-tokened session still routes traffic --

// TestGateBACnetLSO_TokenGeneration_FrameForwards — sanity:
// after authorising with a chunk-4 mutation, the gate still
// forwards permitted LSO requests. Catches regressions from
// the new mutation factory.
func TestGateBACnetLSO_TokenGeneration_FrameForwards(t *testing.T) {
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	ops := []bwrite.AllowedLSOOperation{{Operation: bwire.LSOOpUnsilence}}

	mut := bwrite.SessionMutationWithGeneration(target, bwrite.Allowlists{
		Services:      svcs,
		LSOOperations: ops,
		Generation:    7,
	})
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedLSOOperations: ops,
		TokenGeneration:      7,
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tok,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
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
	rec := &datagramRecorder{}
	go rec.run(upstreamSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()

	frame := buildLSOFrame(bwire.LSOOpUnsilence)
	_, _ = clientIn.Write(frame)

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(rec.snapshot()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rec.snapshot()) == 0 {
		t.Fatal("upstream saw nothing for chunk-4-tokened LSO unsilence")
	}
}
