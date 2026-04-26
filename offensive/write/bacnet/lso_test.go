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

// ---- Hash ladder: per-LSO-op variant degrades --------------

func TestAllowlistHashWithLSOOps_EmptyMatchesV13Chunk10(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	dcc := []bwrite.AllowedDCCState{{State: bwire.DCCStateEnable}}
	hPrev := bwrite.AllowlistHashWithDCCStates("fire:47808", bwrite.Allowlists{
		Services:  svcs,
		DCCStates: dcc,
	})
	hNew := bwrite.AllowlistHashWithLSOOps("fire:47808", bwrite.Allowlists{
		Services:  svcs,
		DCCStates: dcc,
	})
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-11 hash with empty LSOOps must equal chunk-10: %x vs %x", hNew, hPrev)
	}
}

func TestAllowlistHashWithLSOOps_AllEmptyMatchesV4(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	hV4 := bwrite.AllowlistHash("fire:47808", svcs)
	hNew := bwrite.AllowlistHashWithLSOOps("fire:47808", bwrite.Allowlists{
		Services: svcs,
	})
	if !bytes.Equal(hV4[:], hNew[:]) {
		t.Fatalf("chunk-11 hash with all-empty must equal v1.4: %x vs %x", hNew, hV4)
	}
}

func TestAllowlistHashWithLSOOps_NonEmptyChangesHash(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	lso := []bwrite.AllowedLSOOperation{{Operation: bwire.LSOOpUnsilence}}
	hPrev := bwrite.AllowlistHashWithDCCStates("fire:47808", bwrite.Allowlists{Services: svcs})
	hNew := bwrite.AllowlistHashWithLSOOps("fire:47808", bwrite.Allowlists{
		Services:      svcs,
		LSOOperations: lso,
	})
	if bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatal("chunk-11 hash with non-empty LSOOps must differ from chunk-10")
	}
}

func TestAllowlistHashWithLSOOps_OrderInsensitive(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	a := []bwrite.AllowedLSOOperation{{Operation: 4}, {Operation: 7}}
	b := []bwrite.AllowedLSOOperation{{Operation: 7}, {Operation: 4}}
	h1 := bwrite.AllowlistHashWithLSOOps("fire:47808", bwrite.Allowlists{Services: svcs, LSOOperations: a})
	h2 := bwrite.AllowlistHashWithLSOOps("fire:47808", bwrite.Allowlists{Services: svcs, LSOOperations: b})
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on LSOOperations input order")
	}
}

// ---- Wire parser: ParseLifeSafetyOperation ------------------

// buildLSOServiceBody crafts a LifeSafetyOperation body (AFTER
// the 4-byte confirmed-request header) with the 3 required
// fields (no optional objectIdentifier).
//
//	[0] requestingProcessIdentifier (length 1)
//	[1] requestingSource ("ops" — 1 encoding byte + 3 chars = length 4)
//	[2] request (length 1)
func buildLSOServiceBody(processID, op uint8) []byte {
	return []byte{
		0x09, processID, // [0] processID, primitive, length 1
		0x1C, 0x00, 0x6F, 0x70, 0x73, // [1] requestingSource, primitive, length 4: 00=ANSI + "ops"
		0x29, op, // [2] request, primitive, length 1
	}
}

// buildLSOServiceBodyLongerProcessID uses a length-2 processID.
func buildLSOServiceBodyLongerProcessID(processID uint16, op uint8) []byte {
	hi := byte((processID >> 8) & 0xFF)
	lo := byte(processID & 0xFF)
	return []byte{
		0x0A, hi, lo, // [0] length 2
		0x1C, 0x00, 0x6F, 0x70, 0x73, // [1] "ops"
		0x29, op, // [2]
	}
}

// buildLSOServiceBodyExtendedSource uses an extended-length
// CharacterString for [1] requestingSource (length > 4).
func buildLSOServiceBodyExtendedSource(op uint8) []byte {
	// "operator-12345" = 14 chars, +1 encoding byte = 15
	src := []byte("operator-12345")
	body := []byte{
		0x09, 0x01, // [0] processID = 1
		0x1D, 0x0F, 0x00, // [1] extended length 15, encoding ANSI
	}
	body = append(body, src...)
	body = append(body, 0x29, op)
	return body
}

func TestParseLifeSafetyOperation_HappyPath(t *testing.T) {
	cases := map[string]uint8{
		"silence":   bwire.LSOOpSilence,
		"reset":     bwire.LSOOpReset,
		"unsilence": bwire.LSOOpUnsilence,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			body := buildLSOServiceBody(1, want)
			got, ok := bwire.ParseLifeSafetyOperation(body)
			if !ok {
				t.Fatal("expected ok=true")
			}
			if got != want {
				t.Errorf("op = %d, want %d", got, want)
			}
		})
	}
}

func TestParseLifeSafetyOperation_LongerProcessID(t *testing.T) {
	body := buildLSOServiceBodyLongerProcessID(0x1234, bwire.LSOOpReset)
	op, ok := bwire.ParseLifeSafetyOperation(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if op != bwire.LSOOpReset {
		t.Errorf("op = %d, want %d (reset)", op, bwire.LSOOpReset)
	}
}

func TestParseLifeSafetyOperation_ExtendedLengthSource(t *testing.T) {
	body := buildLSOServiceBodyExtendedSource(bwire.LSOOpUnsilence)
	op, ok := bwire.ParseLifeSafetyOperation(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if op != bwire.LSOOpUnsilence {
		t.Errorf("op = %d, want %d (unsilence)", op, bwire.LSOOpUnsilence)
	}
}

func TestParseLifeSafetyOperation_TruncatedFails(t *testing.T) {
	body := buildLSOServiceBody(1, bwire.LSOOpSilence)
	_, ok := bwire.ParseLifeSafetyOperation(body[:5])
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

func TestParseLifeSafetyOperation_WrongTagFails(t *testing.T) {
	body := buildLSOServiceBody(1, bwire.LSOOpSilence)
	body[0] = 0x19 // looks like context-1 length-1 — wrong context for processID
	_, ok := bwire.ParseLifeSafetyOperation(body)
	if ok {
		t.Fatal("wrong tag byte should return ok=false")
	}
}

func TestParseLifeSafetyOperation_OutOfRangeOpFails(t *testing.T) {
	body := buildLSOServiceBody(1, 99) // outside ASHRAE 135-2020 range
	_, ok := bwire.ParseLifeSafetyOperation(body)
	if ok {
		t.Fatal("unknown enum value should return ok=false (fail-closed)")
	}
}

// ---- E2E gate: LifeSafetyOperation --------------------------

// driveLSOSession boots a gated handler with svc 27 + per-op
// allowlist.
func driveLSOSession(t *testing.T, lso []bwrite.AllowedLSOOperation) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "fire.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedLSOOperations: lso,
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithLSOOps(target, bwrite.Allowlists{
		Services:      svcs,
		LSOOperations: lso,
	})
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h.SessionConfirm = confirm.Confirm{
		AcceptsWrites: true,
		ConfirmTarget: target,
		ConfirmToken:  tok,
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
	return clientIn, rec
}

// buildLSOFrame wraps a LSO request body in a BVLC + NPDU +
// APDU frame.
func buildLSOFrame(op uint8) []byte {
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		byte(bwire.ConfirmedSvcLifeSafetyOperation),
	}
	apdu = append(apdu, buildLSOServiceBody(1, op)...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetLSO_AllowedOpPasses — LSO for an allowlisted
// operation forwards.
func TestGateBACnetLSO_AllowedOpPasses(t *testing.T) {
	lso := []bwrite.AllowedLSOOperation{{Operation: bwire.LSOOpUnsilence}}
	client, upstream := driveLSOSession(t, lso)
	frame := buildLSOFrame(bwire.LSOOpUnsilence)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for allowed LSO unsilence")
	}
}

// TestGateBACnetLSO_SilenceRefused — silence (1) MUST refuse
// when only unsilence is allowed. This is the canonical
// life-safety invariant: an attacker cannot silence a fire
// alarm panel.
func TestGateBACnetLSO_SilenceRefused(t *testing.T) {
	lso := []bwrite.AllowedLSOOperation{{Operation: bwire.LSOOpUnsilence}}
	client, upstream := driveLSOSession(t, lso)
	frame := buildLSOFrame(bwire.LSOOpSilence)
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, err := client.Read(rbuf)
	if err != nil {
		t.Fatalf("read abort: %v", err)
	}
	if n < 4 || rbuf[0] != bwire.BVLCTypeBacnetIP {
		t.Fatalf("expected BVLC abort frame, got % x", rbuf[:16])
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw %d frames for forbidden silence operation", len(snap))
	}
}

// TestGateBACnetLSO_AllSilenceVariantsRefused — silence,
// silence-audible, silence-visual all refuse when the policy
// is recovery-only (unsilence-family allowed).
func TestGateBACnetLSO_AllSilenceVariantsRefused(t *testing.T) {
	lso := []bwrite.AllowedLSOOperation{
		{Operation: bwire.LSOOpUnsilence},
		{Operation: bwire.LSOOpUnsilenceAudible},
		{Operation: bwire.LSOOpUnsilenceVisual},
	}
	for _, op := range []uint8{
		bwire.LSOOpSilence,
		bwire.LSOOpSilenceAudible,
		bwire.LSOOpSilenceVisual,
	} {
		client, upstream := driveLSOSession(t, lso)
		frame := buildLSOFrame(op)
		_, _ = client.Write(frame)
		_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		rbuf := make([]byte, 256)
		n, _ := client.Read(rbuf)
		if n == 0 {
			t.Fatalf("op %d: expected abort refusal", op)
		}
		time.Sleep(50 * time.Millisecond)
		if snap := upstream.snapshot(); len(snap) != 0 {
			t.Fatalf("op %d: upstream should not see silence variant", op)
		}
	}
}

// TestGateBACnetLSO_EmptyAllowlistBypasses — empty
// AllowedLSOOperations list bypasses the per-op gate (svc 27
// still passes service-only).
func TestGateBACnetLSO_EmptyAllowlistBypasses(t *testing.T) {
	client, upstream := driveLSOSession(t, nil)
	// Even silence should pass when the per-op gate is empty.
	frame := buildLSOFrame(bwire.LSOOpSilence)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("empty allowlist should bypass per-LSO-op check")
	}
}

// TestGateBACnetLSO_ResetAndUnsilenceMix — operator allows
// reset (4) + unsilence (7) — both pass; silence (1) refuses.
func TestGateBACnetLSO_ResetAndUnsilenceMix(t *testing.T) {
	lso := []bwrite.AllowedLSOOperation{
		{Operation: bwire.LSOOpReset},
		{Operation: bwire.LSOOpUnsilence},
	}
	for _, op := range []uint8{bwire.LSOOpReset, bwire.LSOOpUnsilence} {
		client, upstream := driveLSOSession(t, lso)
		frame := buildLSOFrame(op)
		_, _ = client.Write(frame)
		frames := waitForFramesOne(t, upstream)
		if len(frames) == 0 {
			t.Fatalf("op %d should pass", op)
		}
	}
}
