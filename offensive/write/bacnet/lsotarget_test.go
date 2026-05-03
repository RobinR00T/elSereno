//go:build offensive

package bacnet_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	bwire "local/elsereno/internal/protocols/bacnet/wire"
	"local/elsereno/offensive/confirm"
	bwrite "local/elsereno/offensive/write/bacnet"
)

// ---- Hash ladder: per-(op, type, instance) variant degrades --

// TestAllowlistHashWithLSOTargets_EmptyMatchesV16Chunk2 — the
// v1.16 chunk-3 hash with empty LSOTargets must equal the v1.16
// chunk-2 hash. Backwards-compat ladder step 1.
func TestAllowlistHashWithLSOTargets_EmptyMatchesV16Chunk2(t *testing.T) {
	target := "bms.test:47808"
	al := bwrite.Allowlists{
		Services: []bwrite.AllowedService{{ServiceChoice: 27}},
		LSOOperations: []bwrite.AllowedLSOOperation{
			{Operation: bwire.LSOOpUnsilence},
		},
	}
	hPrev := bwrite.AllowlistHashWithCreateObjectInstances(target, al)
	hNew := bwrite.AllowlistHashWithLSOTargets(target, al)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-3 hash with empty LSOTargets must equal chunk-2 hash:\n%x\n%x", hNew, hPrev)
	}
}

// TestAllowlistHashWithLSOTargets_NonEmptyChangesHash — adding
// a per-target entry must perturb the hash.
func TestAllowlistHashWithLSOTargets_NonEmptyChangesHash(t *testing.T) {
	target := "bms.test:47808"
	base := bwrite.Allowlists{
		Services: []bwrite.AllowedService{{ServiceChoice: 27}},
	}
	hPrev := bwrite.AllowlistHashWithLSOTargets(target, base)

	withTarget := base
	withTarget.LSOTargets = []bwrite.AllowedLSOTarget{
		{Operation: 7, ObjectType: 21, ObjectInstance: 3},
	}
	hNew := bwrite.AllowlistHashWithLSOTargets(target, withTarget)
	if bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatal("chunk-3 hash with non-empty LSOTargets must differ from base")
	}
}

// TestAllowlistHashWithLSOTargets_OrderInsensitive — hash is
// stable across different CLI input orders.
func TestAllowlistHashWithLSOTargets_OrderInsensitive(t *testing.T) {
	target := "bms.test:47808"
	base := bwrite.Allowlists{
		Services: []bwrite.AllowedService{{ServiceChoice: 27}},
	}
	a := base
	a.LSOTargets = []bwrite.AllowedLSOTarget{
		{Operation: 7, ObjectType: 21, ObjectInstance: 3},
		{Operation: 4, ObjectType: 21, ObjectInstance: 3},
	}
	b := base
	b.LSOTargets = []bwrite.AllowedLSOTarget{
		{Operation: 4, ObjectType: 21, ObjectInstance: 3},
		{Operation: 7, ObjectType: 21, ObjectInstance: 3},
	}
	h1 := bwrite.AllowlistHashWithLSOTargets(target, a)
	h2 := bwrite.AllowlistHashWithLSOTargets(target, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on LSOTargets input order")
	}
}

// ---- Wire parser: ParseLifeSafetyOperationWithTarget ----------

// buildLSOWithTarget crafts an LSO confirmed-request body with
// the optional [3] objectIdentifier filled in. Mirrors the
// existing buildLifeSafetyOperationBody helper but adds the [3]
// field.
//
//nolint:unparam // tests in this file converge on type=21 (LifeSafetyPoint) by domain — the parameter is kept for clarity at call sites + potential future tests on other LSO-bearing types.
func buildLSOWithTarget(op uint8, objType uint16, objInst uint32) []byte {
	// [0] requestingProcessIdentifier — ASN.1 BER context-0 length-1
	body := []byte{0x09, 0x01}
	// [1] requestingSource — ASN.1 BER context-1 length-1 (single byte)
	body = append(body, 0x19, byte('A'))
	// [2] request — ENUMERATED, length 1
	body = append(body, 0x29, op)
	// [3] objectIdentifier — context 3, primitive, length 4 packed
	// #nosec G115 -- test-bounded — type fits in 10 bits, instance in 22.
	packed := (uint32(objType) << 22) | (objInst & 0x3FFFFF)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], packed)
	body = append(body, 0x3C)
	body = append(body, u32[:]...)
	return body
}

// buildLSOWithoutTarget is the same as buildLSOWithTarget minus
// the [3] field (device-wide LSO).
func buildLSOWithoutTarget(op uint8) []byte {
	body := []byte{0x09, 0x01}
	body = append(body, 0x19, byte('A'))
	body = append(body, 0x29, op)
	return body
}

func TestParseLifeSafetyOperationWithTarget_HasTarget(t *testing.T) {
	body := buildLSOWithTarget(bwire.LSOOpUnsilence, 21, 3) // LifeSafetyPoint#3 unsilence
	op, target, hasTarget, ok := bwire.ParseLifeSafetyOperationWithTarget(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !hasTarget {
		t.Error("hasTarget = false; want true for [3]-bearing request")
	}
	if op != bwire.LSOOpUnsilence {
		t.Errorf("op = %d, want %d", op, bwire.LSOOpUnsilence)
	}
	if target.ObjectType != 21 || target.ObjectInstance != 3 {
		t.Errorf("target = (%d, %d), want (21, 3)", target.ObjectType, target.ObjectInstance)
	}
}

func TestParseLifeSafetyOperationWithTarget_NoTarget(t *testing.T) {
	body := buildLSOWithoutTarget(bwire.LSOOpUnsilence)
	op, _, hasTarget, ok := bwire.ParseLifeSafetyOperationWithTarget(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if hasTarget {
		t.Error("hasTarget = true; want false for absent [3]")
	}
	if op != bwire.LSOOpUnsilence {
		t.Errorf("op = %d, want %d", op, bwire.LSOOpUnsilence)
	}
}

// TestParseLifeSafetyOperation_BackwardsCompat — the older
// thin-wrapper Parse function must still work for callers that
// don't care about the target.
func TestParseLifeSafetyOperation_BackwardsCompat(t *testing.T) {
	body := buildLSOWithTarget(bwire.LSOOpUnsilence, 21, 3)
	op, ok := bwire.ParseLifeSafetyOperation(body)
	if !ok || op != bwire.LSOOpUnsilence {
		t.Errorf("ParseLifeSafetyOperation = (%d, %v), want (%d, true)", op, ok, bwire.LSOOpUnsilence)
	}
}

// ---- E2E gate: per-(op, type, instance) LSO -------------------

// driveLSOTargetSession boots a gated handler with svc 27 + the
// supplied per-op + per-target lists.
func driveLSOTargetSession(t *testing.T, ops []bwrite.AllowedLSOOperation, targets []bwrite.AllowedLSOTarget) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 27}}
	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedLSOOperations: ops,
		AllowedLSOTargets:    targets,
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithLSOTargets(target, bwrite.Allowlists{
		Services:      svcs,
		LSOOperations: ops,
		LSOTargets:    targets,
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

// buildLSOFrameFromBody wraps an arbitrary LSO request body in
// BVLC + NPDU + APDU. Unlike buildLSOFrame (which takes an op
// enum and constructs the body internally), this lets the
// chunk-3 tests inject the optional [3] objectIdentifier.
func buildLSOFrameFromBody(body []byte) []byte {
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		byte(bwire.ConfirmedSvcLifeSafetyOperation),
	}
	apdu = append(apdu, body...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetLSO_PerTargetExactPasses — operator declares
// (op=Unsilence, type=21, instance=3); ACS sends matching
// request → forwards.
func TestGateBACnetLSO_PerTargetExactPasses(t *testing.T) {
	targets := []bwrite.AllowedLSOTarget{{Operation: bwire.LSOOpUnsilence, ObjectType: 21, ObjectInstance: 3}}
	client, upstream := driveLSOTargetSession(t, nil, targets)
	frame := buildLSOFrameFromBody(buildLSOWithTarget(bwire.LSOOpUnsilence, 21, 3))
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for exact (op, type, instance) match")
	}
}

// TestGateBACnetLSO_PerTargetDifferentInstanceRefuses — same
// op + type but different instance → refused.
func TestGateBACnetLSO_PerTargetDifferentInstanceRefuses(t *testing.T) {
	targets := []bwrite.AllowedLSOTarget{{Operation: bwire.LSOOpUnsilence, ObjectType: 21, ObjectInstance: 3}}
	client, upstream := driveLSOTargetSession(t, nil, targets)
	frame := buildLSOFrameFromBody(buildLSOWithTarget(bwire.LSOOpUnsilence, 21, 99))
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
		t.Fatalf("upstream saw %d frames for non-matching instance", len(snap))
	}
}

// TestGateBACnetLSO_PerTarget_DeviceWideRefusesWhenOnlyTargetsSet
// — operator opted into per-target scoping (only LSOTargets, no
// LSOOperations); device-wide LSO (no [3]) → refused.
func TestGateBACnetLSO_PerTarget_DeviceWideRefusesWhenOnlyTargetsSet(t *testing.T) {
	targets := []bwrite.AllowedLSOTarget{{Operation: bwire.LSOOpUnsilence, ObjectType: 21, ObjectInstance: 3}}
	client, upstream := driveLSOTargetSession(t, nil, targets)
	frame := buildLSOFrameFromBody(buildLSOWithoutTarget(bwire.LSOOpUnsilence))
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := client.Read(rbuf)
	if n < 4 || rbuf[0] != bwire.BVLCTypeBacnetIP {
		t.Fatalf("expected BVLC abort frame, got % x", rbuf[:16])
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw %d frames for device-wide LSO with only per-target list", len(snap))
	}
}

// TestGateBACnetLSO_PerTargetFallbackToOpList — operator mixes
// both lists. Device-wide LSO falls back to per-op list.
func TestGateBACnetLSO_PerTargetFallbackToOpList(t *testing.T) {
	ops := []bwrite.AllowedLSOOperation{{Operation: bwire.LSOOpUnsilence}}
	targets := []bwrite.AllowedLSOTarget{{Operation: bwire.LSOOpReset, ObjectType: 21, ObjectInstance: 3}}
	client, upstream := driveLSOTargetSession(t, ops, targets)

	// Device-wide unsilence — per-op list passes.
	frame := buildLSOFrameFromBody(buildLSOWithoutTarget(bwire.LSOOpUnsilence))
	_, _ = client.Write(frame)
	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for device-wide unsilence with per-op fallback")
	}
}

// TestGateBACnetLSO_PerTarget_OpMismatchRefuses — per-target
// list has (Reset, 21, 3) but ACS sends (Silence, 21, 3) →
// refused (op mismatch).
func TestGateBACnetLSO_PerTarget_OpMismatchRefuses(t *testing.T) {
	targets := []bwrite.AllowedLSOTarget{{Operation: bwire.LSOOpReset, ObjectType: 21, ObjectInstance: 3}}
	client, upstream := driveLSOTargetSession(t, nil, targets)
	frame := buildLSOFrameFromBody(buildLSOWithTarget(bwire.LSOOpSilence, 21, 3)) // wrong op (and HOSTILE — silencing)
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := client.Read(rbuf)
	if n < 4 || rbuf[0] != bwire.BVLCTypeBacnetIP {
		t.Fatalf("expected BVLC abort frame, got % x", rbuf[:16])
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw %d frames for op-mismatch (HOSTILE silence attempted on Reset-only target)", len(snap))
	}
}
