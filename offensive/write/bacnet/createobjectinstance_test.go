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

// ---- Hash ladder: per-(type, instance) variant degrades -------

// TestAllowlistHashWithCreateObjectInstances_EmptyMatchesV13Chunk13
// — the v1.16 chunk-2 hash with empty CreateObjectInstances
// must equal the v1.13 chunk-13 hash. Backwards-compat ladder
// step 1.
func TestAllowlistHashWithCreateObjectInstances_EmptyMatchesV13Chunk13(t *testing.T) {
	target := "bms.test:47808"
	al := bwrite.Allowlists{
		Services: []bwrite.AllowedService{{ServiceChoice: 10}},
		ListElements: []bwrite.AllowedListElement{
			{ObjectType: 15, ObjectInstance: 7, PropertyID: 102},
		},
	}
	hPrev := bwrite.AllowlistHashWithListElements(target, al)
	hNew := bwrite.AllowlistHashWithCreateObjectInstances(target, al)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-2 hash with empty CreateObjectInstances must equal chunk-13 hash:\n%x\n%x", hNew, hPrev)
	}
}

// TestAllowlistHashWithCreateObjectInstances_NonEmptyChangesHash
// — adding a per-(type, instance) entry must perturb the hash.
func TestAllowlistHashWithCreateObjectInstances_NonEmptyChangesHash(t *testing.T) {
	target := "bms.test:47808"
	base := bwrite.Allowlists{
		Services: []bwrite.AllowedService{{ServiceChoice: 10}},
	}
	hPrev := bwrite.AllowlistHashWithCreateObjectInstances(target, base)

	withInstance := base
	withInstance.CreateObjectInstances = []bwrite.AllowedCreateObjectInstance{
		{ObjectType: 17, ObjectInstance: 42},
	}
	hNew := bwrite.AllowlistHashWithCreateObjectInstances(target, withInstance)
	if bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatal("chunk-2 hash with non-empty CreateObjectInstances must differ from base")
	}
}

// TestAllowlistHashWithCreateObjectInstances_OrderInsensitive — hash
// is stable across different CLI input orders.
func TestAllowlistHashWithCreateObjectInstances_OrderInsensitive(t *testing.T) {
	target := "bms.test:47808"
	base := bwrite.Allowlists{
		Services: []bwrite.AllowedService{{ServiceChoice: 10}},
	}
	a := base
	a.CreateObjectInstances = []bwrite.AllowedCreateObjectInstance{
		{ObjectType: 17, ObjectInstance: 42},
		{ObjectType: 19, ObjectInstance: 7},
	}
	b := base
	b.CreateObjectInstances = []bwrite.AllowedCreateObjectInstance{
		{ObjectType: 19, ObjectInstance: 7},
		{ObjectType: 17, ObjectInstance: 42},
	}
	h1 := bwrite.AllowlistHashWithCreateObjectInstances(target, a)
	h2 := bwrite.AllowlistHashWithCreateObjectInstances(target, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on CreateObjectInstances input order")
	}
}

// ---- Wire parser: ParseCreateObjectWithInstance ---------------

// TestParseCreateObjectWithInstance_ChoiceObjectTypeNoInstance —
// CHOICE [0] returns hasInstance=false, instance=0.
func TestParseCreateObjectWithInstance_ChoiceObjectTypeNoInstance(t *testing.T) {
	body := buildCreateObjectChoiceObjectType(17)
	objType, instance, hasInstance, ok := bwire.ParseCreateObjectWithInstance(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if objType != 17 {
		t.Errorf("objType = %d, want 17", objType)
	}
	if hasInstance {
		t.Error("hasInstance = true; want false for CHOICE [0]")
	}
	if instance != 0 {
		t.Errorf("instance = %d, want 0 for CHOICE [0]", instance)
	}
}

// TestParseCreateObjectWithInstance_ChoiceObjectIdentifierExtractsInstance
// — CHOICE [1] returns the instance from the packed
// ObjectIdentifier.
func TestParseCreateObjectWithInstance_ChoiceObjectIdentifierExtractsInstance(t *testing.T) {
	body := buildCreateObjectChoiceObjectIdentifier(19, 4096) // MultiStateValue#4096
	objType, instance, hasInstance, ok := bwire.ParseCreateObjectWithInstance(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if objType != 19 {
		t.Errorf("objType = %d, want 19", objType)
	}
	if !hasInstance {
		t.Error("hasInstance = false; want true for CHOICE [1]")
	}
	if instance != 4096 {
		t.Errorf("instance = %d, want 4096", instance)
	}
}

// TestParseCreateObjectWithInstance_LargestInstance — boundary
// test: 22-bit max instance value (4194303).
func TestParseCreateObjectWithInstance_LargestInstance(t *testing.T) {
	body := buildCreateObjectChoiceObjectIdentifier(17, 0x3FFFFF)
	objType, instance, hasInstance, ok := bwire.ParseCreateObjectWithInstance(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if objType != 17 || instance != 0x3FFFFF || !hasInstance {
		t.Errorf("got (%d, %d, %v), want (17, 4194303, true)", objType, instance, hasInstance)
	}
}

// ---- E2E gate: per-(type, instance) CreateObject --------------

// driveCreateObjectInstanceSession mirrors driveCreateObjectSession
// but seeds the chunk-2 per-(type, instance) allowlist (and
// optionally the chunk-8 per-type list as a fallback).
func driveCreateObjectInstanceSession(t *testing.T, types []bwrite.AllowedCreateObject, instances []bwrite.AllowedCreateObjectInstance) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 10}}
	h := &bwrite.WriteGatedHandler{
		Target:                       target,
		Allowed:                      svcs,
		AllowedCreateObjects:         types,
		AllowedCreateObjectInstances: instances,
		Deriver:                      &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:                      &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithCreateObjectInstances(target, bwrite.Allowlists{
		Services:              svcs,
		CreateObjects:         types,
		CreateObjectInstances: instances,
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

// TestGateBACnetCreate_PerInstance_AllowedExactPasses — operator
// declares (type=17, instance=42); ACS sends CHOICE [1] with
// matching tuple → forwards.
func TestGateBACnetCreate_PerInstance_AllowedExactPasses(t *testing.T) {
	instances := []bwrite.AllowedCreateObjectInstance{{ObjectType: 17, ObjectInstance: 42}}
	client, upstream := driveCreateObjectInstanceSession(t, nil, instances)
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectIdentifier(17, 42))
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for exact (type, instance) match")
	}
}

// TestGateBACnetCreate_PerInstance_DifferentInstanceRefuses — same
// type but a different instance → refused.
func TestGateBACnetCreate_PerInstance_DifferentInstanceRefuses(t *testing.T) {
	instances := []bwrite.AllowedCreateObjectInstance{{ObjectType: 17, ObjectInstance: 42}}
	client, upstream := driveCreateObjectInstanceSession(t, nil, instances)
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectIdentifier(17, 99)) // wrong instance
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

// TestGateBACnetCreate_PerInstance_ChoiceObjectTypeRefusesWhenOnlyInstancesSet
// — operator opted in to per-instance scoping (only
// CreateObjectInstances populated, no CreateObjects fallback);
// CHOICE [0] (type-only) carries no instance to match against
// → refused. Failure mode chosen because the operator's intent
// is "explicit instance control".
func TestGateBACnetCreate_PerInstance_ChoiceObjectTypeRefusesWhenOnlyInstancesSet(t *testing.T) {
	instances := []bwrite.AllowedCreateObjectInstance{{ObjectType: 17, ObjectInstance: 42}}
	client, upstream := driveCreateObjectInstanceSession(t, nil, instances)
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectType(17)) // CHOICE [0]
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := client.Read(rbuf)
	if n < 4 || rbuf[0] != bwire.BVLCTypeBacnetIP {
		t.Fatalf("expected BVLC abort frame, got % x", rbuf[:16])
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw %d frames for CHOICE [0] with only per-instance allowlist", len(snap))
	}
}

// TestGateBACnetCreate_PerInstance_FallbackToTypeList — operator
// mixes both lists: per-instance for fine control + per-type
// as fallback. CHOICE [0] with type=17 falls back to per-type
// list (which has 17) → forwards.
func TestGateBACnetCreate_PerInstance_FallbackToTypeList(t *testing.T) {
	types := []bwrite.AllowedCreateObject{{ObjectType: 17}}
	instances := []bwrite.AllowedCreateObjectInstance{{ObjectType: 17, ObjectInstance: 42}}
	client, upstream := driveCreateObjectInstanceSession(t, types, instances)

	// CHOICE [0] type=17 — per-type list passes.
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectType(17))
	_, _ = client.Write(frame)
	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for CHOICE [0] with mixed-list fallback")
	}
}

// TestGateBACnetCreate_PerInstance_TypeMismatchRefuses — even
// when AllowedCreateObjectInstances has (17, 42), a CHOICE [1]
// request with type=8 (Device) refuses (type doesn't match
// any list entry).
func TestGateBACnetCreate_PerInstance_TypeMismatchRefuses(t *testing.T) {
	instances := []bwrite.AllowedCreateObjectInstance{{ObjectType: 17, ObjectInstance: 42}}
	client, upstream := driveCreateObjectInstanceSession(t, nil, instances)
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectIdentifier(8, 42))
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := client.Read(rbuf)
	if n < 4 || rbuf[0] != bwire.BVLCTypeBacnetIP {
		t.Fatalf("expected BVLC abort frame, got % x", rbuf[:16])
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw %d frames for type-mismatch", len(snap))
	}
}
