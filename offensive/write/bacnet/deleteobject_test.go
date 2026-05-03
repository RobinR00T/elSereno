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

// ---- Hash ladder: per-delete-object variant degrades --------

func TestAllowlistHashWithDeleteObjects_EmptyMatchesV12(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 11}}
	objs := []bwrite.AllowedObject{{ObjectType: 0, ObjectInstance: 42, PropertyID: 85}}
	h12 := bwrite.AllowlistHashWithObjects("bms:47808", svcs, objs)
	h13 := bwrite.AllowlistHashWithDeleteObjects("bms:47808", svcs, objs, nil)
	if !bytes.Equal(h12[:], h13[:]) {
		t.Fatalf("v1.13 hash with empty deleteObjects differs from v1.12: %x vs %x", h13, h12)
	}
}

func TestAllowlistHashWithDeleteObjects_EmptyAllMatchesV14(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 11}}
	h14 := bwrite.AllowlistHash("bms:47808", svcs)
	h13 := bwrite.AllowlistHashWithDeleteObjects("bms:47808", svcs, nil, nil)
	if !bytes.Equal(h14[:], h13[:]) {
		t.Fatalf("v1.13 hash with all-empty differs from v1.4: %x vs %x", h13, h14)
	}
}

func TestAllowlistHashWithDeleteObjects_NonEmptyChangesHash(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 11}}
	dels := []bwrite.AllowedDeleteObject{{ObjectType: 2, ObjectInstance: 99}}
	h12 := bwrite.AllowlistHashWithObjects("bms:47808", svcs, nil)
	h13 := bwrite.AllowlistHashWithDeleteObjects("bms:47808", svcs, nil, dels)
	if bytes.Equal(h12[:], h13[:]) {
		t.Fatal("v1.13 hash with non-empty deleteObjects must differ from v1.12")
	}
}

func TestAllowlistHashWithDeleteObjects_OrderInsensitive(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 11}}
	a := []bwrite.AllowedDeleteObject{
		{ObjectType: 0, ObjectInstance: 42},
		{ObjectType: 2, ObjectInstance: 99},
	}
	b := []bwrite.AllowedDeleteObject{
		{ObjectType: 2, ObjectInstance: 99},
		{ObjectType: 0, ObjectInstance: 42},
	}
	h1 := bwrite.AllowlistHashWithDeleteObjects("bms:47808", svcs, nil, a)
	h2 := bwrite.AllowlistHashWithDeleteObjects("bms:47808", svcs, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on deleteObjects input order")
	}
}

// ---- Wire parser: ParseDeleteObject -------------------------

// buildDeleteObjectServiceBody crafts a DeleteObject service-
// request body (AFTER the 4-byte confirmed-request header) for
// a given (type, instance) target.
func buildDeleteObjectServiceBody(objType uint16, objInst uint32) []byte {
	buf := make([]byte, 0, 5)
	// #nosec G115 -- test-bounded — type fits in 10 bits, instance in 22.
	packed := (uint32(objType) << 22) | (objInst & 0x3FFFFF)
	buf = append(buf, 0x0C)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], packed)
	buf = append(buf, u32[:]...)
	return buf
}

func TestParseDeleteObject_HappyPath(t *testing.T) {
	body := buildDeleteObjectServiceBody(2, 99) // BinaryOutput#99
	id, ok := bwire.ParseDeleteObject(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if id.ObjectType != 2 || id.ObjectInstance != 99 {
		t.Errorf("id = %+v, want {2, 99}", id)
	}
}

func TestParseDeleteObject_TruncatedFails(t *testing.T) {
	body := buildDeleteObjectServiceBody(2, 99)
	_, ok := bwire.ParseDeleteObject(body[:3])
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

func TestParseDeleteObject_WrongTagFails(t *testing.T) {
	body := buildDeleteObjectServiceBody(2, 99)
	body[0] = 0x08 // not a context-0-len-4 tag
	_, ok := bwire.ParseDeleteObject(body)
	if ok {
		t.Fatal("wrong tag byte should return ok=false")
	}
}

// ---- E2E gate: DeleteObject -------------------------------

// driveDeleteObjectSession boots a gated handler with svc 11
// allowed + a per-target delete allowlist.
func driveDeleteObjectSession(t *testing.T, dels []bwrite.AllowedDeleteObject) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 11}}
	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedDeleteObjects: dels,
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithDeleteObjects(target, svcs, nil, dels)
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

// buildDeleteObjectFrame wraps a DeleteObject request body in a
// BVLC + NPDU + APDU frame.
func buildDeleteObjectFrame(objType uint16, objInst uint32) []byte {
	service := buildDeleteObjectServiceBody(objType, objInst)
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		byte(bwire.ConfirmedSvcDeleteObject),
	}
	apdu = append(apdu, service...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetDelete_AllowedTargetPasses — DeleteObject for an
// allowlisted (type, instance) tuple forwards.
func TestGateBACnetDelete_AllowedTargetPasses(t *testing.T) {
	dels := []bwrite.AllowedDeleteObject{
		{ObjectType: 2, ObjectInstance: 99},
	}
	client, upstream := driveDeleteObjectSession(t, dels)
	frame := buildDeleteObjectFrame(2, 99)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for allowed DeleteObject")
	}
}

// TestGateBACnetDelete_ForbiddenTargetRefuses — DeleteObject for
// a non-allowlisted target gets an Abort-PDU refusal.
func TestGateBACnetDelete_ForbiddenTargetRefuses(t *testing.T) {
	dels := []bwrite.AllowedDeleteObject{
		{ObjectType: 2, ObjectInstance: 99},
	}
	client, upstream := driveDeleteObjectSession(t, dels)
	frame := buildDeleteObjectFrame(0, 42) // AnalogInput#42 — not in list
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
		t.Fatalf("upstream saw %d frames for forbidden DeleteObject", len(snap))
	}
}

// TestGateBACnetDelete_EmptyAllowlistBypasses — empty
// AllowedDeleteObjects list bypasses the per-target gate (svc
// 11 still passes service-only).
func TestGateBACnetDelete_EmptyAllowlistBypasses(t *testing.T) {
	client, upstream := driveDeleteObjectSession(t, nil)
	frame := buildDeleteObjectFrame(7, 999)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("empty allowlist should bypass per-delete check")
	}
}

// TestGateBACnetDelete_PerObjectVsDeleteAreSeparate — proves
// that a (Type, Instance) entry in AllowedObjects (property
// list) does NOT auto-grant delete; the operator must
// explicitly add the same target to AllowedDeleteObjects.
func TestGateBACnetDelete_PerObjectVsDeleteAreSeparate(t *testing.T) {
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 11}, {ServiceChoice: 15}}
	objs := []bwrite.AllowedObject{
		// Operator allowed property writes to (2, 99). They did
		// NOT add (2, 99) to AllowedDeleteObjects, so a
		// DeleteObject on the same target must refuse.
		{ObjectType: 2, ObjectInstance: 99, PropertyID: 85},
	}
	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedObjects:       objs,
		AllowedDeleteObjects: []bwrite.AllowedDeleteObject{}, // explicitly empty
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithDeleteObjects(target, svcs, objs, nil)
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
	// With AllowedDeleteObjects empty, the delete gate is
	// disabled (bypass) — DeleteObject would PASS service-only.
	// This test specifically validates the SEPARATE semantics:
	// operator must opt INTO per-delete restriction by adding
	// at least one entry. Once they add an entry that doesn't
	// match, all unmatched targets refuse.
	h.AllowedDeleteObjects = []bwrite.AllowedDeleteObject{
		{ObjectType: 999, ObjectInstance: 0}, // dummy — (2, 99) is NOT here.
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

	frame := buildDeleteObjectFrame(2, 99) // in AllowedObjects, NOT in DeleteObjects
	_, _ = clientIn.Write(frame)

	_ = clientIn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := clientIn.Read(rbuf)
	if n == 0 {
		t.Fatal("expected abort refusal — AllowedObjects entry should NOT auto-grant delete")
	}
	time.Sleep(50 * time.Millisecond)
	if snap := rec.snapshot(); len(snap) != 0 {
		t.Fatal("upstream should not see DeleteObject when (2,99) is only in AllowedObjects, not AllowedDeleteObjects")
	}
}
