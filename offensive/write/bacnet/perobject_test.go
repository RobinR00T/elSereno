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

// ---- Hash ladder: per-object variant degrades to v1.4 -----

func TestAllowlistHashWithObjects_EmptyMatchesV14(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 15}}
	h14 := bwrite.AllowlistHash("bms:47808", svcs)
	h12 := bwrite.AllowlistHashWithObjects("bms:47808", svcs, nil)
	if !bytes.Equal(h14[:], h12[:]) {
		t.Fatalf("v1.12 hash with empty objects differs from v1.4: %x vs %x", h12, h14)
	}
}

func TestAllowlistHashWithObjects_NonEmptyChangesHash(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 15}}
	objs := []bwrite.AllowedObject{{ObjectType: 0, ObjectInstance: 42, PropertyID: 85}}
	h14 := bwrite.AllowlistHash("bms:47808", svcs)
	h12 := bwrite.AllowlistHashWithObjects("bms:47808", svcs, objs)
	if bytes.Equal(h14[:], h12[:]) {
		t.Fatal("v1.12 hash with non-empty objects must differ from v1.4")
	}
}

func TestAllowlistHashWithObjects_OrderInsensitive(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 15}}
	a := []bwrite.AllowedObject{
		{ObjectType: 0, ObjectInstance: 42, PropertyID: 85},
		{ObjectType: 2, ObjectInstance: 3, PropertyID: 85},
	}
	b := []bwrite.AllowedObject{
		{ObjectType: 2, ObjectInstance: 3, PropertyID: 85},
		{ObjectType: 0, ObjectInstance: 42, PropertyID: 85},
	}
	h1 := bwrite.AllowlistHashWithObjects("bms:47808", svcs, a)
	h2 := bwrite.AllowlistHashWithObjects("bms:47808", svcs, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on object input order")
	}
}

func TestAllowlistHashWithObjects_DistinctTuplesDiffer(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 15}}
	a := []bwrite.AllowedObject{{ObjectType: 0, ObjectInstance: 42, PropertyID: 85}}
	b := []bwrite.AllowedObject{{ObjectType: 0, ObjectInstance: 42, PropertyID: 86}}
	h1 := bwrite.AllowlistHashWithObjects("bms:47808", svcs, a)
	h2 := bwrite.AllowlistHashWithObjects("bms:47808", svcs, b)
	if bytes.Equal(h1[:], h2[:]) {
		t.Fatal("different PropertyID should produce different hash")
	}
}

// ---- BER parser: ParseWriteProperty ------------------------

// buildWritePropertyServiceBody crafts the WriteProperty service-
// request body (AFTER the 4-byte confirmed-request header) for a
// given (type, instance, property) tuple.
func buildWritePropertyServiceBody(objType uint16, objInst uint32, propID uint32) []byte {
	buf := make([]byte, 0, 32)
	// Tag 0: BACnetObjectIdentifier (context tag 0, length 4).
	//nolint:gosec // G115 — test constants are 10+22 bit bounded.
	packed := (uint32(objType) << 22) | (objInst & 0x3FFFFF)
	buf = append(buf, 0x0C)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], packed)
	buf = append(buf, u32[:]...)
	// Tag 1: PropertyIdentifier (context tag 1, length 1..3).
	switch {
	case propID < 256:
		buf = append(buf, 0x19, byte(propID))
	case propID < 65536:
		buf = append(buf, 0x1A, byte(propID>>8&0xFF), byte(propID&0xFF)) //nolint:gosec // G115 — bytes intentionally truncated
	default:
		buf = append(buf, 0x1B, byte(propID>>16&0xFF), byte(propID>>8&0xFF), byte(propID&0xFF)) //nolint:gosec // G115 — bytes intentionally truncated
	}
	// Tag 3 opening + Null value (application tag 0, length 0) +
	// Tag 3 closing.
	buf = append(buf, 0x3E, 0x00, 0x3F)
	return buf
}

func TestParseWriteProperty_HappyPath(t *testing.T) {
	body := buildWritePropertyServiceBody(0, 42, 85) // AnalogInput#42.PresentValue
	target, ok := bwire.ParseWriteProperty(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if target.ObjectType != 0 || target.ObjectInstance != 42 || target.PropertyID != 85 {
		t.Errorf("target = %+v, want {0, 42, 85}", target)
	}
}

func TestParseWriteProperty_MultiBytePropertyID(t *testing.T) {
	body := buildWritePropertyServiceBody(2, 3, 1024)
	target, ok := bwire.ParseWriteProperty(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if target.PropertyID != 1024 {
		t.Errorf("PropertyID = %d, want 1024", target.PropertyID)
	}
}

func TestParseWriteProperty_TruncatedFails(t *testing.T) {
	body := buildWritePropertyServiceBody(0, 42, 85)
	_, ok := bwire.ParseWriteProperty(body[:4]) // mid-ObjectId
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

func TestParseWriteProperty_WrongTagFails(t *testing.T) {
	body := buildWritePropertyServiceBody(0, 42, 85)
	body[0] = 0x08
	_, ok := bwire.ParseWriteProperty(body)
	if ok {
		t.Fatal("wrong tag byte should return ok=false")
	}
}

// ---- E2E gate tests ----------------------------------------

// drivePerObjectSession wires client ↔ handler ↔ upstream via
// net.Pipe, authorised with the per-object allowlist on top of
// service 15.
func drivePerObjectSession(t *testing.T, svcs []bwrite.AllowedService, objs []bwrite.AllowedObject) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
	h := &bwrite.WriteGatedHandler{
		Target:         target,
		Allowed:        svcs,
		AllowedObjects: objs,
		Deriver:        &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:        &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithObjects(target, svcs, objs)
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

// buildWritePropertyFrame builds a full BVLC + NPDU + APDU
// frame carrying a WriteProperty confirmed-request. The
// invoke-id is fixed at 1 — tests don't multiplex pending
// requests.
func buildWritePropertyFrame(objType uint16, objInst uint32, propID uint32) []byte {
	service := buildWritePropertyServiceBody(objType, objInst, propID)
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		byte(bwire.ConfirmedSvcWriteProperty),
	}
	apdu = append(apdu, service...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetPerObject_AllowedPasses — WriteProperty to an
// allowlisted (type, instance, property) tuple forwards.
func TestGateBACnetPerObject_AllowedPasses(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 15}}
	objs := []bwrite.AllowedObject{
		{ObjectType: 0, ObjectInstance: 42, PropertyID: 85},
	}
	client, upstream := drivePerObjectSession(t, svcs, objs)

	frame := buildWritePropertyFrame(0, 42, 85)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for allowed WriteProperty")
	}
}

// TestGateBACnetPerObject_ForbiddenRefuses — WriteProperty to a
// non-allowlisted tuple gets an Abort-PDU refusal.
func TestGateBACnetPerObject_ForbiddenRefuses(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 15}}
	objs := []bwrite.AllowedObject{
		{ObjectType: 0, ObjectInstance: 42, PropertyID: 85},
	}
	client, upstream := drivePerObjectSession(t, svcs, objs)

	// Forbidden: different property.
	frame := buildWritePropertyFrame(0, 42, 86)
	_, _ = client.Write(frame)

	// Client should see the Abort-PDU refusal.
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
		t.Fatalf("upstream saw %d frames for forbidden WriteProperty", len(snap))
	}
}

// TestGateBACnetPerObject_ForbiddenType — different ObjectType
// (not just property).
func TestGateBACnetPerObject_ForbiddenType(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 15}}
	objs := []bwrite.AllowedObject{
		{ObjectType: 0, ObjectInstance: 42, PropertyID: 85}, // AnalogInput
	}
	client, upstream := drivePerObjectSession(t, svcs, objs)

	frame := buildWritePropertyFrame(2, 42, 85) // BinaryOutput instead
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := client.Read(rbuf)
	if n == 0 {
		t.Fatal("expected abort refusal")
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatal("upstream should not see WriteProperty with wrong ObjectType")
	}
}

// TestGateBACnetPerObject_EmptyAllowlistBypasses — with an empty
// AllowedObjects list, WriteProperty falls back to the v1.4
// service-only gate and passes freely.
func TestGateBACnetPerObject_EmptyAllowlistBypasses(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 15}}
	client, upstream := drivePerObjectSession(t, svcs, nil)

	// Any (type, instance, property) passes.
	frame := buildWritePropertyFrame(7, 999, 99)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing — empty allowlist should bypass per-object check")
	}
}
