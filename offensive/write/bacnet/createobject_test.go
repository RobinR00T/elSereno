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

// ---- Hash ladder: per-create-object variant degrades --------

func TestAllowlistHashWithCreateObjects_EmptyMatchesV13Chunk7(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 10}}
	objs := []bwrite.AllowedObject{{ObjectType: 0, ObjectInstance: 42, PropertyID: 85}}
	dels := []bwrite.AllowedDeleteObject{{ObjectType: 2, ObjectInstance: 99}}
	hPrev := bwrite.AllowlistHashWithDeleteObjects("bms:47808", svcs, objs, dels)
	hNew := bwrite.AllowlistHashWithCreateObjects("bms:47808", svcs, objs, dels, nil)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-8 hash with empty createObjects must equal chunk-7 hash: %x vs %x", hNew, hPrev)
	}
}

func TestAllowlistHashWithCreateObjects_AllEmptyMatchesV4(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 10}}
	hV4 := bwrite.AllowlistHash("bms:47808", svcs)
	hNew := bwrite.AllowlistHashWithCreateObjects("bms:47808", svcs, nil, nil, nil)
	if !bytes.Equal(hV4[:], hNew[:]) {
		t.Fatalf("chunk-8 hash with all-empty must equal v1.4 hash: %x vs %x", hNew, hV4)
	}
}

func TestAllowlistHashWithCreateObjects_NonEmptyChangesHash(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 10}}
	cre := []bwrite.AllowedCreateObject{{ObjectType: 17}}
	hPrev := bwrite.AllowlistHashWithDeleteObjects("bms:47808", svcs, nil, nil)
	hNew := bwrite.AllowlistHashWithCreateObjects("bms:47808", svcs, nil, nil, cre)
	if bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatal("chunk-8 hash with non-empty createObjects must differ from chunk-7")
	}
}

func TestAllowlistHashWithCreateObjects_OrderInsensitive(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 10}}
	a := []bwrite.AllowedCreateObject{{ObjectType: 17}, {ObjectType: 19}}
	b := []bwrite.AllowedCreateObject{{ObjectType: 19}, {ObjectType: 17}}
	h1 := bwrite.AllowlistHashWithCreateObjects("bms:47808", svcs, nil, nil, a)
	h2 := bwrite.AllowlistHashWithCreateObjects("bms:47808", svcs, nil, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on createObjects input order")
	}
}

// ---- Wire parser: ParseCreateObject -------------------------

// buildCreateObjectChoiceObjectType crafts a CreateObject service-
// request body using the [0] BACnetObjectType choice form (length 1).
func buildCreateObjectChoiceObjectType(objType uint8) []byte {
	return []byte{
		0x0E,    // open context tag 0
		0x09,    // [0] objectType, length 1
		objType, // value
		0x0F,    // close context tag 0
	}
}

// buildCreateObjectChoiceObjectTypeLen2 uses length-2 encoding for
// types > 255.
func buildCreateObjectChoiceObjectTypeLen2(objType uint16) []byte {
	buf := []byte{
		0x0E, // open context tag 0
		0x0A, // [0] objectType, length 2
	}
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], objType)
	buf = append(buf, u16[:]...)
	return append(buf, 0x0F) // close context tag 0
}

// buildCreateObjectChoiceObjectIdentifier crafts the [1]
// BACnetObjectIdentifier choice form.
func buildCreateObjectChoiceObjectIdentifier(objType uint16, objInst uint32) []byte {
	buf := []byte{
		0x0E, // open context tag 0
		0x1C, // [1] objectIdentifier, length 4
	}
	//nolint:gosec // test-bounded — type fits in 10 bits, instance in 22.
	packed := (uint32(objType) << 22) | (objInst & 0x3FFFFF)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], packed)
	buf = append(buf, u32[:]...)
	return append(buf, 0x0F) // close context tag 0
}

func TestParseCreateObject_HappyPath_ObjectType(t *testing.T) {
	body := buildCreateObjectChoiceObjectType(17) // Schedule
	objType, ok := bwire.ParseCreateObject(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if objType != 17 {
		t.Errorf("objType = %d, want 17", objType)
	}
}

func TestParseCreateObject_HappyPath_ObjectTypeLen2(t *testing.T) {
	body := buildCreateObjectChoiceObjectTypeLen2(300) // proprietary type
	objType, ok := bwire.ParseCreateObject(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if objType != 300 {
		t.Errorf("objType = %d, want 300", objType)
	}
}

func TestParseCreateObject_HappyPath_ObjectIdentifier(t *testing.T) {
	body := buildCreateObjectChoiceObjectIdentifier(17, 42)
	objType, ok := bwire.ParseCreateObject(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if objType != 17 {
		t.Errorf("objType = %d (instance ignored at gate), want 17", objType)
	}
}

func TestParseCreateObject_TruncatedFails(t *testing.T) {
	body := buildCreateObjectChoiceObjectType(17)
	_, ok := bwire.ParseCreateObject(body[:2])
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

func TestParseCreateObject_MissingOpenTagFails(t *testing.T) {
	body := buildCreateObjectChoiceObjectType(17)
	body[0] = 0x09 // looks like a primitive context-0 length-1
	_, ok := bwire.ParseCreateObject(body)
	if ok {
		t.Fatal("missing 0x0E open tag should return ok=false")
	}
}

func TestParseCreateObject_MissingCloseTagFails(t *testing.T) {
	body := buildCreateObjectChoiceObjectType(17)
	body[3] = 0x07 // not the 0x0F close
	_, ok := bwire.ParseCreateObject(body)
	if ok {
		t.Fatal("missing 0x0F close tag should return ok=false")
	}
}

func TestParseCreateObject_UnknownChoiceFails(t *testing.T) {
	body := []byte{
		0x0E, // open
		0x39, // unknown context tag (3)
		0x42, // value byte
		0x0F, // close
	}
	_, ok := bwire.ParseCreateObject(body)
	if ok {
		t.Fatal("unknown CHOICE tag should return ok=false")
	}
}

// ---- E2E gate: CreateObject ----------------------------------

// driveCreateObjectSession boots a gated handler with svc 10 +
// per-type allowlist.
func driveCreateObjectSession(t *testing.T, cre []bwrite.AllowedCreateObject) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 10}}
	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedCreateObjects: cre,
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithCreateObjects(target, svcs, nil, nil, cre)
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

// buildCreateObjectFrame wraps a CreateObject request body in a
// BVLC + NPDU + APDU frame.
func buildCreateObjectFrame(body []byte) []byte {
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		byte(bwire.ConfirmedSvcCreateObject),
	}
	apdu = append(apdu, body...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetCreate_AllowedTypePasses — CreateObject for an
// allowlisted type forwards.
func TestGateBACnetCreate_AllowedTypePasses(t *testing.T) {
	cre := []bwrite.AllowedCreateObject{{ObjectType: 17}} // Schedule
	client, upstream := driveCreateObjectSession(t, cre)
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectType(17))
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for allowed CreateObject")
	}
}

// TestGateBACnetCreate_ForbiddenTypeRefuses — CreateObject for a
// non-allowlisted type gets an Abort-PDU refusal.
func TestGateBACnetCreate_ForbiddenTypeRefuses(t *testing.T) {
	cre := []bwrite.AllowedCreateObject{{ObjectType: 17}}
	client, upstream := driveCreateObjectSession(t, cre)
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectType(8)) // Device — not in list
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
		t.Fatalf("upstream saw %d frames for forbidden CreateObject", len(snap))
	}
}

// TestGateBACnetCreate_EmptyAllowlistBypasses — empty
// AllowedCreateObjects list bypasses the per-type gate (svc
// 10 still passes service-only).
func TestGateBACnetCreate_EmptyAllowlistBypasses(t *testing.T) {
	client, upstream := driveCreateObjectSession(t, nil)
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectType(8))
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("empty allowlist should bypass per-create check")
	}
}

// TestGateBACnetCreate_ObjectIdentifierFormMatchesByType — the
// [1] objectIdentifier choice form (with a specific instance)
// still matches the per-type allowlist.
func TestGateBACnetCreate_ObjectIdentifierFormMatchesByType(t *testing.T) {
	cre := []bwrite.AllowedCreateObject{{ObjectType: 17}}
	client, upstream := driveCreateObjectSession(t, cre)
	// [1] form with type=17, instance=42 — instance is ignored.
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectIdentifier(17, 42))
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for [1] form with allowed type")
	}
}

// TestGateBACnetCreate_PropertyAllowDoesNotGrantCreate — an
// AllowedObject for (TypeX, InstanceY, PropZ) does NOT auto-
// grant CreateObject of TypeX. The two allowlists are separate.
func TestGateBACnetCreate_PropertyAllowDoesNotGrantCreate(t *testing.T) {
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 10}, {ServiceChoice: 15}}
	objs := []bwrite.AllowedObject{
		// Operator allowed property writes to (17, 42, 85). They did
		// NOT add type 17 to AllowedCreateObjects, so a CreateObject
		// with type 17 must refuse.
		{ObjectType: 17, ObjectInstance: 42, PropertyID: 85},
	}
	cre := []bwrite.AllowedCreateObject{
		{ObjectType: 999}, // dummy — type 17 is NOT here.
	}
	h := &bwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              svcs,
		AllowedObjects:       objs,
		AllowedCreateObjects: cre,
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithCreateObjects(target, svcs, objs, nil, cre)
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

	// CreateObject with type 17 — present in AllowedObjects, NOT
	// in AllowedCreateObjects.
	frame := buildCreateObjectFrame(buildCreateObjectChoiceObjectType(17))
	_, _ = clientIn.Write(frame)

	_ = clientIn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := clientIn.Read(rbuf)
	if n == 0 {
		t.Fatal("expected abort refusal — AllowedObjects entry should NOT auto-grant CreateObject")
	}
	time.Sleep(50 * time.Millisecond)
	if snap := rec.snapshot(); len(snap) != 0 {
		t.Fatal("upstream should not see CreateObject when type 17 is only in AllowedObjects, not AllowedCreateObjects")
	}
}
