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

// ---- Hash ladder: per-list-element variant degrades --------

func TestAllowlistHashWithListElements_EmptyMatchesV13Chunk12(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 8}}
	awf := []bwrite.AllowedAtomicWriteFile{{Instance: 5}}
	hPrev := bwrite.AllowlistHashWithAWF("bms:47808", bwrite.Allowlists{
		Services:         svcs,
		AtomicWriteFiles: awf,
	})
	hNew := bwrite.AllowlistHashWithListElements("bms:47808", bwrite.Allowlists{
		Services:         svcs,
		AtomicWriteFiles: awf,
	})
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-13 hash with empty ListElements must equal chunk-12: %x vs %x", hNew, hPrev)
	}
}

func TestAllowlistHashWithListElements_AllEmptyMatchesV4(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 8}}
	hV4 := bwrite.AllowlistHash("bms:47808", svcs)
	hNew := bwrite.AllowlistHashWithListElements("bms:47808", bwrite.Allowlists{
		Services: svcs,
	})
	if !bytes.Equal(hV4[:], hNew[:]) {
		t.Fatalf("chunk-13 hash with all-empty must equal v1.4: %x vs %x", hNew, hV4)
	}
}

func TestAllowlistHashWithListElements_NonEmptyChangesHash(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 8}}
	le := []bwrite.AllowedListElement{
		{ObjectType: 15, ObjectInstance: 1, PropertyID: 102}, // NotificationClass#1.recipient_list
	}
	hPrev := bwrite.AllowlistHashWithAWF("bms:47808", bwrite.Allowlists{Services: svcs})
	hNew := bwrite.AllowlistHashWithListElements("bms:47808", bwrite.Allowlists{
		Services:     svcs,
		ListElements: le,
	})
	if bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatal("chunk-13 hash with non-empty ListElements must differ from chunk-12")
	}
}

func TestAllowlistHashWithListElements_OrderInsensitive(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 8}}
	a := []bwrite.AllowedListElement{
		{ObjectType: 15, ObjectInstance: 1, PropertyID: 102},
		{ObjectType: 17, ObjectInstance: 3, PropertyID: 38},
	}
	b := []bwrite.AllowedListElement{
		{ObjectType: 17, ObjectInstance: 3, PropertyID: 38},
		{ObjectType: 15, ObjectInstance: 1, PropertyID: 102},
	}
	h1 := bwrite.AllowlistHashWithListElements("bms:47808", bwrite.Allowlists{Services: svcs, ListElements: a})
	h2 := bwrite.AllowlistHashWithListElements("bms:47808", bwrite.Allowlists{Services: svcs, ListElements: b})
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on ListElements input order")
	}
}

// ---- Wire reuse: ParseWriteProperty parses LE bodies --------

// Note: Add/RemoveListElement share the WriteProperty prefix
// ([0] objectIdentifier + [1] propertyIdentifier) so we don't
// need a new wire parser. The gate calls wire.ParseWriteProperty
// directly. The existing TestParseWriteProperty_* tests cover
// the parser path; here we only need to verify the gate's
// integration on svc 8/9.

// ---- E2E gate: AddListElement / RemoveListElement -----------

// driveListElementSession boots a gated handler with svc 8 + 9
// + per-element allowlist.
func driveListElementSession(t *testing.T, le []bwrite.AllowedListElement) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 8}, {ServiceChoice: 9}}
	h := &bwrite.WriteGatedHandler{
		Target:              target,
		Allowed:             svcs,
		AllowedListElements: le,
		Deriver:             &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:             &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithListElements(target, bwrite.Allowlists{
		Services:     svcs,
		ListElements: le,
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

// buildListElementFrame wraps a list-mutation request body in a
// BVLC + NPDU + APDU frame. svc selects AddListElement (8) or
// RemoveListElement (9).
func buildListElementFrame(svc uint8, objType uint16, objInst, propID uint32) []byte {
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		svc,
	}
	// Reuse the WriteProperty service body (same prefix).
	apdu = append(apdu, buildWritePropertyServiceBody(objType, objInst, propID)...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetLE_AddAllowedTuplePasses — AddListElement for
// an allowlisted (object, property) tuple forwards.
func TestGateBACnetLE_AddAllowedTuplePasses(t *testing.T) {
	le := []bwrite.AllowedListElement{
		{ObjectType: 15, ObjectInstance: 1, PropertyID: 102}, // NotificationClass#1.recipient_list
	}
	client, upstream := driveListElementSession(t, le)
	frame := buildListElementFrame(byte(bwire.ConfirmedSvcAddListElement), 15, 1, 102)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for allowed AddListElement")
	}
}

// TestGateBACnetLE_RemoveAllowedTuplePasses — RemoveListElement
// uses the same allowlist (no separate add/remove dimension).
// Uses Schedule (type=17) to also exercise non-NotificationClass
// targets through the gate.
func TestGateBACnetLE_RemoveAllowedTuplePasses(t *testing.T) {
	le := []bwrite.AllowedListElement{
		{ObjectType: 17, ObjectInstance: 3, PropertyID: 38}, // Schedule#3.exception_schedule
	}
	client, upstream := driveListElementSession(t, le)
	frame := buildListElementFrame(byte(bwire.ConfirmedSvcRemoveListElement), 17, 3, 38)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for allowed RemoveListElement (Schedule type)")
	}
}

// TestGateBACnetLE_ForbiddenTupleRefuses — a (type, instance,
// property) tuple NOT in the allowlist must refuse.
func TestGateBACnetLE_ForbiddenTupleRefuses(t *testing.T) {
	le := []bwrite.AllowedListElement{
		{ObjectType: 15, ObjectInstance: 1, PropertyID: 102},
	}
	client, upstream := driveListElementSession(t, le)
	// Different NotificationClass instance — not in allowlist.
	frame := buildListElementFrame(byte(bwire.ConfirmedSvcAddListElement), 15, 99, 102)
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
		t.Fatalf("upstream saw %d frames for forbidden AddListElement", len(snap))
	}
}

// TestGateBACnetLE_EmptyAllowlistBypasses — empty
// AllowedListElements list bypasses the per-element gate
// (svc 8/9 still pass service-only).
func TestGateBACnetLE_EmptyAllowlistBypasses(t *testing.T) {
	client, upstream := driveListElementSession(t, nil)
	frame := buildListElementFrame(byte(bwire.ConfirmedSvcAddListElement), 15, 99, 102)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("empty allowlist should bypass per-element check")
	}
}

// TestGateBACnetLE_PropertyAllowDoesNotGrantListMutation —
// proves the canonical separation: an entry in AllowedObjects
// (svc 15/16 WriteProperty) does NOT auto-grant
// Add/RemoveListElement on the same (type, instance, property).
func TestGateBACnetLE_PropertyAllowDoesNotGrantListMutation(t *testing.T) {
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{
		{ServiceChoice: 8},  // AddListElement
		{ServiceChoice: 15}, // WriteProperty
	}
	objs := []bwrite.AllowedObject{
		// Operator allowed property writes to NotificationClass#1.
		// recipient_list. They did NOT add the same tuple to
		// AllowedListElements, so AddListElement on the same
		// target must refuse.
		{ObjectType: 15, ObjectInstance: 1, PropertyID: 102},
	}
	le := []bwrite.AllowedListElement{
		{ObjectType: 999, ObjectInstance: 0, PropertyID: 0}, // dummy
	}
	h := &bwrite.WriteGatedHandler{
		Target:              target,
		Allowed:             svcs,
		AllowedObjects:      objs,
		AllowedListElements: le,
		Deriver:             &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:             &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithListElements(target, bwrite.Allowlists{
		Services:     svcs,
		Objects:      objs,
		ListElements: le,
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

	// AddListElement with (15, 1, 102) — present in
	// AllowedObjects, NOT in AllowedListElements.
	frame := buildListElementFrame(byte(bwire.ConfirmedSvcAddListElement), 15, 1, 102)
	_, _ = clientIn.Write(frame)

	_ = clientIn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := clientIn.Read(rbuf)
	if n == 0 {
		t.Fatal("expected abort refusal — AllowedObjects entry should NOT auto-grant AddListElement")
	}
	time.Sleep(50 * time.Millisecond)
	if snap := rec.snapshot(); len(snap) != 0 {
		t.Fatal("upstream should not see AddListElement when (15, 1, 102) is only in AllowedObjects, not AllowedListElements")
	}
}
