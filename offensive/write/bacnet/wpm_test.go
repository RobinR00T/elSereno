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

// ---- BER walker: ParseWritePropertyMultiple --------------

// buildWPMServiceBody crafts a WritePropertyMultiple service-
// request body (AFTER the 4-byte confirmed-request header) for
// a list of (objectType, objectInstance, propertyIDs[]) groups.
// Each group becomes one WriteAccessSpecification.
//
// Each property's value is encoded minimally as Null
// (application tag 0, length 0).
func buildWPMServiceBody(groups []wpmGroup) []byte {
	buf := make([]byte, 0, 64)
	for _, g := range groups {
		// Tag 0 ObjectIdentifier (5 bytes: 0x0C + 4-byte packed).
		// #nosec G115 -- test-bounded
		packed := (uint32(g.objectType) << 22) | (g.objectInstance & 0x3FFFFF)
		buf = append(buf, 0x0C)
		var u32 [4]byte
		binary.BigEndian.PutUint32(u32[:], packed)
		buf = append(buf, u32[:]...)

		// Tag 1 OPENING.
		buf = append(buf, 0x1E)

		for _, propID := range g.propertyIDs {
			// Tag 0 PropertyIdentifier.
			switch {
			case propID < 256:
				buf = append(buf, 0x09, byte(propID))
			case propID < 65536:
				buf = append(buf, 0x0A,
					byte(propID>>8&0xFF),
					byte(propID&0xFF)) // #nosec G115 -- bytes intentionally truncated
			default:
				buf = append(buf, 0x0B,
					byte(propID>>16&0xFF),
					byte(propID>>8&0xFF),
					byte(propID&0xFF)) // #nosec G115 -- bytes intentionally truncated
			}
			// Tag 2 OPENING + Null value (app tag 0, length 0)
			// + Tag 2 CLOSING.
			buf = append(buf, 0x2E, 0x00, 0x2F)
		}

		// Tag 1 CLOSING.
		buf = append(buf, 0x1F)
	}
	return buf
}

type wpmGroup struct {
	objectType     uint16
	objectInstance uint32
	propertyIDs    []uint32
}

func TestParseWPM_SingleObjectSingleProperty(t *testing.T) {
	body := buildWPMServiceBody([]wpmGroup{
		{objectType: 0, objectInstance: 42, propertyIDs: []uint32{85}},
	})
	targets, ok := bwire.ParseWritePropertyMultiple(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(targets) != 1 {
		t.Fatalf("len=%d, want 1", len(targets))
	}
	if targets[0].ObjectType != 0 || targets[0].ObjectInstance != 42 || targets[0].PropertyID != 85 {
		t.Errorf("targets[0] = %+v, want {0, 42, 85}", targets[0])
	}
}

func TestParseWPM_SingleObjectMultipleProperties(t *testing.T) {
	body := buildWPMServiceBody([]wpmGroup{
		{objectType: 0, objectInstance: 42, propertyIDs: []uint32{85, 87, 117}},
	})
	targets, ok := bwire.ParseWritePropertyMultiple(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(targets) != 3 {
		t.Fatalf("len=%d, want 3", len(targets))
	}
	for i, want := range []uint32{85, 87, 117} {
		if targets[i].PropertyID != want {
			t.Errorf("targets[%d].PropertyID = %d, want %d", i, targets[i].PropertyID, want)
		}
	}
}

func TestParseWPM_MultipleObjects(t *testing.T) {
	body := buildWPMServiceBody([]wpmGroup{
		{objectType: 0, objectInstance: 42, propertyIDs: []uint32{85}},
		{objectType: 2, objectInstance: 3, propertyIDs: []uint32{85, 87}},
		{objectType: 8, objectInstance: 1, propertyIDs: []uint32{75}},
	})
	targets, ok := bwire.ParseWritePropertyMultiple(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(targets) != 4 {
		t.Fatalf("len=%d, want 4 total properties (1+2+1)", len(targets))
	}
	// Check sequence — first AnalogInput#42, then BinaryOutput#3 ×2,
	// then Device#1.
	wants := []bwire.WritePropertyTarget{
		{ObjectType: 0, ObjectInstance: 42, PropertyID: 85},
		{ObjectType: 2, ObjectInstance: 3, PropertyID: 85},
		{ObjectType: 2, ObjectInstance: 3, PropertyID: 87},
		{ObjectType: 8, ObjectInstance: 1, PropertyID: 75},
	}
	for i, w := range wants {
		if targets[i] != w {
			t.Errorf("targets[%d] = %+v, want %+v", i, targets[i], w)
		}
	}
}

func TestParseWPM_EmptyFails(t *testing.T) {
	_, ok := bwire.ParseWritePropertyMultiple(nil)
	if ok {
		t.Fatal("empty body should return ok=false")
	}
	_, ok = bwire.ParseWritePropertyMultiple([]byte{})
	if ok {
		t.Fatal("empty slice should return ok=false")
	}
}

func TestParseWPM_TruncatedFails(t *testing.T) {
	body := buildWPMServiceBody([]wpmGroup{
		{objectType: 0, objectInstance: 42, propertyIDs: []uint32{85, 87}},
	})
	// Cut off mid-second-property — the inner BACnetPropertyValue
	// loop should fail.
	_, ok := bwire.ParseWritePropertyMultiple(body[:len(body)-3])
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

func TestParseWPM_WrongOpeningTagFails(t *testing.T) {
	body := buildWPMServiceBody([]wpmGroup{
		{objectType: 0, objectInstance: 42, propertyIDs: []uint32{85}},
	})
	// Corrupt tag-1 opening (0x1E → 0x1A primitive).
	body[5] = 0x1A
	_, ok := bwire.ParseWritePropertyMultiple(body)
	if ok {
		t.Fatal("wrong opening tag should return ok=false")
	}
}

// TestParseWPM_NestedConstructedValue — values can themselves be
// constructed (e.g. BACnetWeeklySchedule). The depth-aware
// walker must skip past nested opening/closing pairs.
func TestParseWPM_NestedConstructedValue(t *testing.T) {
	// Build a body with one AnalogInput#42.PresentValue but
	// inject a nested constructed value: opening 0x2E + opening
	// 0x6E (sub-tag 6) + null + closing 0x6F + closing 0x2F.
	buf := make([]byte, 0, 16)
	// Object identifier.
	buf = append(buf, 0x0C, 0x00, 0x00, 0x00, 0x2A)
	// Tag 1 OPENING.
	buf = append(buf, 0x1E)
	// Property identifier (tag 0, length 1, value 85).
	buf = append(buf, 0x09, 0x55)
	// Value: tag 2 OPENING + tag 6 OPENING + null + tag 6 CLOSING + tag 2 CLOSING.
	buf = append(buf, 0x2E, 0x6E, 0x00, 0x6F, 0x2F)
	// Tag 1 CLOSING.
	buf = append(buf, 0x1F)

	targets, ok := bwire.ParseWritePropertyMultiple(buf)
	if !ok {
		t.Fatalf("nested constructed value should parse: %x", buf)
	}
	if len(targets) != 1 || targets[0].PropertyID != 85 {
		t.Errorf("targets=%+v, want one with PropertyID=85", targets)
	}
}

// ---- E2E gate: WPM ------------------------------------------

// driveWPMSession boots a gated handler with services 16 + a
// per-object allowlist.
func driveWPMSession(t *testing.T, objs []bwrite.AllowedObject) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 16}}
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

// buildWPMFrame wraps a WPM service body in a BVLC + NPDU + APDU
// frame.
func buildWPMFrame(groups []wpmGroup) []byte {
	service := buildWPMServiceBody(groups)
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		byte(bwire.ConfirmedSvcWritePropertyMultiple),
	}
	apdu = append(apdu, service...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetWPM_AllAllowedPasses — every (type, instance,
// property) in the WPM batch is in the allowlist → forward.
func TestGateBACnetWPM_AllAllowedPasses(t *testing.T) {
	objs := []bwrite.AllowedObject{
		{ObjectType: 0, ObjectInstance: 42, PropertyID: 85},
		{ObjectType: 2, ObjectInstance: 3, PropertyID: 85},
	}
	client, upstream := driveWPMSession(t, objs)

	frame := buildWPMFrame([]wpmGroup{
		{objectType: 0, objectInstance: 42, propertyIDs: []uint32{85}},
		{objectType: 2, objectInstance: 3, propertyIDs: []uint32{85}},
	})
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for all-allowed WPM batch")
	}
}

// TestGateBACnetWPM_OneForbiddenRefuses — a single forbidden
// (type, instance, property) tuple in the batch must refuse the
// WHOLE WPM. Closes the multi-object gap analogous to v1.12
// chunk 2 for OPC UA WriteRequest.
func TestGateBACnetWPM_OneForbiddenRefuses(t *testing.T) {
	objs := []bwrite.AllowedObject{
		{ObjectType: 0, ObjectInstance: 42, PropertyID: 85},
	}
	client, upstream := driveWPMSession(t, objs)

	// Allowed first, forbidden second — the gate must walk the
	// whole batch and refuse.
	frame := buildWPMFrame([]wpmGroup{
		{objectType: 0, objectInstance: 42, propertyIDs: []uint32{85}},
		{objectType: 0, objectInstance: 42, propertyIDs: []uint32{86}},
	})
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, err := client.Read(rbuf)
	if err != nil {
		t.Fatalf("read abort: %v", err)
	}
	if n < 4 || !bytes.HasPrefix(rbuf[:n], []byte{bwire.BVLCTypeBacnetIP}) {
		t.Fatalf("expected BVLC abort frame, got % x", rbuf[:16])
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw %d frames for forbidden WPM batch", len(snap))
	}
}

// TestGateBACnetWPM_EmptyAllowlistBypasses — empty AllowedObjects
// list bypasses the per-object gate (svc 16 still passes
// service-only).
func TestGateBACnetWPM_EmptyAllowlistBypasses(t *testing.T) {
	client, upstream := driveWPMSession(t, nil)
	frame := buildWPMFrame([]wpmGroup{
		{objectType: 7, objectInstance: 999, propertyIDs: []uint32{99}},
	})
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("empty allowlist should bypass per-object check")
	}
}

// TestGateBACnetWPM_OnlyOneObjectAllowedRefuses — single
// (type, instance, property) batch where the lone entry isn't
// in the allowlist refuses immediately.
func TestGateBACnetWPM_OnlyOneObjectAllowedRefuses(t *testing.T) {
	objs := []bwrite.AllowedObject{
		{ObjectType: 0, ObjectInstance: 42, PropertyID: 85},
	}
	client, upstream := driveWPMSession(t, objs)

	frame := buildWPMFrame([]wpmGroup{
		{objectType: 0, objectInstance: 42, propertyIDs: []uint32{86}},
	})
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := client.Read(rbuf)
	if n == 0 {
		t.Fatal("expected abort refusal")
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatal("upstream should not see WPM with wrong PropertyID")
	}
}
