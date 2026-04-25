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

// ---- Hash ladder: per-reinit-state variant degrades ---------

func TestAllowlistHashWithReinitStates_EmptyMatchesV13Chunk8(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 20}}
	cre := []bwrite.AllowedCreateObject{{ObjectType: 17}}
	hPrev := bwrite.AllowlistHashWithCreateObjects("bms:47808", svcs, nil, nil, cre)
	hNew := bwrite.AllowlistHashWithReinitStates("bms:47808", svcs, nil, nil, cre, nil)
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-9 hash with empty reinitStates must equal chunk-8: %x vs %x", hNew, hPrev)
	}
}

func TestAllowlistHashWithReinitStates_AllEmptyMatchesV4(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 20}}
	hV4 := bwrite.AllowlistHash("bms:47808", svcs)
	hNew := bwrite.AllowlistHashWithReinitStates("bms:47808", svcs, nil, nil, nil, nil)
	if !bytes.Equal(hV4[:], hNew[:]) {
		t.Fatalf("chunk-9 hash with all-empty must equal v1.4: %x vs %x", hNew, hV4)
	}
}

func TestAllowlistHashWithReinitStates_NonEmptyChangesHash(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 20}}
	rei := []bwrite.AllowedReinitState{{State: 7}} // activate-changes
	hPrev := bwrite.AllowlistHashWithCreateObjects("bms:47808", svcs, nil, nil, nil)
	hNew := bwrite.AllowlistHashWithReinitStates("bms:47808", svcs, nil, nil, nil, rei)
	if bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatal("chunk-9 hash with non-empty reinitStates must differ from chunk-8")
	}
}

func TestAllowlistHashWithReinitStates_OrderInsensitive(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 20}}
	a := []bwrite.AllowedReinitState{{State: 1}, {State: 7}}
	b := []bwrite.AllowedReinitState{{State: 7}, {State: 1}}
	h1 := bwrite.AllowlistHashWithReinitStates("bms:47808", svcs, nil, nil, nil, a)
	h2 := bwrite.AllowlistHashWithReinitStates("bms:47808", svcs, nil, nil, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on reinitStates input order")
	}
}

// ---- Wire parser: ParseReinitializeDevice -------------------

// buildReinitServiceBody crafts a ReinitializeDevice service-
// request body (AFTER the 4-byte confirmed-request header) for
// a given state enum value. Skips the optional password field.
func buildReinitServiceBody(state uint8) []byte {
	return []byte{
		0x09,  // [0] reinitializedStateOfDevice, primitive, length 1
		state, // value
	}
}

func TestParseReinitializeDevice_HappyPath(t *testing.T) {
	cases := map[string]uint8{
		"coldstart":        bwire.ReinitStateColdstart,
		"warmstart":        bwire.ReinitStateWarmstart,
		"activate-changes": bwire.ReinitStateActivateChanges,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			body := buildReinitServiceBody(want)
			got, ok := bwire.ParseReinitializeDevice(body)
			if !ok {
				t.Fatal("expected ok=true")
			}
			if got != want {
				t.Errorf("state = %d, want %d", got, want)
			}
		})
	}
}

func TestParseReinitializeDevice_TruncatedFails(t *testing.T) {
	body := buildReinitServiceBody(0)
	_, ok := bwire.ParseReinitializeDevice(body[:1])
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

func TestParseReinitializeDevice_WrongTagFails(t *testing.T) {
	body := buildReinitServiceBody(0)
	body[0] = 0x19 // looks like a context-1 length-1 tag — wrong context
	_, ok := bwire.ParseReinitializeDevice(body)
	if ok {
		t.Fatal("wrong tag byte should return ok=false")
	}
}

func TestParseReinitializeDevice_OutOfRangeStateFails(t *testing.T) {
	body := buildReinitServiceBody(99) // outside ASHRAE 135-2020 range
	_, ok := bwire.ParseReinitializeDevice(body)
	if ok {
		t.Fatal("unknown enum value should return ok=false (fail-closed)")
	}
}

// ---- E2E gate: ReinitializeDevice ---------------------------

// driveReinitSession boots a gated handler with svc 20 + per-
// state allowlist.
func driveReinitSession(t *testing.T, rei []bwrite.AllowedReinitState) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 20}}
	h := &bwrite.WriteGatedHandler{
		Target:              target,
		Allowed:             svcs,
		AllowedReinitStates: rei,
		Deriver:             &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:             &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithReinitStates(target, svcs, nil, nil, nil, rei)
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

// buildReinitFrame wraps a ReinitializeDevice request body in
// a BVLC + NPDU + APDU frame.
func buildReinitFrame(state uint8) []byte {
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		byte(bwire.ConfirmedSvcReinitializeDevice),
	}
	apdu = append(apdu, buildReinitServiceBody(state)...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetReinit_AllowedStatePasses — ReinitializeDevice
// for an allowlisted state forwards.
func TestGateBACnetReinit_AllowedStatePasses(t *testing.T) {
	rei := []bwrite.AllowedReinitState{{State: bwire.ReinitStateActivateChanges}}
	client, upstream := driveReinitSession(t, rei)
	frame := buildReinitFrame(bwire.ReinitStateActivateChanges)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for allowed ReinitializeDevice")
	}
}

// TestGateBACnetReinit_ColdstartRefused — coldstart MUST refuse
// when only activate-changes is allowed. This is the canonical
// safety invariant of the per-state gate.
func TestGateBACnetReinit_ColdstartRefused(t *testing.T) {
	rei := []bwrite.AllowedReinitState{{State: bwire.ReinitStateActivateChanges}}
	client, upstream := driveReinitSession(t, rei)
	frame := buildReinitFrame(bwire.ReinitStateColdstart)
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
		t.Fatalf("upstream saw %d frames for forbidden coldstart", len(snap))
	}
}

// TestGateBACnetReinit_EmptyAllowlistBypasses — empty
// AllowedReinitStates list bypasses the per-state gate (svc
// 20 still passes service-only).
func TestGateBACnetReinit_EmptyAllowlistBypasses(t *testing.T) {
	client, upstream := driveReinitSession(t, nil)
	frame := buildReinitFrame(bwire.ReinitStateColdstart)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("empty allowlist should bypass per-state check")
	}
}

// TestGateBACnetReinit_PartialAllowlist_OnlyAllowedPasses — when
// the allowlist has 2 of the 8 states, the others all refuse.
func TestGateBACnetReinit_PartialAllowlist_OnlyAllowedPasses(t *testing.T) {
	rei := []bwrite.AllowedReinitState{
		{State: bwire.ReinitStateWarmstart},
		{State: bwire.ReinitStateActivateChanges},
	}
	// Allowed: warmstart should pass.
	client, upstream := driveReinitSession(t, rei)
	frame := buildReinitFrame(bwire.ReinitStateWarmstart)
	_, _ = client.Write(frame)
	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for warmstart in partial allowlist")
	}
}

func TestGateBACnetReinit_PartialAllowlist_OthersRefuse(t *testing.T) {
	rei := []bwrite.AllowedReinitState{
		{State: bwire.ReinitStateWarmstart},
		{State: bwire.ReinitStateActivateChanges},
	}
	// Refused: startbackup is NOT in the list.
	client, upstream := driveReinitSession(t, rei)
	frame := buildReinitFrame(bwire.ReinitStateStartBackup)
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := client.Read(rbuf)
	if n == 0 {
		t.Fatal("expected abort refusal for startbackup")
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatal("upstream should not see startbackup when it's not in the partial allowlist")
	}
}
