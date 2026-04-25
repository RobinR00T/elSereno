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

// ---- Hash ladder: per-DCC-state variant degrades ------------

func TestAllowlistHashWithDCCStates_EmptyMatchesV13Chunk9(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 17}}
	rei := []bwrite.AllowedReinitState{{State: 7}}
	hPrev := bwrite.AllowlistHashWithReinitStates("bms:47808", svcs, nil, nil, nil, rei)
	hNew := bwrite.AllowlistHashWithDCCStates("bms:47808", bwrite.Allowlists{
		Services:     svcs,
		ReinitStates: rei,
	})
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-10 hash with empty DCCStates must equal chunk-9: %x vs %x", hNew, hPrev)
	}
}

func TestAllowlistHashWithDCCStates_AllEmptyMatchesV4(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 17}}
	hV4 := bwrite.AllowlistHash("bms:47808", svcs)
	hNew := bwrite.AllowlistHashWithDCCStates("bms:47808", bwrite.Allowlists{
		Services: svcs,
	})
	if !bytes.Equal(hV4[:], hNew[:]) {
		t.Fatalf("chunk-10 hash with all-empty must equal v1.4: %x vs %x", hNew, hV4)
	}
}

func TestAllowlistHashWithDCCStates_NonEmptyChangesHash(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 17}}
	dcc := []bwrite.AllowedDCCState{{State: bwire.DCCStateEnable}}
	hPrev := bwrite.AllowlistHashWithReinitStates("bms:47808", svcs, nil, nil, nil, nil)
	hNew := bwrite.AllowlistHashWithDCCStates("bms:47808", bwrite.Allowlists{
		Services:  svcs,
		DCCStates: dcc,
	})
	if bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatal("chunk-10 hash with non-empty DCCStates must differ from chunk-9")
	}
}

func TestAllowlistHashWithDCCStates_OrderInsensitive(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 17}}
	a := []bwrite.AllowedDCCState{{State: 0}, {State: 2}}
	b := []bwrite.AllowedDCCState{{State: 2}, {State: 0}}
	h1 := bwrite.AllowlistHashWithDCCStates("bms:47808", bwrite.Allowlists{Services: svcs, DCCStates: a})
	h2 := bwrite.AllowlistHashWithDCCStates("bms:47808", bwrite.Allowlists{Services: svcs, DCCStates: b})
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on DCCStates input order")
	}
}

// ---- Wire parser: ParseDeviceCommControl --------------------

// buildDCCBodyWithoutDuration crafts a DeviceCommControl body
// (AFTER the 4-byte confirmed-request header) WITHOUT the
// optional [0] timeDuration field — operator picks
// "indefinitely silenced" / immediate enable.
func buildDCCBodyWithoutDuration(state uint8) []byte {
	return []byte{
		0x19,  // [1] enableDisable, primitive, length 1
		state, // value
	}
}

// buildDCCBodyWithDuration crafts a body with the optional
// [0] timeDuration field present (length 1 = 1 byte minutes).
func buildDCCBodyWithDuration(duration, state uint8) []byte {
	return []byte{
		0x09, duration, // [0] timeDuration, primitive, length 1
		0x19, state, // [1] enableDisable, primitive, length 1
	}
}

// buildDCCBodyWithDurationLen2 uses length-2 timeDuration (e.g.
// for durations > 255 minutes).
func buildDCCBodyWithDurationLen2(durHi, durLo, state uint8) []byte {
	return []byte{
		0x0A, durHi, durLo, // [0] timeDuration, primitive, length 2
		0x19, state, // [1] enableDisable, primitive, length 1
	}
}

func TestParseDeviceCommControl_HappyPath_NoDuration(t *testing.T) {
	cases := map[string]uint8{
		"enable":            bwire.DCCStateEnable,
		"disable":           bwire.DCCStateDisable,
		"disableInitiation": bwire.DCCStateDisableInitiation,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			body := buildDCCBodyWithoutDuration(want)
			got, ok := bwire.ParseDeviceCommControl(body)
			if !ok {
				t.Fatal("expected ok=true")
			}
			if got != want {
				t.Errorf("state = %d, want %d", got, want)
			}
		})
	}
}

func TestParseDeviceCommControl_HappyPath_WithDuration(t *testing.T) {
	body := buildDCCBodyWithDuration(60, bwire.DCCStateDisable)
	state, ok := bwire.ParseDeviceCommControl(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if state != bwire.DCCStateDisable {
		t.Errorf("state = %d, want %d (disable)", state, bwire.DCCStateDisable)
	}
}

func TestParseDeviceCommControl_HappyPath_WithDurationLen2(t *testing.T) {
	body := buildDCCBodyWithDurationLen2(0x10, 0x00, bwire.DCCStateDisable) // 4096 min
	state, ok := bwire.ParseDeviceCommControl(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if state != bwire.DCCStateDisable {
		t.Errorf("state = %d, want %d", state, bwire.DCCStateDisable)
	}
}

func TestParseDeviceCommControl_TruncatedFails(t *testing.T) {
	body := buildDCCBodyWithoutDuration(0)
	_, ok := bwire.ParseDeviceCommControl(body[:1])
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

func TestParseDeviceCommControl_WrongTagFails(t *testing.T) {
	body := buildDCCBodyWithoutDuration(0)
	body[0] = 0x29 // looks like context-2 length-1 — wrong context
	_, ok := bwire.ParseDeviceCommControl(body)
	if ok {
		t.Fatal("wrong tag byte should return ok=false")
	}
}

func TestParseDeviceCommControl_OutOfRangeStateFails(t *testing.T) {
	body := buildDCCBodyWithoutDuration(99) // outside ASHRAE 135-2020 range
	_, ok := bwire.ParseDeviceCommControl(body)
	if ok {
		t.Fatal("unknown enum value should return ok=false (fail-closed)")
	}
}

// ---- E2E gate: DeviceCommunicationControl -------------------

// driveDCCSession boots a gated handler with svc 17 + per-state
// allowlist.
func driveDCCSession(t *testing.T, dcc []bwrite.AllowedDCCState) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 17}}
	h := &bwrite.WriteGatedHandler{
		Target:           target,
		Allowed:          svcs,
		AllowedDCCStates: dcc,
		Deriver:          &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:          &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithDCCStates(target, bwrite.Allowlists{
		Services:  svcs,
		DCCStates: dcc,
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

// buildDCCFrame wraps a DeviceCommControl request body in a
// BVLC + NPDU + APDU frame.
func buildDCCFrame(body []byte) []byte {
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		byte(bwire.ConfirmedSvcDeviceCommControl),
	}
	apdu = append(apdu, body...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetDCC_AllowedStatePasses — DeviceCommControl for
// an allowlisted state forwards.
func TestGateBACnetDCC_AllowedStatePasses(t *testing.T) {
	dcc := []bwrite.AllowedDCCState{{State: bwire.DCCStateEnable}}
	client, upstream := driveDCCSession(t, dcc)
	frame := buildDCCFrame(buildDCCBodyWithoutDuration(bwire.DCCStateEnable))
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for allowed DeviceCommControl")
	}
}

// TestGateBACnetDCC_DisableRefused — disable MUST refuse when
// only enable is allowed. This is the canonical safety
// invariant: an attacker cannot silence the device.
func TestGateBACnetDCC_DisableRefused(t *testing.T) {
	dcc := []bwrite.AllowedDCCState{{State: bwire.DCCStateEnable}}
	client, upstream := driveDCCSession(t, dcc)
	frame := buildDCCFrame(buildDCCBodyWithoutDuration(bwire.DCCStateDisable))
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
		t.Fatalf("upstream saw %d frames for forbidden disable", len(snap))
	}
}

// TestGateBACnetDCC_DisableInitiationRefused — same invariant
// for the subtler attack vector. disableInitiation is also a
// silencing mode and must refuse when only enable is allowed.
func TestGateBACnetDCC_DisableInitiationRefused(t *testing.T) {
	dcc := []bwrite.AllowedDCCState{{State: bwire.DCCStateEnable}}
	client, upstream := driveDCCSession(t, dcc)
	frame := buildDCCFrame(buildDCCBodyWithoutDuration(bwire.DCCStateDisableInitiation))
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := client.Read(rbuf)
	if n == 0 {
		t.Fatal("expected abort refusal for disableInitiation")
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatal("upstream should not see disableInitiation when only enable is allowed")
	}
}

// TestGateBACnetDCC_EmptyAllowlistBypasses — empty
// AllowedDCCStates list bypasses the per-state gate (svc 17
// still passes service-only).
func TestGateBACnetDCC_EmptyAllowlistBypasses(t *testing.T) {
	client, upstream := driveDCCSession(t, nil)
	// Even disable should pass when the per-state gate is empty.
	frame := buildDCCFrame(buildDCCBodyWithoutDuration(bwire.DCCStateDisable))
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("empty allowlist should bypass per-DCC-state check")
	}
}

// TestGateBACnetDCC_AllowedStateWithDurationPasses — the
// optional timeDuration prefix is correctly skipped by the
// parser before reading the enableDisable enum.
func TestGateBACnetDCC_AllowedStateWithDurationPasses(t *testing.T) {
	dcc := []bwrite.AllowedDCCState{{State: bwire.DCCStateEnable}}
	client, upstream := driveDCCSession(t, dcc)
	// duration=60 minutes + state=enable
	frame := buildDCCFrame(buildDCCBodyWithDuration(60, bwire.DCCStateEnable))
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing — duration prefix should not affect gate decision")
	}
}
