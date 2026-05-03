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

// ---- Hash ladder: per-AWF-file variant degrades ------------

func TestAllowlistHashWithAWF_EmptyMatchesV13Chunk11(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 7}}
	lso := []bwrite.AllowedLSOOperation{{Operation: 7}}
	hPrev := bwrite.AllowlistHashWithLSOOps("plc:47808", bwrite.Allowlists{
		Services:      svcs,
		LSOOperations: lso,
	})
	hNew := bwrite.AllowlistHashWithAWF("plc:47808", bwrite.Allowlists{
		Services:      svcs,
		LSOOperations: lso,
	})
	if !bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatalf("chunk-12 hash with empty AtomicWriteFiles must equal chunk-11: %x vs %x", hNew, hPrev)
	}
}

func TestAllowlistHashWithAWF_AllEmptyMatchesV4(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 7}}
	hV4 := bwrite.AllowlistHash("plc:47808", svcs)
	hNew := bwrite.AllowlistHashWithAWF("plc:47808", bwrite.Allowlists{
		Services: svcs,
	})
	if !bytes.Equal(hV4[:], hNew[:]) {
		t.Fatalf("chunk-12 hash with all-empty must equal v1.4: %x vs %x", hNew, hV4)
	}
}

func TestAllowlistHashWithAWF_NonEmptyChangesHash(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 7}}
	awf := []bwrite.AllowedAtomicWriteFile{{Instance: 5}}
	hPrev := bwrite.AllowlistHashWithLSOOps("plc:47808", bwrite.Allowlists{Services: svcs})
	hNew := bwrite.AllowlistHashWithAWF("plc:47808", bwrite.Allowlists{
		Services:         svcs,
		AtomicWriteFiles: awf,
	})
	if bytes.Equal(hPrev[:], hNew[:]) {
		t.Fatal("chunk-12 hash with non-empty AtomicWriteFiles must differ from chunk-11")
	}
}

func TestAllowlistHashWithAWF_OrderInsensitive(t *testing.T) {
	svcs := []bwrite.AllowedService{{ServiceChoice: 7}}
	a := []bwrite.AllowedAtomicWriteFile{{Instance: 1}, {Instance: 5}}
	b := []bwrite.AllowedAtomicWriteFile{{Instance: 5}, {Instance: 1}}
	h1 := bwrite.AllowlistHashWithAWF("plc:47808", bwrite.Allowlists{Services: svcs, AtomicWriteFiles: a})
	h2 := bwrite.AllowlistHashWithAWF("plc:47808", bwrite.Allowlists{Services: svcs, AtomicWriteFiles: b})
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on AtomicWriteFiles input order")
	}
}

// ---- Wire parser: ParseAtomicWriteFile -----------------------

// buildAWFServiceBody crafts an AtomicWriteFile body (AFTER the
// 4-byte confirmed-request header) for File#instance with a
// minimal streamAccess wrapper. The wrapper bytes don't matter
// to the gate parser (it only reads the leading
// fileIdentifier).
func buildAWFServiceBody(instance uint32) []byte {
	// #nosec G115 -- test-bounded — instance fits in 22 bits.
	packed := (uint32(bwire.FileObjectType) << 22) | (instance & 0x3FFFFF)
	buf := []byte{0xC4} // application tag 12, primitive, length 4
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], packed)
	buf = append(buf, u32[:]...)
	// Append a minimal streamAccess wrapper so the request looks
	// well-formed end-to-end. Gate ignores everything past the
	// fileIdentifier.
	buf = append(buf, 0x0E, 0x31, 0x00, 0x65, 0x00, 0x0F)
	return buf
}

// buildAWFServiceBodyWithType crafts a body with an arbitrary
// ObjectType — used to exercise the "ObjectType != 10 fails
// closed" invariant.
func buildAWFServiceBodyWithType(objType uint16, instance uint32) []byte {
	// #nosec G115 -- test-bounded.
	packed := (uint32(objType) << 22) | (instance & 0x3FFFFF)
	buf := []byte{0xC4}
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], packed)
	buf = append(buf, u32[:]...)
	return buf
}

func TestParseAtomicWriteFile_HappyPath(t *testing.T) {
	body := buildAWFServiceBody(42)
	inst, ok := bwire.ParseAtomicWriteFile(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if inst != 42 {
		t.Errorf("instance = %d, want 42", inst)
	}
}

func TestParseAtomicWriteFile_TruncatedFails(t *testing.T) {
	body := buildAWFServiceBody(42)
	_, ok := bwire.ParseAtomicWriteFile(body[:3])
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

func TestParseAtomicWriteFile_WrongTagFails(t *testing.T) {
	body := buildAWFServiceBody(42)
	body[0] = 0x0C // looks like context-0 length-4 — wrong class
	_, ok := bwire.ParseAtomicWriteFile(body)
	if ok {
		t.Fatal("wrong tag class should return ok=false")
	}
}

func TestParseAtomicWriteFile_NonFileTypeFails(t *testing.T) {
	// ObjectType = 2 (BinaryOutput) — not File.
	body := buildAWFServiceBodyWithType(2, 42)
	_, ok := bwire.ParseAtomicWriteFile(body)
	if ok {
		t.Fatal("ObjectType != 10 should fail closed (only File targets are valid)")
	}
}

func TestParseAtomicWriteFile_LargeInstance(t *testing.T) {
	// Max 22-bit instance.
	body := buildAWFServiceBody(0x3FFFFF)
	inst, ok := bwire.ParseAtomicWriteFile(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if inst != 0x3FFFFF {
		t.Errorf("instance = %d, want 0x3FFFFF", inst)
	}
}

// ---- E2E gate: AtomicWriteFile ------------------------------

// driveAWFSession boots a gated handler with svc 7 + per-File
// allowlist.
func driveAWFSession(t *testing.T, awf []bwrite.AllowedAtomicWriteFile) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "plc.test:47808"
	svcs := []bwrite.AllowedService{{ServiceChoice: 7}}
	h := &bwrite.WriteGatedHandler{
		Target:                  target,
		Allowed:                 svcs,
		AllowedAtomicWriteFiles: awf,
		Deriver:                 &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:                 &fakeAuditor{},
	}
	mut := bwrite.SessionMutationWithAWF(target, bwrite.Allowlists{
		Services:         svcs,
		AtomicWriteFiles: awf,
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

// buildAWFFrame wraps an AtomicWriteFile request body in a
// BVLC + NPDU + APDU frame.
func buildAWFFrame(instance uint32) []byte {
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, // max-seg | max-apdu
		0x01, // invoke-id
		byte(bwire.ConfirmedSvcAtomicWriteFile),
	}
	apdu = append(apdu, buildAWFServiceBody(instance)...)
	return buildBACnetFrame(apdu)
}

// TestGateBACnetAWF_AllowedFilePasses — AWF for an allowlisted
// File instance forwards.
func TestGateBACnetAWF_AllowedFilePasses(t *testing.T) {
	awf := []bwrite.AllowedAtomicWriteFile{{Instance: 5}}
	client, upstream := driveAWFSession(t, awf)
	frame := buildAWFFrame(5)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("upstream saw nothing for allowed AtomicWriteFile")
	}
}

// TestGateBACnetAWF_FirmwareFileRefused — when only File#5 (log)
// is allowed, an attempt to overwrite File#1 (firmware) refuses.
// Canonical safety invariant.
func TestGateBACnetAWF_FirmwareFileRefused(t *testing.T) {
	awf := []bwrite.AllowedAtomicWriteFile{{Instance: 5}}
	client, upstream := driveAWFSession(t, awf)
	frame := buildAWFFrame(1) // firmware blob — NOT in allowlist
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
		t.Fatalf("upstream saw %d frames for forbidden firmware overwrite", len(snap))
	}
}

// TestGateBACnetAWF_EmptyAllowlistBypasses — empty
// AllowedAtomicWriteFiles list bypasses the per-file gate
// (svc 7 still passes service-only).
func TestGateBACnetAWF_EmptyAllowlistBypasses(t *testing.T) {
	client, upstream := driveAWFSession(t, nil)
	frame := buildAWFFrame(1)
	_, _ = client.Write(frame)

	frames := waitForFramesOne(t, upstream)
	if len(frames) == 0 {
		t.Fatal("empty allowlist should bypass per-file check")
	}
}

// TestGateBACnetAWF_NonFileTypeRefuses — a request claiming to
// write to AnalogValue#5 (ObjectType=2, not File=10) refuses
// even when File#5 is in the allowlist.
func TestGateBACnetAWF_NonFileTypeRefuses(t *testing.T) {
	awf := []bwrite.AllowedAtomicWriteFile{{Instance: 5}}
	client, upstream := driveAWFSession(t, awf)
	// Build a frame with ObjectType=2 (BinaryOutput) instead of 10.
	apdu := []byte{
		byte(bwire.APDUConfirmedRequest) << 4,
		0x05, 0x01,
		byte(bwire.ConfirmedSvcAtomicWriteFile),
	}
	apdu = append(apdu, buildAWFServiceBodyWithType(2, 5)...)
	frame := buildBACnetFrame(apdu)
	_, _ = client.Write(frame)

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 256)
	n, _ := client.Read(rbuf)
	if n == 0 {
		t.Fatal("expected abort refusal — non-File object type must fail closed")
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatal("upstream should not see malformed AtomicWriteFile (wrong ObjectType)")
	}
}
