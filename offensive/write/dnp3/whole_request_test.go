//go:build offensive

package dnp3

import (
	"bytes"
	"encoding/binary"
	"testing"

	"local/elsereno/internal/protocols/dnp3/wire"
)

// userFrame builds an unconfirmed-user-data frame (control 0xC4) from
// master 2 to outstation 1 carrying userData, CRCs included.
func userFrame(userData []byte) []byte { return ctrlFrame(0xC4, 1, userData) }

// ctrlFrame builds a user-data frame with any control octet from master
// 2 to outstation dest carrying userData, CRCs included.
func ctrlFrame(ctrl uint8, dest uint16, userData []byte) []byte {
	body := wire.AppendBlockCRCs(userData)
	f := make([]byte, wire.HeaderLen, wire.HeaderLen+len(body))
	f[0], f[1] = wire.StartBytes[0], wire.StartBytes[1]
	f[2] = uint8(5 + len(userData)) // #nosec G115 -- test data under 250 octets
	f[3] = ctrl
	binary.LittleEndian.PutUint16(f[4:6], dest)
	binary.LittleEndian.PutUint16(f[6:8], 2)
	binary.LittleEndian.PutUint16(f[8:10], wire.CRC16(f[0:8]))
	return append(f, body...)
}

// cat concatenates frames.
func cat(frames ...[]byte) []byte {
	var out []byte
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}

// segmentRead splits a Read of appOctets application octets (AC, FC,
// then g60v1 class-0 headers padded with zero octets) into segments of
// at most 240 application octets each.
func segmentRead(appOctets int) []byte {
	app := []byte{0xC0, AppFCRead}
	for len(app)+3 <= appOctets {
		app = append(app, 60, 1, 0x06)
	}
	app = append(app, make([]byte, appOctets-len(app))...)
	var out []byte
	for seq, off := uint8(0), 0; off < len(app); seq++ {
		end := off + 240
		if end > len(app) {
			end = len(app)
		}
		th := seq
		if off == 0 {
			th |= wire.TransportFIR
		}
		if end == len(app) {
			th |= wire.TransportFIN
		}
		out = append(out, userFrame(append([]byte{th}, app[off:end]...))...)
		off = end
	}
	return out
}

// latchOnlyGate allows Direct Operate with a LATCH_ON on points 5-8 only.
func latchOnlyGate() *WriteGatedHandler {
	return &WriteGatedHandler{
		AllowedAppFC:         []AllowedAppFunction{{FC: AppFCDirectOperate}},
		AllowedControlOutput: []AllowedCROBControl{{IndexStart: 5, IndexEnd: 8, Codes: []uint8{wire.OpLatchOn}}},
	}
}

// runForward feeds `in` through the master->outstation path and returns
// what reached the outstation and what the gate answered the master.
func runForward(t *testing.T, h *WriteGatedHandler, in []byte) (upstream, reply []byte) {
	t.Helper()
	var up, back bytes.Buffer
	_ = h.forward(bytes.NewReader(in), &up, &back) // ends with io.EOF
	return up.Bytes(), back.Bytes()
}

// TestGate_SecondObjectHeaderJudged: a single Direct Operate carrying an
// allowed LATCH on point 5 and a TRIP on point 7 in a second object
// header. Until 2026-10-14 only the first header was read and the whole
// request passed (PITF-082). An analog setpoint behind a CROB, and a
// header of a type the scope does not cover, are refused too.
func TestGate_SecondObjectHeaderJudged(t *testing.T) {
	t.Parallel()
	h := latchOnlyGate()
	if !h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, crobObjects(5, wire.OpLatchOn))) {
		t.Fatal("an allowed LATCH on point 5 was refused")
	}
	if !h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, append(crobObjects(5, wire.OpLatchOn), crobObjects(6, wire.OpLatchOn)...))) {
		t.Fatal("two allowed LATCH headers were refused")
	}
	for name, objs := range map[string][]byte{
		"TRIP in a second CROB header":     append(crobObjects(5, wire.OpLatchOn), crobObjects(7, 0x81)...),
		"analog setpoint behind a CROB":    append(crobObjects(5, wire.OpLatchOn), aobObjects(10, 9999)...),
		"g30 header behind a CROB":         append(crobObjects(5, wire.OpLatchOn), 30, 1, 0x06),
		"one octet left over after a CROB": append(crobObjects(5, wire.OpLatchOn), 0x00),
	} {
		if h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, objs)) {
			t.Errorf("%s: the request passed", name)
		}
	}
}

// TestGate_SegmentedRequestJudgedWhole: the same Direct Operate split in
// two transport segments. The second segment begins with a g12v1 header
// whose variation octet (0x01) sits where the gate read the function
// code of every frame, so until 2026-10-14 it was judged a Read and
// passed, and the outstation reassembled a TRIP on point 7 (PITF-082).
// Only a Read may now span several segments: any other multi-segment
// request is refused, even when every object in it is allowed.
func TestGate_SegmentedRequestJudgedWhole(t *testing.T) {
	t.Parallel()
	first := userFrame(append([]byte{wire.TransportFIR, 0xC0, AppFCDirectOperate}, crobObjects(5, wire.OpLatchOn)...))
	trip := userFrame(append([]byte{wire.TransportFIN | 1}, crobObjects(7, 0x81)...))
	latch6 := userFrame(append([]byte{wire.TransportFIN | 1}, crobObjects(6, wire.OpLatchOn)...))
	readFirst := userFrame([]byte{wire.TransportFIR, 0xC0, AppFCRead, 60, 1, 0x06})
	readCont := userFrame([]byte{wire.TransportFIN | 1, 60, 2, 0x06})
	single := userFrame(append([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCDirectOperate}, crobObjects(6, wire.OpLatchOn)...))
	rls := wire.BuildRequestLinkStatus(1, 2)

	for name, in := range map[string][]byte{
		"split Direct Operate with a TRIP":     cat(first, trip),
		"split Direct Operate, all allowed":    cat(first, latch6),
		"split Direct Operate, Link Status in": cat(first, rls, latch6),
	} {
		up, reply := runForward(t, latchOnlyGate(), in)
		if bytes.Contains(up, first) || bytes.Contains(up, latch6) || bytes.Contains(up, trip) {
			t.Errorf("%s: a segment reached the outstation: % x", name, up)
		}
		if len(reply) == 0 {
			t.Errorf("%s: no refusal", name)
		}
	}

	// A split Read passes whole, after a Request Link Status that arrived
	// between its segments.
	up, reply := runForward(t, latchOnlyGate(), cat(readFirst, rls, readCont))
	if want := cat(rls, readFirst, readCont); !bytes.Equal(up, want) || len(reply) != 0 {
		t.Fatalf("split Read: upstream % x reply % x, want upstream % x", up, reply, want)
	}

	// The audit's interleaving: a split Direct Operate, then a split Read
	// whose continuation carries a TRIP. If the outstation's link layer
	// dropped a segment, the two could join into a control the gate never
	// judged; with only Reads spanning segments, no control's first
	// segment ever reaches it.
	readTrip := userFrame(append([]byte{wire.TransportFIN | 1}, crobObjects(7, 0x81)...))
	up, _ = runForward(t, latchOnlyGate(), cat(first, latch6, readFirst, readTrip))
	if !bytes.Equal(up, cat(readFirst, readTrip)) {
		t.Fatalf("interleaving: upstream % x, want only the split Read", up)
	}

	// A held first segment is dropped by a new first segment: only the
	// allowed single-frame request that follows passes.
	up, _ = runForward(t, latchOnlyGate(), cat(readFirst, single))
	if !bytes.Equal(up, single) {
		t.Fatalf("held segment then a single frame: upstream % x, want only the single frame", up)
	}

	for name, in := range map[string][]byte{
		"continuation without a first segment":   readCont,
		"continuation out of sequence":           cat(readFirst, userFrame([]byte{wire.TransportFIN | 5, 60, 2, 0x06})),
		"continuation from another address pair": cat(readFirst, ctrlFrame(0xC4, 9, []byte{wire.TransportFIN | 1, 60, 2, 0x06})),
	} {
		if up, reply := runForward(t, latchOnlyGate(), in); len(up) != 0 {
			t.Errorf("%s: forwarded % x (reply % x)", name, up, reply)
		}
	}

	// A continuation whose link function is not allowed refuses the
	// request (--dnp3-primary 4, continuation sent as Confirmed User Data).
	h := latchOnlyGate()
	h.Allowed = []AllowedControl{{PrimaryFC: LinkFCUnconfirmedUserData}}
	if up, reply := runForward(t, h, cat(readFirst, ctrlFrame(0xD3, 1, []byte{wire.TransportFIN | 1, 60, 2, 0x06}))); len(up) != 0 || len(reply) == 0 {
		t.Fatalf("continuation with a refused link function: upstream % x reply % x", up, reply)
	}

	// The cap counts application octets: a Read of exactly 2048 passes,
	// one of 2049 is discarded.
	if up, _ := runForward(t, latchOnlyGate(), segmentRead(2048)); !bytes.Equal(up, segmentRead(2048)) {
		t.Fatal("a split Read of 2048 application octets was not forwarded whole")
	}
	if up, _ := runForward(t, latchOnlyGate(), segmentRead(2049)); len(up) != 0 {
		t.Fatal("a split Read above the 2048-octet cap was forwarded")
	}
}
