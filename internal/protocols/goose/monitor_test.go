package goose_test

import (
	"encoding/binary"
	"testing"

	"local/elsereno/internal/protocols/goose"
)

// observe dissects a built frame and feeds it to the monitor, failing on
// a dissect error.
func observe(t *testing.T, m *goose.Monitor, frame []byte) []goose.Event {
	t.Helper()
	f, err := goose.Dissect(frame)
	if err != nil {
		t.Fatalf("Dissect: %v", err)
	}
	return m.Observe(f)
}

// hasKind reports whether evs contains an event of the given kind.
func hasKind(evs []goose.Event, k goose.EventKind) bool {
	for _, e := range evs {
		if e.Kind == k {
			return true
		}
	}
	return false
}

func TestMonitor_StateChangeIsNormal(t *testing.T) {
	m := goose.NewMonitor()
	_ = observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 1, sqNum: 0}))
	evs := observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 2, sqNum: 0}))
	if !hasKind(evs, goose.EvStateChange) {
		t.Fatalf("expected state_change, got %v", evs)
	}
	if hasKind(evs, goose.EvStNumJump) || hasKind(evs, goose.EvStNumRegression) {
		t.Fatalf("a +1 stNum step must not raise jump/regression: %v", evs)
	}
}

func TestMonitor_StNumJump(t *testing.T) {
	m := goose.NewMonitor()
	_ = observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 1}))
	evs := observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 9}))
	if !hasKind(evs, goose.EvStNumJump) {
		t.Fatalf("expected stnum_jump for 1 -> 9, got %v", evs)
	}
}

func TestMonitor_StNumRegression(t *testing.T) {
	m := goose.NewMonitor()
	_ = observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 8}))
	evs := observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 3}))
	if !hasKind(evs, goose.EvStNumRegression) {
		t.Fatalf("expected stnum_regression for 8 -> 3, got %v", evs)
	}
}

func TestMonitor_TestBit(t *testing.T) {
	m := goose.NewMonitor()
	evs := observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 1, testPresent: true, test: true}))
	if !hasKind(evs, goose.EvTestBitSet) {
		t.Fatalf("expected test_bit_set, got %v", evs)
	}
}

func TestMonitor_NdsCom(t *testing.T) {
	m := goose.NewMonitor()
	evs := observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 1, ndsComPresent: true, ndsCom: true}))
	if !hasKind(evs, goose.EvNdsComSet) {
		t.Fatalf("expected ndscom_set, got %v", evs)
	}
}

func TestMonitor_SqNumStall(t *testing.T) {
	m := goose.NewMonitor()
	_ = observe(t, m, buildGooseFrame(gooseFields{goID: "hb", ttl: 10, stNum: 5, sqNum: 4}))
	// Same stNum, sqNum does not advance -> anomaly.
	evs := observe(t, m, buildGooseFrame(gooseFields{goID: "hb", ttl: 10, stNum: 5, sqNum: 4}))
	if !hasKind(evs, goose.EvSqNumAnomaly) {
		t.Fatalf("expected sqnum_anomaly, got %v", evs)
	}
}

func TestMonitor_ConfRevChange(t *testing.T) {
	m := goose.NewMonitor()
	_ = observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 1, confRev: 1}))
	evs := observe(t, m, buildGooseFrame(gooseFields{goID: "trip", ttl: 10, stNum: 2, confRev: 2}))
	if !hasKind(evs, goose.EvConfRevChange) {
		t.Fatalf("expected confrev_change, got %v", evs)
	}
}

func TestMonitor_SeparatePublishers(t *testing.T) {
	// Two goIDs are independent: a jump on one must not be blamed on the
	// other.
	m := goose.NewMonitor()
	_ = observe(t, m, buildGooseFrame(gooseFields{goID: "a", ttl: 10, stNum: 1}))
	_ = observe(t, m, buildGooseFrame(gooseFields{goID: "b", ttl: 10, stNum: 100}))
	evs := observe(t, m, buildGooseFrame(gooseFields{goID: "a", ttl: 10, stNum: 2}))
	if hasKind(evs, goose.EvStNumJump) {
		t.Fatalf("publisher a stepped 1 -> 2; must not inherit b's stNum: %v", evs)
	}
}

// ---- SV -------------------------------------------------------------

func buildSVFrame(svID string, smpCnt, confRev uint16) []byte {
	var asdu []byte
	asdu = append(asdu, tlv(0x80, []byte(svID))...) // svID
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], smpCnt)
	asdu = append(asdu, tlv(0x82, cnt[:])...) // smpCnt (OCTET STRING(2))
	asdu = append(asdu, tlv(0x83, berInt(uint32(confRev)))...)

	seq := tlv(0x30, asdu)  // ASDU SEQUENCE
	seqOf := tlv(0xA2, seq) // seqOfASDU
	noASDU := tlv(0x80, []byte{0x01})
	savPdu := tlv(0x60, append(noASDU, seqOf...))

	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], 0x4000)                // APPID
	binary.BigEndian.PutUint16(hdr[2:4], uint16(8+len(savPdu))) // #nosec G115 -- test frames small
	payload := make([]byte, 0, len(hdr)+len(savPdu))
	payload = append(payload, hdr...)
	payload = append(payload, savPdu...)
	return wrapEthernet(goose.EtherTypeSV, payload, false, 0)
}

func TestDissectSV(t *testing.T) {
	f, err := goose.Dissect(buildSVFrame("MU01/LLN0.smvcb", 1000, 1))
	if err != nil {
		t.Fatalf("Dissect SV: %v", err)
	}
	if f.Kind != goose.KindSV || f.SV == nil {
		t.Fatalf("kind=%v sv=%v", f.Kind, f.SV)
	}
	if f.SV.SvID != "MU01/LLN0.smvcb" || f.SV.SmpCnt != 1000 || f.SV.ConfRev != 1 {
		t.Errorf("SV fields wrong: %+v", f.SV)
	}
}

func TestMonitor_SVSmpCntRegression(t *testing.T) {
	m := goose.NewMonitor()
	_ = observe(t, m, buildSVFrame("MU01", 2000, 1))
	evs := observe(t, m, buildSVFrame("MU01", 500, 1)) // large backwards step, not a wrap
	if !hasKind(evs, goose.EvSVSmpCntRegression) {
		t.Fatalf("expected sv_smpcnt_regression, got %v", evs)
	}
}
