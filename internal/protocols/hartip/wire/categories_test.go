package wire

import "testing"

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		id   uint8
		want Category
	}{
		{IDSessionInitiate, CategoryRead},
		{IDSessionClose, CategoryRead},
		{IDKeepAlive, CategoryRead},
		{IDTokenPassPDU, CategoryWrite},
		{0xFF, CategoryUnknown},
	} {
		got := Classify(Header{MsgID: tc.id})
		if got != tc.want {
			t.Errorf("MsgID 0x%02x: got %d, want %d", tc.id, got, tc.want)
		}
	}
}

func TestBuildRefusal(t *testing.T) {
	req := Header{Sequence: 0x1234}
	out := BuildRefusal(req)
	if len(out) != HeaderLen {
		t.Fatalf("len=%d, want %d", len(out), HeaderLen)
	}
	if out[0] != Version || out[1] != MsgResponse || out[2] != IDSessionClose {
		t.Fatalf("header bytes wrong: % x", out[:3])
	}
	if out[3] != 0x04 {
		t.Fatalf("status=0x%02x, want 0x04", out[3])
	}
	if out[4] != 0x12 || out[5] != 0x34 {
		t.Fatalf("sequence echo wrong: % x", out[4:6])
	}
}
