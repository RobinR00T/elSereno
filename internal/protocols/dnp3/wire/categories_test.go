package wire

import "testing"

func TestClassifyControl(t *testing.T) {
	cases := []struct {
		name string
		ctrl uint8
		want Category
	}{
		{"primary Test Link", 0xC1, CategoryRead},           // DIR=1 PRM=1 FC=1
		{"primary Request Link Status", 0xC9, CategoryRead}, // DIR=1 PRM=1 FC=9
		{"primary Reset Link", 0xC0, CategoryWrite},
		{"primary Confirmed Data", 0xC3, CategoryWrite},
		{"primary Unconfirmed Data", 0xC4, CategoryWrite},
		{"primary unknown FC 7", 0xC7, CategoryUnknown},
		{"secondary ACK", 0x00, CategoryRead}, // PRM=0 always read
		{"secondary Not Supported", 0x0F, CategoryRead},
	}
	for _, c := range cases {
		if got := ClassifyControl(c.ctrl); got != c.want {
			t.Errorf("%s: ctrl=0x%02x got %d, want %d", c.name, c.ctrl, got, c.want)
		}
	}
}

func TestBuildRefusal(t *testing.T) {
	req := Header{Dest: 0x0001, Src: 0x0002}
	out := BuildRefusal(req)
	if len(out) != HeaderLen {
		t.Fatalf("len=%d, want %d", len(out), HeaderLen)
	}
	if out[0] != 0x05 || out[1] != 0x64 {
		t.Fatalf("start bytes wrong: % x", out[:2])
	}
	if out[3] != 0x0F {
		t.Fatalf("control byte = 0x%02x, want 0x0F (FC 15 Not Supported)", out[3])
	}
	// Dest/Src should be swapped.
	if out[4] != 0x02 || out[5] != 0x00 {
		t.Fatalf("dest (was src) = % x", out[4:6])
	}
	if out[6] != 0x01 || out[7] != 0x00 {
		t.Fatalf("src (was dest) = % x", out[6:8])
	}
}
