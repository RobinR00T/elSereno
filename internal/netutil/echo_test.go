package netutil_test

import (
	"testing"

	"local/elsereno/internal/netutil"
)

func TestIsEcho(t *testing.T) {
	sent := []byte{0x00, 0x01, 0x17, 0xE8, 0x30, 0x00, 0x00, 0x00}
	cases := []struct {
		name  string
		reply []byte
		want  bool
	}{
		{"full echo", sent, true},
		{"echo cut by a read boundary", sent[:3], true},
		{"empty reply is not an echo", nil, false},
		{"reply longer than the probe", append(append([]byte{}, sent...), 0x99), false},
		{"same magic, different length field (a real reply)", []byte{0x00, 0x01, 0x17, 0xE8, 0x10, 0x00, 0x00, 0x00}, false},
		{"unrelated bytes", []byte("HTTP/1.1 200 OK"), false},
	}
	for _, c := range cases {
		if got := netutil.IsEcho(sent, c.reply); got != c.want {
			t.Errorf("%s: IsEcho = %v, want %v", c.name, got, c.want)
		}
	}
}
