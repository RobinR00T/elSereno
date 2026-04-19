package banner_test

import (
	"testing"

	"local/elsereno/internal/protocols/banner"
)

func TestDetectVendor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want banner.Vendor
	}{
		{"Moxa NPort 5150 V3.5 Build 23032410\r\n", banner.VendorMoxa},
		{"Lantronix XPort device ready\n", banner.VendorLantronix},
		{"Welcome to Digi Connect ME", banner.VendorDigi},
		{"NetBurner SB70LC\n", banner.VendorNetBurner},
		{"SSH-2.0-OpenSSH_9.0", banner.VendorOpenSSH},
		{"KONE KCE-5500 lift-interphone", banner.VendorKoneLift},
		{"", banner.VendorUnknown},
		{"random telnet banner without markers", banner.VendorUnknown},
	}
	for _, c := range cases {
		if got := banner.DetectVendor(c.in); got != c.want {
			t.Fatalf("DetectVendor(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
