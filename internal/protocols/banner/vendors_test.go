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
		// Original v1.0 patterns.
		{"Moxa NPort 5150 V3.5 Build 23032410\r\n", banner.VendorMoxa},
		{"Lantronix XPort device ready\n", banner.VendorLantronix},
		{"Welcome to Digi Connect ME", banner.VendorDigi},
		{"NetBurner SB70LC\n", banner.VendorNetBurner},
		{"SSH-2.0-OpenSSH_9.0", banner.VendorOpenSSH},
		{"KONE KCE-5500 lift-interphone", banner.VendorKoneLift},
		{"", banner.VendorUnknown},
		{"random telnet banner without markers", banner.VendorUnknown},

		// v1.23 chunk 2 expansion: industrial controller / HMI
		// / RTU vendors.
		{"SIMATIC S7-1200 V4.5", banner.VendorSiemens},
		{"RUGGEDCOM RSG2100", banner.VendorSiemens},
		{"SIEMENS RX1500 IOS-XE", banner.VendorSiemens},
		{"Allen-Bradley CompactLogix 5380", banner.VendorRockwell},
		{"Rockwell Automation MicroLogix 1100", banner.VendorRockwell},
		{"ControlLogix L75 firmware v32", banner.VendorRockwell},
		{"Modicon M340 BMXP3420302", banner.VendorSchneider},
		{"Schneider Electric Modicon M580", banner.VendorSchneider},
		{"Schneider-Electric M251MESC", banner.VendorSchneider},
		{"ABB AC500 PM590-ETH", banner.VendorABB},
		{"ABB Robotics IRC5", banner.VendorABB},
		{"WAGO PFC200 750-8204 fw=20240115", banner.VendorWAGO},
		{"WAGO 750-880 ETH", banner.VendorWAGO},
		{"Beckhoff CX9020 TwinCAT 3.1", banner.VendorBeckhoff},
		{"Phoenix Contact AXC F 2152", banner.VendorPhoenixContact},
		{"PhoenixContact ME-PLC", banner.VendorPhoenixContact},
		{"Hirschmann Eagle20 Tofino", banner.VendorHirschmann},
		{"Westermo MRD-455 Industrial Router", banner.VendorWestermo},
		{"Advantech EKI-1361 1-port serial server", banner.VendorAdvantech},
		{"Sealevel SeaLINK 4-port serial gateway", banner.VendorSealevel},
		{"Honeywell Experion R501.1 PKS", banner.VendorHoneywell},
		{"Honeywell  XYR 6000 wireless gateway", banner.VendorHoneywell},
		{"Johnson Controls Metasys NCE25", banner.VendorJohnsonControls},
		{"Tridium Niagara 4 Station", banner.VendorTridium},

		// Network gear adjacent to ICS.
		{"Cisco IOS Software, Catalyst L3 Switch", banner.VendorCiscoIOS},
		{"IOS Software, RUGGEDCOM RX series", banner.VendorSiemens}, // most-specific wins
		{"MikroTik RouterOS 7.13", banner.VendorMikroTik},
		{"RouterOS v6.49.10", banner.VendorMikroTik},
		{"Ubiquiti EdgeRouter X", banner.VendorUbiquiti},
		{"UniFi Cloud Key", banner.VendorUbiquiti},
		{"pfSense 2.7.0-RELEASE", banner.VendorPfSense},
		{"OPNsense Community Edition", banner.VendorPfSense},
		{"SSH-2.0-dropbear_2022.83", banner.VendorDropbear}, // Dropbear before generic ssh-
		{"Server: RomPager/4.07", banner.VendorRomPager},
	}
	for _, c := range cases {
		if got := banner.DetectVendor(c.in); got != c.want {
			t.Fatalf("DetectVendor(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDetectVendorOrderingSiemensVsCisco(t *testing.T) {
	t.Parallel()
	// A banner that references both SIMATIC and Cisco IOS should
	// match Siemens first because the SIMATIC rule precedes the
	// Cisco IOS one in vendorRules. This guards against
	// accidental ordering regression.
	in := "Cisco IOS Software booting on SIMATIC RUGGEDCOM"
	if got := banner.DetectVendor(in); got != banner.VendorSiemens {
		t.Fatalf("expected Siemens to win on mixed banner: got %q", got)
	}
}

func TestDetectVendorEmptyAndCaseInsensitive(t *testing.T) {
	t.Parallel()
	if got := banner.DetectVendor(""); got != banner.VendorUnknown {
		t.Fatalf("empty: got %q", got)
	}
	// Case-insensitive: lowercase banner should still match the
	// canonical needle.
	if got := banner.DetectVendor("WAGO PFC200"); got != banner.VendorWAGO {
		t.Fatalf("upper-case WAGO: got %q", got)
	}
	if got := banner.DetectVendor("wago pfc200"); got != banner.VendorWAGO {
		t.Fatalf("lower-case wago: got %q", got)
	}
}
