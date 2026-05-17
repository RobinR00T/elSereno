package profinet_test

import (
	"strings"
	"testing"

	"local/elsereno/internal/protocols/profinet"
)

// TestVendorName_Siemens: known vendor returns name.
func TestVendorName_Siemens(t *testing.T) {
	if got := profinet.VendorName(0x002A); got != "Siemens AG" {
		t.Errorf("VendorName(0x002A) = %q", got)
	}
}

// TestVendorName_Unknown: unknown vendor → empty.
func TestVendorName_Unknown(t *testing.T) {
	if got := profinet.VendorName(0xFFFF); got != "" {
		t.Errorf("VendorName(0xFFFF) = %q, want empty", got)
	}
}

// TestDeviceName_S71500: known vendor + known device.
func TestDeviceName_S71500(t *testing.T) {
	got := profinet.DeviceName(0x002A, 0x010E)
	if !strings.Contains(got, "S7-1500") {
		t.Errorf("DeviceName = %q, want contains S7-1500", got)
	}
}

// TestDeviceName_UnknownDevice: known vendor + unknown device → empty.
func TestDeviceName_UnknownDevice(t *testing.T) {
	if got := profinet.DeviceName(0x002A, 0xFFFF); got != "" {
		t.Errorf("DeviceName = %q, want empty", got)
	}
}

// TestFormatVendorDevice_FullMatch.
func TestFormatVendorDevice_FullMatch(t *testing.T) {
	got := profinet.FormatVendorDevice(0x002A, 0x010E)
	if !strings.Contains(got, "Siemens") || !strings.Contains(got, "S7-1500") {
		t.Errorf("FormatVendorDevice = %q", got)
	}
}

// TestFormatVendorDevice_VendorOnly.
func TestFormatVendorDevice_VendorOnly(t *testing.T) {
	got := profinet.FormatVendorDevice(0x002A, 0xFFFF)
	if !strings.Contains(got, "Siemens AG · 0xFFFF") {
		t.Errorf("FormatVendorDevice = %q", got)
	}
}

// TestFormatVendorDevice_BothUnknown.
func TestFormatVendorDevice_BothUnknown(t *testing.T) {
	got := profinet.FormatVendorDevice(0x9999, 0xFFFF)
	if got != "0x9999 · 0xFFFF" {
		t.Errorf("FormatVendorDevice = %q", got)
	}
}

// TestVendorRegistrySize: sanity check; we should have at
// least 15 vendors curated.
func TestVendorRegistrySize(t *testing.T) {
	if n := profinet.VendorRegistrySize(); n < 15 {
		t.Errorf("VendorRegistrySize = %d, want >= 15", n)
	}
}
