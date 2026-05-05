package wire

import (
	"errors"
	"testing"
)

// TestServiceType pins the 16-bit BE extraction at offset [2:4].
func TestServiceType(t *testing.T) {
	frame := []byte{0x06, 0x10, 0x04, 0x20, 0x00, 0x10}
	got, err := ServiceType(frame)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != ServiceTypeTunnellingRequest {
		t.Errorf("got 0x%04x, want 0x%04x", got, ServiceTypeTunnellingRequest)
	}
}

// TestServiceType_TooShort returns the sentinel.
func TestServiceType_TooShort(t *testing.T) {
	_, err := ServiceType([]byte{0x06, 0x10, 0x04})
	if !errors.Is(err, ErrServiceTypeMissing) {
		t.Errorf("err = %v, want ErrServiceTypeMissing", err)
	}
}

// buildTunnelling constructs a TUNNELLING_REQUEST framing the cEMI
// L_Data.req that writes a single bit to group address 1/0/3.
//
//	GroupValue_Write APCI = 0x080.
//	Short-form: APCI byte top 2 bits = 0x80 >> 4 = 0x08;
//	apciByte = 0x80 | (data & 0x3F) = 0x80 | 1 = 0x81 for ON.
//
// The frame layout we build:
//
//	hdr 6:  0x06 0x10 0x04 0x20 0x00 [total]
//	connhdr 4: 0x04 channel seq 0x00
//	cEMI 11: 0x11 0x00 ctrl1 ctrl2 srcHi srcLo dstHi dstLo 0x01 tpci apci
//
// buildTunnelling: dst is fixed at 0x0803 in test cases below
// because the inner-cEMI parsing is what's under test, not the
// destination-address byte handling — but we keep dst as a
// parameter to document the intent. nolint:unparam avoids the
// false-positive complaint about it always being 0x0803.
//
//nolint:unparam // dst documents intent; see comment above
func buildTunnelling(msgCode byte, dst uint16, isGroup bool, tpci, apci byte) []byte {
	frame := []byte{0x06, 0x10, 0x04, 0x20, 0x00, 0x15}
	frame = append(frame, 0x04, 0x01, 0x00, 0x00) // connection header
	ctrl2 := byte(0x00)
	if isGroup {
		ctrl2 = 0x80
	}
	frame = append(frame,
		msgCode, 0x00, // MsgCode + addInfoLen
		0xBC, ctrl2, // Control1 + Control2
		0x11, 0x01, // Source IA = 1.1.1
		byte(dst>>8), byte(dst&0xFF), // dest
		0x01, // NPDU length
		tpci, apci,
	)
	return frame
}

// TestParseTunnellingCEMI_GroupWrite extracts the canonical
// short-form GroupValue_Write to 1/0/3 = 0x0803.
func TestParseTunnellingCEMI_GroupWrite(t *testing.T) {
	dst := uint16(0x0803) // 1/0/3
	// short-form GroupValue_Write data=1 (turn on)
	tpci := byte(0x00) // top 6 bits TPCI = 0; bottom 2 = APCI[9..8] = 0
	apci := byte(0x81) // top 4 bits = 0x8 (Write); bottom 6 = data=1
	frame := buildTunnelling(CEMILDataReq, dst, true, tpci, apci)
	got, err := ParseTunnellingCEMI(frame)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got.MsgCode != CEMILDataReq {
		t.Errorf("MsgCode = 0x%02x, want 0x11", got.MsgCode)
	}
	if !got.DestIsGroup {
		t.Errorf("DestIsGroup should be true")
	}
	if got.DestAddr != dst {
		t.Errorf("DestAddr = 0x%04x, want 0x%04x", got.DestAddr, dst)
	}
	if got.APCI != APCIGroupValueWrite {
		t.Errorf("APCI = 0x%03x, want 0x%03x", got.APCI, APCIGroupValueWrite)
	}
}

// TestParseTunnellingCEMI_GroupRead distinguishes Read (0x000)
// from Write (0x080).
func TestParseTunnellingCEMI_GroupRead(t *testing.T) {
	frame := buildTunnelling(CEMILDataReq, 0x0803, true, 0x00, 0x00)
	got, err := ParseTunnellingCEMI(frame)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got.APCI != APCIGroupValueRead {
		t.Errorf("APCI = 0x%03x, want APCIGroupValueRead 0x%03x", got.APCI, APCIGroupValueRead)
	}
}

// TestParseTunnellingCEMI_TooShort refuses bodies shorter than the
// L_Data minimum.
func TestParseTunnellingCEMI_TooShort(t *testing.T) {
	frame := []byte{0x06, 0x10, 0x04, 0x20, 0x00, 0x0A, 0x04, 0x01, 0x00, 0x00, 0x11, 0x00}
	_, err := ParseTunnellingCEMI(frame)
	if !errors.Is(err, ErrCEMITooShort) {
		t.Errorf("err = %v, want ErrCEMITooShort", err)
	}
}

// TestParseTunnellingCEMI_NotLData refuses cEMI bodies whose
// MsgCode isn't an L_Data variant (e.g., 0x10 L_Raw.req).
func TestParseTunnellingCEMI_NotLData(t *testing.T) {
	frame := buildTunnelling(0x10, 0x0803, true, 0x00, 0x81)
	_, err := ParseTunnellingCEMI(frame)
	if !errors.Is(err, ErrCEMINotLData) {
		t.Errorf("err = %v, want ErrCEMINotLData", err)
	}
}

// TestParseTunnellingCEMI_BadConnHeader refuses frames whose
// connection-header length isn't 0x04.
func TestParseTunnellingCEMI_BadConnHeader(t *testing.T) {
	frame := buildTunnelling(CEMILDataReq, 0x0803, true, 0x00, 0x81)
	frame[6] = 0x05 // wrong conn-header length
	_, err := ParseTunnellingCEMI(frame)
	if !errors.Is(err, ErrTunnellingBodyTooShort) {
		t.Errorf("err = %v, want ErrTunnellingBodyTooShort", err)
	}
}

// TestParseCEMILData_AddInfo skips a non-zero additional-info
// block correctly.
func TestParseCEMILData_AddInfo(t *testing.T) {
	body := []byte{
		CEMILDataReq, 0x02, 0xAA, 0xBB, // addInfoLen=2 + 2 dummy bytes
		0xBC, 0x80, // ctrl1 + ctrl2 (group)
		0x11, 0x01, // src
		0x08, 0x03, // dst = 1/0/3
		0x01,       // NPDU
		0x00, 0x81, // tpci + apci (write data=1)
	}
	got, err := ParseCEMILData(body)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got.APCI != APCIGroupValueWrite {
		t.Errorf("APCI = 0x%03x, want Write", got.APCI)
	}
	if got.DestAddr != 0x0803 {
		t.Errorf("DestAddr = 0x%04x", got.DestAddr)
	}
}

// TestFormatGroupAddress pins the 5/3/8 bit-pack to canonical
// "main/middle/sub" form.
func TestFormatGroupAddress(t *testing.T) {
	for _, tc := range []struct {
		ga   uint16
		want string
	}{
		{0x0000, "0/0/0"},
		{0x0803, "1/0/3"}, // 5-bit main=1, 3-bit middle=0, 8-bit sub=3
		{0x100A, "2/0/10"},
		{0xFFFF, "31/7/255"},
	} {
		if got := FormatGroupAddress(tc.ga); got != tc.want {
			t.Errorf("FormatGroupAddress(0x%04x) = %q, want %q", tc.ga, got, tc.want)
		}
	}
}
