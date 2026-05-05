package wire

import (
	"encoding/binary"
	"errors"
	"testing"
)

// TestBuildReadDeviceInfo pins the on-wire shape: 6 +
// 32 = 38 bytes total, target NetID echoed correctly,
// command 0x0001, request flag set.
func TestBuildReadDeviceInfo(t *testing.T) {
	netID := [6]byte{0x0A, 0x00, 0x00, 0x01, 0x01, 0x01}
	frame := BuildReadDeviceInfo(netID)
	if len(frame) != FrameMinLen {
		t.Fatalf("frame len = %d, want %d", len(frame), FrameMinLen)
	}
	if frame[0] != 0x00 || frame[1] != 0x00 {
		t.Errorf("AMS/TCP prefix = 0x%02x%02x", frame[0], frame[1])
	}
	if got := binary.LittleEndian.Uint32(frame[2:6]); got != uint32(AMSHeaderLen) {
		t.Errorf("length field = %d", got)
	}
	for i, b := range netID {
		if frame[6+i] != b {
			t.Errorf("target NetID[%d] = 0x%02x, want 0x%02x", i, frame[6+i], b)
		}
	}
	if got := binary.LittleEndian.Uint16(frame[12:14]); got != AMSPortRouter {
		t.Errorf("target port = %d, want %d", got, AMSPortRouter)
	}
	if got := binary.LittleEndian.Uint16(frame[22:24]); got != CmdReadDeviceInfo {
		t.Errorf("cmd = 0x%04x, want 0x%04x", got, CmdReadDeviceInfo)
	}
	flags := binary.LittleEndian.Uint16(frame[24:26])
	// bit2 set, bit0 clear → request
	if flags&0x0001 != 0 {
		t.Errorf("request frame has response bit set: 0x%04x", flags)
	}
	if flags&0x0004 == 0 {
		t.Errorf("request frame missing ADS-cmd bit: 0x%04x", flags)
	}
}

// buildResponse constructs a synthetic
// ReadDeviceInfo response for tests. errCode 0 + version
// 3.1.4024 + name "TC3 PLC1".
func buildResponse(errCode uint32, major, minor uint8, build uint16, name string) []byte {
	dataLen := uint32(8 + 16)
	body := AMSHeaderLen + int(dataLen)
	frame := make([]byte, AMSTCPHeaderLen+body)
	frame[0] = 0
	frame[1] = 0
	binary.LittleEndian.PutUint32(frame[2:6], uint32(body)) // #nosec G115 -- test fixture
	// AMS header: target/source NetIDs/ports zero (stand-in)
	binary.LittleEndian.PutUint16(frame[22:24], CmdReadDeviceInfo)
	binary.LittleEndian.PutUint16(frame[24:26], 0x0005) // bit0 = response, bit2 = ADS cmd
	binary.LittleEndian.PutUint32(frame[26:30], dataLen)
	// Payload starts at byte 38
	off := 38
	binary.LittleEndian.PutUint32(frame[off:off+4], errCode)
	frame[off+4] = major
	frame[off+5] = minor
	binary.LittleEndian.PutUint16(frame[off+6:off+8], build)
	copy(frame[off+8:off+8+16], []byte(name))
	return frame
}

func TestParseDeviceInfo_Happy(t *testing.T) {
	resp := buildResponse(0, 3, 1, 4024, "TC3 PLC1")
	info, err := ParseDeviceInfo(resp)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if info.MajorVersion != 3 || info.MinorVersion != 1 || info.VersionBuild != 4024 {
		t.Errorf("version = %d.%d.%d", info.MajorVersion, info.MinorVersion, info.VersionBuild)
	}
	if info.Name != "TC3 PLC1" {
		t.Errorf("name = %q", info.Name)
	}
}

func TestParseDeviceInfo_NULPaddedName(t *testing.T) {
	resp := buildResponse(0, 2, 11, 2308, "TCatPlcCtrl") // shorter than 16 bytes
	info, err := ParseDeviceInfo(resp)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if info.Name != "TCatPlcCtrl" {
		t.Errorf("name = %q (NUL-padding leak?)", info.Name)
	}
}

func TestParseDeviceInfo_ShortFrame(t *testing.T) {
	resp := []byte{0x00, 0x00}
	_, err := ParseDeviceInfo(resp)
	if !errors.Is(err, ErrShortFrame) {
		t.Errorf("err = %v, want ErrShortFrame", err)
	}
}

func TestParseDeviceInfo_BadAMSTCP(t *testing.T) {
	resp := buildResponse(0, 3, 1, 4024, "TC3 PLC1")
	resp[0] = 0xCA // invalid prefix
	_, err := ParseDeviceInfo(resp)
	if !errors.Is(err, ErrBadAMSTCP) {
		t.Errorf("err = %v, want ErrBadAMSTCP", err)
	}
}

func TestParseDeviceInfo_NotResponse(t *testing.T) {
	resp := buildResponse(0, 3, 1, 4024, "TC3 PLC1")
	binary.LittleEndian.PutUint16(resp[24:26], 0x0004) // request, not response
	_, err := ParseDeviceInfo(resp)
	if !errors.Is(err, ErrNotADSResponse) {
		t.Errorf("err = %v, want ErrNotADSResponse", err)
	}
}

func TestParseDeviceInfo_ADSError(t *testing.T) {
	resp := buildResponse(0x07, 0, 0, 0, "") // ADS error 7 = Unknown Group
	_, err := ParseDeviceInfo(resp)
	if !errors.Is(err, ErrNotADSResponse) {
		t.Errorf("err = %v, want ErrNotADSResponse", err)
	}
}

func TestParseDeviceInfo_LengthOverflow(t *testing.T) {
	resp := buildResponse(0, 3, 1, 4024, "TC3")
	// Bump the AMS/TCP length field beyond MaxBodyLen.
	binary.LittleEndian.PutUint32(resp[2:6], MaxBodyLen+1)
	_, err := ParseDeviceInfo(resp)
	if !errors.Is(err, ErrLengthMismatch) {
		t.Errorf("err = %v, want ErrLengthMismatch", err)
	}
}
