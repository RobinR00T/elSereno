package profinet_test

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/profinet"
)

// TestEncodeIdentifyAll: the request shape matches the
// IEC 61158 layout: FrameID=0xFEFE, ServiceID=Identify,
// ServiceType=Request, BlockLength=2, BlockInfo=0.
func TestEncodeIdentifyAll(t *testing.T) {
	frame := profinet.EncodeDCPIdentifyAll(0xCAFEBABE)
	if len(frame) != 18 {
		t.Fatalf("frame len = %d, want 18", len(frame))
	}
	if got := binary.BigEndian.Uint16(frame[0:2]); got != profinet.FrameIDIdentifyRequest {
		t.Errorf("FrameID = 0x%04X", got)
	}
	if frame[2] != profinet.ServiceIdentify {
		t.Errorf("ServiceID = 0x%02X", frame[2])
	}
	if frame[3] != profinet.ServiceTypeRequest {
		t.Errorf("ServiceType = 0x%02X", frame[3])
	}
	if got := binary.BigEndian.Uint32(frame[4:8]); got != 0xCAFEBABE {
		t.Errorf("XID = 0x%08X", got)
	}
	// Block: Option=0xFF, Suboption=0xFF, Length=2, BlockInfo=0.
	if frame[12] != 0xFF || frame[13] != 0xFF {
		t.Errorf("block option/sub = 0x%02X 0x%02X, want FF FF", frame[12], frame[13])
	}
}

// TestDecodeDCP_RoundTrip: encode + decode preserves the
// header fields.
func TestDecodeDCP_RoundTrip(t *testing.T) {
	frame := profinet.EncodeDCPIdentifyAll(0xDEAD_BEEF)
	f, err := profinet.DecodeDCP(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Header.FrameID != profinet.FrameIDIdentifyRequest {
		t.Errorf("FrameID = 0x%04X", f.Header.FrameID)
	}
	if f.Header.XID != 0xDEADBEEF {
		t.Errorf("XID = 0x%08X", f.Header.XID)
	}
	if len(f.Blocks) != 1 {
		t.Fatalf("blocks = %d, want 1", len(f.Blocks))
	}
	if f.Blocks[0].Option != profinet.OptionAll || f.Blocks[0].Suboption != profinet.OptionAll {
		t.Errorf("block opt/sub = %d/%d", f.Blocks[0].Option, f.Blocks[0].Suboption)
	}
}

// TestDecodeDCP_TooShort.
func TestDecodeDCP_TooShort(t *testing.T) {
	_, err := profinet.DecodeDCP([]byte{0xFE})
	if !errors.Is(err, profinet.ErrShortDCP) {
		t.Errorf("err = %v, want ErrShortDCP", err)
	}
}

// TestParseIdentifyResponse_Siemens: synthetic response
// frame with NameOfStation + DeviceID + IPParameter blocks.
func TestParseIdentifyResponse_Siemens(t *testing.T) {
	// Header: response, XID arbitrary, dataLength computed.
	station := "plcxb1.cell-3.factory.local"
	// Build the blocks (4 of them).
	blocks := []byte{}
	// Block 1: Option=Device, Sub=NameOfStation, Length=2+len(name)
	nameBlk := []byte{profinet.OptionDevice, profinet.SubDeviceNameOfStation}
	nameLen := 2 + len(station)
	if nameLen > 0xFFFF {
		t.Fatalf("station name too long for uint16: %d", nameLen)
	}
	nameBlk = append(nameBlk, byte(nameLen>>8), byte(nameLen&0xFF)) // #nosec G115 — bounded above.
	nameBlk = append(nameBlk, 0x00, 0x00)                           // BlockInfo
	nameBlk = append(nameBlk, station...)
	blocks = append(blocks, nameBlk...)
	if len(nameBlk)%2 != 0 {
		blocks = append(blocks, 0x00) // pad
	}
	// Block 2: Option=Device, Sub=DeviceID, Length=6 (2 BlockInfo + 4 data)
	devBlk := []byte{profinet.OptionDevice, profinet.SubDeviceID,
		0x00, 0x06, 0x00, 0x00,
		0x00, 0x2A, 0x01, 0x23} // VendorID=0x002A (Siemens), DeviceID=0x0123
	blocks = append(blocks, devBlk...)
	// Block 3: Option=Device, Sub=Role
	roleBlk := []byte{profinet.OptionDevice, profinet.SubDeviceRole,
		0x00, 0x04, 0x00, 0x00,
		0x02, 0x00} // role=0x02 (IO-Device), 1 byte data + 1 pad
	blocks = append(blocks, roleBlk...)
	// Block 4: Option=IP, Sub=Parameter, Length=14 (2 BlockInfo + 12 data)
	ipBlk := []byte{profinet.OptionIP, profinet.SubIPParameter,
		0x00, 0x0E, 0x00, 0x00,
		192, 168, 10, 50, // IP
		255, 255, 255, 0, // Subnet
		192, 168, 10, 1, // Gateway
	}
	blocks = append(blocks, ipBlk...)
	// Pad to even.
	if len(blocks)%2 != 0 {
		blocks = append(blocks, 0x00)
	}
	// Assemble frame.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], profinet.FrameIDIdentifyResponse)
	hdr[2] = profinet.ServiceIdentify
	hdr[3] = profinet.ServiceTypeResponse
	binary.BigEndian.PutUint32(hdr[4:8], 0xCAFEBABE)
	binary.BigEndian.PutUint16(hdr[8:10], 0x0000)
	if len(blocks) > 0xFFFF {
		t.Fatalf("block too large for uint16 length: %d", len(blocks))
	}
	binary.BigEndian.PutUint16(hdr[10:12], uint16(len(blocks))) // #nosec G115 — bounded above.
	// Use single-slice append + grow pattern so gocritic's
	// appendAssign rule (which fires on `frame := append(hdr, ...)`
	// because frame is a *new* slice) doesn't complain.
	frame := make([]byte, 0, len(hdr)+len(blocks))
	frame = append(frame, hdr...)
	frame = append(frame, blocks...)

	f, err := profinet.DecodeDCP(frame)
	if err != nil {
		t.Fatalf("decode err: %v", err)
	}
	resp := profinet.ParseIdentifyResponse(f)
	if !strings.Contains(resp.NameOfStation, "plcxb1") {
		t.Errorf("NameOfStation = %q", resp.NameOfStation)
	}
	if resp.VendorID != 0x002A {
		t.Errorf("VendorID = 0x%04X", resp.VendorID)
	}
	if resp.DeviceID != 0x0123 {
		t.Errorf("DeviceID = 0x%04X", resp.DeviceID)
	}
	if resp.DeviceRole != 0x02 {
		t.Errorf("DeviceRole = 0x%02X", resp.DeviceRole)
	}
	if resp.IP.String() != "192.168.10.50" {
		t.Errorf("IP = %s", resp.IP)
	}
}

// TestFormatDeviceRole: multi-bit role renders as plus-
// joined string.
func TestFormatDeviceRole(t *testing.T) {
	for _, tc := range []struct {
		in   uint8
		want string
	}{
		{0x00, "none"},
		{0x01, "IO-Controller"},
		{0x02, "IO-Device"},
		{0x03, "IO-Controller+IO-Device"},
		{0x08, "PNIO-Supervisor"},
		{0xF0, "unknown(0xf0)"},
	} {
		if got := profinet.FormatDeviceRole(tc.in); got != tc.want {
			t.Errorf("FormatDeviceRole(0x%02X) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDecodeDCP_BlockTruncation: a frame whose declared
// DataLength exceeds the actual buffer should surface
// ErrShortBlock from the inner walker (decoder returns
// partial result + error).
func TestDecodeDCP_BlockTruncation(t *testing.T) {
	// 12-byte header with DataLength = 100, but only 4 bytes
	// of block data follow.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], profinet.FrameIDIdentifyResponse)
	hdr[2] = profinet.ServiceIdentify
	hdr[3] = profinet.ServiceTypeResponse
	binary.BigEndian.PutUint32(hdr[4:8], 0x11223344)
	binary.BigEndian.PutUint16(hdr[10:12], 100) // lie
	body := []byte{0x02, 0x02, 0x00, 0x32}
	frame := make([]byte, 0, len(hdr)+len(body))
	frame = append(frame, hdr...)
	frame = append(frame, body...)
	_, err := profinet.DecodeDCP(frame)
	if err == nil {
		t.Errorf("expected truncation error; got nil")
	}
}
