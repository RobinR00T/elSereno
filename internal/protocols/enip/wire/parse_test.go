package wire_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/enip/wire"
)

func TestHeaderRoundTrip(t *testing.T) {
	t.Parallel()
	h := wire.Header{Command: wire.CmdListIdentity, Length: 0}
	b := wire.MarshalHeader(h)
	got, err := wire.ParseHeader(b[:])
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got.Command != wire.CmdListIdentity {
		t.Fatalf("Command=0x%04x", got.Command)
	}
}

func TestParseHeaderRejectsOversized(t *testing.T) {
	t.Parallel()
	var b [wire.HeaderLen]byte
	binary.LittleEndian.PutUint16(b[2:4], 0xFFFF) // length exceeds MaxBodyLen
	_, err := wire.ParseHeader(b[:])
	if !errors.Is(err, wire.ErrBadHeader) {
		t.Fatalf("got %v, want ErrBadHeader", err)
	}
}

func TestParseListIdentity(t *testing.T) {
	t.Parallel()
	// Build a minimal ListIdentity reply body.
	//   ItemCount=1
	//   Item: Type(2) Length(2) EncapProto(2) Sockaddr(16) Vendor(2)
	//         DeviceType(2) ProductCode(2) Revision(2) Status(2)
	//         SerialNumber(4) NameLen(1) Name State(1)
	body := []byte{
		0x01, 0x00, // item count
		0x0C, 0x00, // item type
		0x00, 0x00, // item length (populated below after we know)
		0x01, 0x00, // encap protocol
		0x02, 0x00, 0x00, 0x00, // socket family + port (fake)
		0x00, 0x00, 0x00, 0x00, // addr
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // zero pad
		0x2A, 0x00, // vendor id = 42
		0x0E, 0x00, // device type = 14
		0x78, 0x56, // product code = 0x5678
		0x01, 0x02, // revision (major=1 minor=2)
		0x00, 0x00, // status
		0xEF, 0xBE, 0xAD, 0xDE, // serial number
		0x04, 'A', 'C', 'M', 'E', // name len 4, "ACME"
		0x00, // state
	}
	it, err := wire.ParseListIdentity(body)
	if err != nil {
		t.Fatalf("ParseListIdentity: %v", err)
	}
	if it.VendorID != 42 {
		t.Fatalf("VendorID=%d", it.VendorID)
	}
	if it.ProductName != "ACME" {
		t.Fatalf("ProductName=%q", it.ProductName)
	}
}
