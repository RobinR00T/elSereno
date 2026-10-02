package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/modbus/wire"
)

func TestMBAPRoundTrip(t *testing.T) {
	t.Parallel()
	m := wire.MBAP{TxID: 0xbeef, Protocol: wire.ProtocolID, Length: 6, Unit: 1}
	b := wire.MarshalMBAP(m)
	got, err := wire.ParseMBAP(b[:])
	if err != nil {
		t.Fatalf("ParseMBAP: %v", err)
	}
	if got != m {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, m)
	}
}

func TestMBAPRejectsNonZeroProtocol(t *testing.T) {
	t.Parallel()
	b := [...]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x01}
	_, err := wire.ParseMBAP(b[:])
	if !errors.Is(err, wire.ErrBadProtocol) {
		t.Fatalf("got %v, want ErrBadProtocol", err)
	}
}

func TestMBAPRejectsShortLength(t *testing.T) {
	t.Parallel()
	b := [...]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01}
	_, err := wire.ParseMBAP(b[:])
	if !errors.Is(err, wire.ErrLengthMismatch) {
		t.Fatalf("got %v, want ErrLengthMismatch", err)
	}
}

func TestMBAPRejectsOversizedLength(t *testing.T) {
	t.Parallel()
	// Length=500 => well above MaxPDULen (253).
	b := [...]byte{0x00, 0x01, 0x00, 0x00, 0x01, 0xF4, 0x01}
	_, err := wire.ParseMBAP(b[:])
	if !errors.Is(err, wire.ErrPDUTooLong) {
		t.Fatalf("got %v, want ErrPDUTooLong", err)
	}
}

func TestFrameReadWriteRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	req := wire.BuildReadCoilsRequest(0x0001, 0x11)
	if err := wire.WriteFrame(&buf, req); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := wire.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.MBAP.TxID != 0x0001 || got.MBAP.Unit != 0x11 {
		t.Fatalf("MBAP mismatch: %+v", got.MBAP)
	}
	if got.FunctionCode() != wire.FCReadCoils {
		t.Fatalf("FC=%d want ReadCoils", got.FunctionCode())
	}
}

func TestExceptionFrame(t *testing.T) {
	t.Parallel()
	// FC 0x81 = Read Coils with exception bit; exception code 0x01.
	f := wire.Frame{
		MBAP: wire.MBAP{TxID: 1, Unit: 1},
		PDU:  []byte{0x81, byte(wire.ExIllegalFunction)},
	}
	if !f.IsExceptionFrame() {
		t.Fatal("IsExceptionFrame false")
	}
	code, ok := f.ExceptionCode()
	if !ok || code != wire.ExIllegalFunction {
		t.Fatalf("ExceptionCode=%d ok=%v", code, ok)
	}
	if f.FunctionCode() != wire.FCReadCoils {
		t.Fatalf("FC after stripping exception bit = %d", f.FunctionCode())
	}
}

func TestClassifyWriteFCs(t *testing.T) {
	t.Parallel()
	writes := []wire.FunctionCode{
		wire.FCWriteSingleCoil,
		wire.FCWriteSingleRegister,
		wire.FCWriteMultipleCoils,
		wire.FCWriteMultipleRegisters,
		wire.FCWriteFileRecord,
		wire.FCMaskWriteRegister,
		wire.FCReadWriteMultipleRegisters,
	}
	for _, fc := range writes {
		if wire.Classify(fc) != wire.CategoryWrite {
			t.Fatalf("FC 0x%02x classified %v, want Write", uint8(fc), wire.Classify(fc))
		}
	}
	reads := []wire.FunctionCode{
		wire.FCReadCoils, wire.FCReadDiscreteInputs,
		wire.FCReadHoldingRegisters, wire.FCReadInputRegisters,
	}
	for _, fc := range reads {
		if wire.Classify(fc) != wire.CategoryRead {
			t.Fatalf("FC 0x%02x classified %v, want Read", uint8(fc), wire.Classify(fc))
		}
	}
}

func TestDeviceIDObjectsParse(t *testing.T) {
	t.Parallel()
	// Real FC43/14 response PDU, byte for byte from a captured Modbus/TCP
	// session (CISA cisagov/icsnpp-modbus testing/traces/modbus_example.pcap,
	// packet 94). 7-byte header then three Basic objects:
	//  2b 0e            FC=0x2B, MEI=0x0E
	//  01               Read Device ID code = 01 (Basic)
	//  83               Conformity level = 0x83
	//  00               More Follows = 0x00
	//  00               Next Object Id = 0x00
	//  03               Number of Objects = 3
	//  00 10 "Zeek Modbus Test"           obj0 VendorName (len 16)
	//  01 18 "Protocol Parsing is fun!"   obj1 ProductCode (len 24)
	//  02 07 "1.2.3.6"                    obj2 MajorMinorRevision (len 7)
	pdu := []byte{
		0x2B, 0x0E, 0x01, 0x83, 0x00, 0x00, 0x03,
		0x00, 0x10, 'Z', 'e', 'e', 'k', ' ', 'M', 'o', 'd', 'b', 'u', 's', ' ', 'T', 'e', 's', 't',
		0x01, 0x18, 'P', 'r', 'o', 't', 'o', 'c', 'o', 'l', ' ', 'P', 'a', 'r', 's', 'i', 'n', 'g', ' ', 'i', 's', ' ', 'f', 'u', 'n', '!',
		0x02, 0x07, '1', '.', '2', '.', '3', '.', '6',
	}
	objs, err := wire.DeviceIDObjects(pdu)
	if err != nil {
		t.Fatalf("DeviceIDObjects: %v", err)
	}
	if objs[0x00] != "Zeek Modbus Test" {
		t.Errorf("VendorName=%q, want %q", objs[0x00], "Zeek Modbus Test")
	}
	if objs[0x01] != "Protocol Parsing is fun!" {
		t.Errorf("ProductCode=%q, want %q", objs[0x01], "Protocol Parsing is fun!")
	}
	if objs[0x02] != "1.2.3.6" {
		t.Errorf("MajorMinorRevision=%q, want %q", objs[0x02], "1.2.3.6")
	}
	if len(objs) != 3 {
		t.Errorf("got %d objects, want 3", len(objs))
	}
}
