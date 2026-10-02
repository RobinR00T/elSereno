package wire_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/modbus/wire"
)

// TestReadFrame_RealCapture validates MBAP + PDU parsing, function-code
// masking, and exception detection against real Modbus/TCP frames, byte for
// byte from CISA cisagov/icsnpp-modbus testing/traces/modbus_example.pcap.
// Real wire, not a hand-built fixture (see PITF-064).
func TestReadFrame_RealCapture(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		frame   string // full MBAP+PDU hex, as captured
		txid    uint16
		unit    uint8
		fc      wire.FunctionCode
		isExc   bool
		excCode wire.ExceptionCode
	}{
		{"fc01_read_coils_req", "000100000006040100010001", 0x0001, 0x04, wire.FCReadCoils, false, 0},
		{"fc01_read_coils_resp", "00010000000404010101", 0x0001, 0x04, wire.FCReadCoils, false, 0},
		{"fc03_read_holding_req", "000500000006040300010001", 0x0005, 0x04, wire.FCReadHoldingRegisters, false, 0},
		{"fc03_read_holding_resp", "00050000000504030200aa", 0x0005, 0x04, wire.FCReadHoldingRegisters, false, 0},
		{"fc08_diagnostics_req", "000c00000006020800020000", 0x000c, 0x02, wire.FCDiagnostics, false, 0},
		{"fc17_rw_multiple_req", "00140000000d061700010001000200010200ff", 0x0014, 0x06, wire.FCReadWriteMultipleRegisters, false, 0},
		{"fc17_rw_multiple_resp", "00140000000506170200aa", 0x0014, 0x06, wire.FCReadWriteMultipleRegisters, false, 0},
		{"fc03_exception_resp", "000100000003008302", 0x0001, 0x00, wire.FCReadHoldingRegisters, true, wire.ExIllegalDataAddress},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := hex.DecodeString(tc.frame)
			if err != nil {
				t.Fatal(err)
			}
			f, err := wire.ReadFrame(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if f.MBAP.TxID != tc.txid {
				t.Errorf("TxID=0x%04x, want 0x%04x", f.MBAP.TxID, tc.txid)
			}
			if f.MBAP.Unit != tc.unit {
				t.Errorf("Unit=0x%02x, want 0x%02x", f.MBAP.Unit, tc.unit)
			}
			if f.FunctionCode() != tc.fc {
				t.Errorf("FunctionCode=0x%02x, want 0x%02x", uint8(f.FunctionCode()), uint8(tc.fc))
			}
			if f.IsExceptionFrame() != tc.isExc {
				t.Errorf("IsExceptionFrame=%v, want %v", f.IsExceptionFrame(), tc.isExc)
			}
			if tc.isExc {
				ec, ok := f.ExceptionCode()
				if !ok || ec != tc.excCode {
					t.Errorf("ExceptionCode=0x%02x ok=%v, want 0x%02x", uint8(ec), ok, uint8(tc.excCode))
				}
			}
		})
	}
}

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
