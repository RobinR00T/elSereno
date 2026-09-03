package wire

import "testing"

// diagFrame builds an FC 8 request carrying sub-function `sub` and a
// two-byte data field (0x0000). PDU = [0x08, subHi, subLo, 0x00, 0x00].
func diagFrame(sub uint16) Frame {
	return Frame{
		MBAP: MBAP{TxID: 1, Protocol: ProtocolID, Unit: 1},
		PDU: []byte{
			byte(FCDiagnostics),
			byte(sub >> 8), byte(sub & 0xFF),
			0x00, 0x00,
		},
	}
}

func TestDiagSubFunction_Extract(t *testing.T) {
	t.Parallel()
	cases := []uint16{0x0000, 0x0001, 0x0004, 0x000A, 0x0014, 0x1234}
	for _, want := range cases {
		f := diagFrame(want)
		got, ok := f.DiagSubFunction()
		if !ok {
			t.Fatalf("sub 0x%04x: ok=false, want true", want)
		}
		if uint16(got) != want {
			t.Fatalf("sub: got 0x%04x, want 0x%04x", uint16(got), want)
		}
	}
}

func TestDiagSubFunction_NotFC8(t *testing.T) {
	t.Parallel()
	// A read-coils frame is not FC 8: no sub-function.
	f := Frame{PDU: []byte{byte(FCReadCoils), 0x00, 0x01, 0x00, 0x01}}
	if _, ok := f.DiagSubFunction(); ok {
		t.Fatal("DiagSubFunction ok on a non-FC8 frame")
	}
}

func TestDiagSubFunction_ShortPDU(t *testing.T) {
	t.Parallel()
	// FC 8 with only the FC byte + one sub byte: too short for a
	// 16-bit sub-function.
	f := Frame{PDU: []byte{byte(FCDiagnostics), 0x00}}
	if _, ok := f.DiagSubFunction(); ok {
		t.Fatal("DiagSubFunction ok on a truncated FC8 PDU")
	}
}

func TestDiagIsReadOnly(t *testing.T) {
	t.Parallel()
	readOnly := []DiagSubFunction{
		DiagReturnQueryData, DiagReturnDiagRegister,
		DiagReturnBusMsgCount, DiagReturnBusCommErrCount,
		DiagReturnBusExcErrCount, DiagReturnSlaveMsgCount,
		DiagReturnSlaveNoRespCnt, DiagReturnSlaveNAKCount,
		DiagReturnSlaveBusyCount, DiagReturnBusOverrunCount,
	}
	for _, s := range readOnly {
		if !DiagIsReadOnly(s) {
			t.Errorf("sub 0x%04x: DiagIsReadOnly=false, want true", uint16(s))
		}
	}
	mutating := []DiagSubFunction{
		DiagRestartComms, DiagChangeASCIIDelimiter, DiagForceListenOnly,
		DiagClearCountersAndDiag, DiagClearOverrunCounter,
		0x0015, 0x00FF, 0x1234, // reserved / vendor → default-deny
	}
	for _, s := range mutating {
		if DiagIsReadOnly(s) {
			t.Errorf("sub 0x%04x: DiagIsReadOnly=true, want false (default-deny)", uint16(s))
		}
	}
}
