package wire

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		fc   FunctionCode
		want Category
	}{
		{FuncReadVar, CategoryRead},
		{FuncCommSetup, CategoryRead},
		{FuncWriteVar, CategoryWrite},
		{FuncPLCControl, CategoryWrite},
		{FuncPLCStop, CategoryWrite},
		{FuncRequestDownload, CategoryWrite},
		{FuncDownloadBlock, CategoryWrite},
		{FuncDownloadEnded, CategoryWrite},
		{FuncStartUpload, CategoryWrite},
		{FuncUpload, CategoryWrite},
		{FuncEndUpload, CategoryWrite},
		{FunctionCode(0x99), CategoryUnknown},
	}
	for _, c := range cases {
		if got := Classify(c.fc); got != c.want {
			t.Errorf("Classify(0x%02x) = %d, want %d", c.fc, got, c.want)
		}
	}
}

func TestExtractFunctionCode_Job(t *testing.T) {
	// ROSCTR=Job (0x01): header is 10 bytes, parameter starts at [10].
	payload := []byte{
		0x32, 0x01, // protoID, ROSCTR Job
		0x00, 0x00, // redundancy
		0x00, 0x01, // pduRef
		0x00, 0x02, // paramLen=2
		0x00, 0x00, // dataLen
		0x05, 0x00, // parameter[0] = FuncWriteVar, parameter[1] = itemCount
	}
	fc, ok := ExtractFunctionCode(payload)
	if !ok {
		t.Fatal("expected ok")
	}
	if fc != FuncWriteVar {
		t.Fatalf("fc = 0x%02x, want 0x%02x", fc, FuncWriteVar)
	}
}

func TestExtractFunctionCode_AckData(t *testing.T) {
	// ROSCTR=AckData (0x03): header is 12 bytes, parameter starts at [12].
	payload := []byte{
		0x32, 0x03,
		0x00, 0x00,
		0x00, 0x01,
		0x00, 0x02,
		0x00, 0x00,
		0x00, 0x00, // errClass, errCode
		0x04, 0x01, // parameter[0] = FuncReadVar
	}
	fc, ok := ExtractFunctionCode(payload)
	if !ok {
		t.Fatal("expected ok")
	}
	if fc != FuncReadVar {
		t.Fatalf("fc = 0x%02x, want 0x%02x", fc, FuncReadVar)
	}
}

func TestExtractFunctionCode_ShortPayload(t *testing.T) {
	if _, ok := ExtractFunctionCode([]byte{0x32, 0x01, 0, 0}); ok {
		t.Fatalf("expected not-ok for short payload")
	}
}

func TestExtractFunctionCode_WrongProtoID(t *testing.T) {
	// 10 bytes of garbage that is not protocol 0x32.
	payload := []byte{0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x04}
	if _, ok := ExtractFunctionCode(payload); ok {
		t.Fatalf("expected not-ok for non-S7 payload")
	}
}

func TestBuildRefusalPayload(t *testing.T) {
	// A minimal request with pduRef=0x0001: refusal must echo it.
	req := []byte{
		0x32, 0x01,
		0x00, 0x00,
		0x00, 0x01,
		0x00, 0x02,
		0x00, 0x00,
		0x05, 0x00,
	}
	out := BuildRefusalPayload(req)
	// 3 COTP + 12 S7 = 15 bytes.
	if len(out) != 15 {
		t.Fatalf("len=%d, want 15", len(out))
	}
	// COTP header.
	if out[0] != 0x02 || out[1] != 0xF0 || out[2] != 0x80 {
		t.Fatalf("COTP header wrong: % x", out[:3])
	}
	// S7 AckData, pduRef echo, error class 0x85 / code 0x01.
	if out[3] != 0x32 || out[4] != 0x03 {
		t.Fatalf("S7 magic/ROSCTR wrong")
	}
	if out[7] != 0x00 || out[8] != 0x01 {
		t.Fatalf("pduRef echo wrong: % x", out[7:9])
	}
	if out[13] != 0x85 || out[14] != 0x01 {
		t.Fatalf("err class/code wrong: % x", out[13:15])
	}
}
