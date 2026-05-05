package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// buildWrappedAPDU constructs a DLMS wrapper + APDU body.
func buildWrappedAPDU(apdu []byte) []byte {
	if len(apdu) > 0xFFFF {
		panic("buildWrappedAPDU: APDU too long")
	}
	frame := make([]byte, WrapperLen+len(apdu))
	binary.BigEndian.PutUint16(frame[0:2], WrapperVersion)
	binary.BigEndian.PutUint16(frame[2:4], SourceWPortClient)
	binary.BigEndian.PutUint16(frame[4:6], DestWPortServer)
	// #nosec G115 -- length range-checked above
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(apdu)))
	copy(frame[WrapperLen:], apdu)
	return frame
}

// buildSetRequestAPDU constructs a minimal SET-Request normal
// targeting (classID, OBIS, attrID).
func buildSetRequestAPDU(classID uint16, obis [6]byte, attrID byte) []byte {
	apdu := []byte{
		APDUTagSetRequest, // 0xC1
		0x01,              // CHOICE = set-request-normal
		0xC1,              // invoke-id-and-priority
	}
	classBytes := []byte{byte(classID >> 8), byte(classID & 0xFF)}
	apdu = append(apdu, classBytes...)
	apdu = append(apdu, obis[:]...)
	apdu = append(apdu, attrID)
	apdu = append(apdu, 0x00)             // selective-access = false
	apdu = append(apdu, 0x09, 0x01, 0xAA) // OCTET STRING data, len 1, value 0xAA
	return apdu
}

func buildActionRequestAPDU(classID uint16, obis [6]byte, methodID byte) []byte {
	apdu := []byte{APDUTagActionRequest, 0x01, 0xC1}
	apdu = append(apdu, byte(classID>>8), byte(classID&0xFF))
	apdu = append(apdu, obis[:]...)
	apdu = append(apdu, methodID)
	apdu = append(apdu, 0x00) // method-invocation-parameters absent
	return apdu
}

// TestReadFrame_Wrapper_Happy pins a SET-Request round-trip.
func TestReadFrame_Wrapper_Happy(t *testing.T) {
	apdu := buildSetRequestAPDU(70, [6]byte{0, 0, 96, 50, 0, 255}, 1)
	frame := buildWrappedAPDU(apdu)
	f, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if f.APDUTag != APDUTagSetRequest {
		t.Errorf("APDUTag = 0x%02x, want 0xC1", f.APDUTag)
	}
	if !bytes.Equal(f.APDU, apdu) {
		t.Errorf("APDU mismatch")
	}
	if f.SourceWPort != SourceWPortClient {
		t.Errorf("SourceWPort = 0x%04x", f.SourceWPort)
	}
}

func TestReadFrame_BadVersion(t *testing.T) {
	frame := []byte{0x00, 0x02, 0x00, 0x10, 0x00, 0x01, 0x00, 0x05, 0x60, 0x03, 0xA1, 0x01, 0x05}
	_, err := ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, ErrBadWrapperVersion) {
		t.Errorf("err = %v, want ErrBadWrapperVersion", err)
	}
}

func TestReadFrame_ZeroAPDULen(t *testing.T) {
	frame := []byte{0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00}
	_, err := ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, ErrAPDUTooShort) {
		t.Errorf("err = %v, want ErrAPDUTooShort", err)
	}
}

func TestReadFrame_TruncatedAPDU(t *testing.T) {
	frame := []byte{0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x10, 0xC1, 0x01, 0x00}
	_, err := ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF or io.ErrUnexpectedEOF", err)
	}
}

// TestParseSetRequest_Happy: target round-trip on disconnect
// control object.
func TestParseSetRequest_Happy(t *testing.T) {
	disconnectOBIS := [6]byte{0, 0, 96, 50, 0, 255}
	apdu := buildSetRequestAPDU(70, disconnectOBIS, 1)
	target, err := ParseSetRequest(apdu)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if target.ClassID != 70 {
		t.Errorf("ClassID = %d, want 70", target.ClassID)
	}
	if target.OBIS != disconnectOBIS {
		t.Errorf("OBIS = %v, want %v", target.OBIS, disconnectOBIS)
	}
	if target.MemberID != 1 {
		t.Errorf("MemberID = %d, want 1", target.MemberID)
	}
}

// TestParseSetRequest_NotSet refuses tag mismatches.
func TestParseSetRequest_NotSet(t *testing.T) {
	apdu := []byte{APDUTagGetRequest, 0x01, 0x00}
	_, err := ParseSetRequest(apdu)
	if !errors.Is(err, ErrAPDUNotSetRequest) {
		t.Errorf("err = %v, want ErrAPDUNotSetRequest", err)
	}
}

// TestParseSetRequest_ShortAPDU refuses short APDUs.
func TestParseSetRequest_ShortAPDU(t *testing.T) {
	apdu := []byte{APDUTagSetRequest, 0x01, 0x00, 0x00}
	_, err := ParseSetRequest(apdu)
	if !errors.Is(err, ErrAPDUTooShort) {
		t.Errorf("err = %v, want ErrAPDUTooShort", err)
	}
}

// TestParseSetRequest_UnknownChoice refuses non-normal CHOICE.
func TestParseSetRequest_UnknownChoice(t *testing.T) {
	apdu := []byte{APDUTagSetRequest, 0x02, 0x00, 0x00, 0x46, 0x00, 0x00, 0x60, 0x32, 0x00, 0xFF, 0x01}
	_, err := ParseSetRequest(apdu)
	if !errors.Is(err, ErrAPDUUnknownChoice) {
		t.Errorf("err = %v, want ErrAPDUUnknownChoice", err)
	}
}

// TestParseActionRequest_Happy works for ACTION-Request.
func TestParseActionRequest_Happy(t *testing.T) {
	disconnectOBIS := [6]byte{0, 0, 96, 50, 0, 255}
	apdu := buildActionRequestAPDU(70, disconnectOBIS, 2)
	target, err := ParseActionRequest(apdu)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if target.MemberID != 2 {
		t.Errorf("MemberID = %d, want 2", target.MemberID)
	}
}

// TestIsAlwaysSafeAPDU pins the safe set.
func TestIsAlwaysSafeAPDU(t *testing.T) {
	for _, tc := range []struct {
		tag      byte
		expected bool
	}{
		{APDUTagAARQ, true},
		{APDUTagAARE, true},
		{APDUTagRLRQ, true},
		{APDUTagRLRE, true},
		{APDUTagGetRequest, true},
		{APDUTagGetResponse, true},
		{APDUTagSetRequest, false},
		{APDUTagActionRequest, false},
		{0xCC, false},
	} {
		if got := IsAlwaysSafeAPDU(tc.tag); got != tc.expected {
			t.Errorf("IsAlwaysSafeAPDU(0x%02x) = %v, want %v", tc.tag, got, tc.expected)
		}
	}
}

// TestFormatOBIS pins canonical "A-B:C.D.E*F" rendering.
func TestFormatOBIS(t *testing.T) {
	for _, tc := range []struct {
		obis [6]byte
		want string
	}{
		{[6]byte{0, 0, 0, 0, 0, 255}, "0-0:0.0.0*255"},
		{[6]byte{0, 0, 96, 50, 0, 255}, "0-0:96.50.0*255"},
		{[6]byte{1, 0, 94, 7, 0, 255}, "1-0:94.7.0*255"},
	} {
		if got := FormatOBIS(tc.obis); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}
