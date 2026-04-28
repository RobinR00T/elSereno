package wire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/knxip/wire"
)

func TestBuildDescriptionRequestLayout(t *testing.T) {
	t.Parallel()
	got := wire.BuildDescriptionRequest()
	want := []byte{
		0x06, 0x10, // header: len, version
		0x02, 0x04, // service type DESCRIPTION_REQUEST
		0x00, 0x0E, // total length 14
		0x08, 0x01, // HPAI: len 8, UDP
		0x00, 0x00, 0x00, 0x00, // anonymous IP
		0x00, 0x00, // port 0
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("frame mismatch:\n got=%x\nwant=%x", got, want)
	}
	if len(got) != 14 {
		t.Fatalf("frame length: got %d want 14", len(got))
	}
}

func TestParseDescriptionResponseSuccess(t *testing.T) {
	t.Parallel()
	resp := buildResp("MDT IP Interface")
	di, err := wire.ParseDescriptionResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if di.FriendlyName != "MDT IP Interface" {
		t.Fatalf("FriendlyName: got %q", di.FriendlyName)
	}
	if di.KNXMedium != 0x02 {
		t.Fatalf("KNXMedium: got 0x%02x want 0x02", di.KNXMedium)
	}
	if di.KNXIndividualAddress != 0x1101 {
		t.Fatalf("KNXIndividualAddress: got 0x%04x want 0x1101", di.KNXIndividualAddress)
	}
}

func TestParseDescriptionResponseShortFrame(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 5, 30, 59} {
		_, err := wire.ParseDescriptionResponse(make([]byte, n))
		if !errors.Is(err, wire.ErrShortFrame) {
			t.Fatalf("len=%d: expected ErrShortFrame, got %v", n, err)
		}
	}
}

func TestParseDescriptionResponseBadHeader(t *testing.T) {
	t.Parallel()
	resp := buildResp("MDT IP Interface")
	resp[1] = 0x11 // wrong protocol version
	_, err := wire.ParseDescriptionResponse(resp)
	if !errors.Is(err, wire.ErrBadHeader) {
		t.Fatalf("expected ErrBadHeader on wrong version, got %v", err)
	}

	resp2 := buildResp("MDT IP Interface")
	resp2[0] = 0x07 // wrong header length
	_, err = wire.ParseDescriptionResponse(resp2)
	if !errors.Is(err, wire.ErrBadHeader) {
		t.Fatalf("expected ErrBadHeader on wrong header len, got %v", err)
	}
}

func TestParseDescriptionResponseWrongServiceType(t *testing.T) {
	t.Parallel()
	resp := buildResp("MDT IP Interface")
	binary.BigEndian.PutUint16(resp[2:4], 0x0202) // SEARCH_RESPONSE
	_, err := wire.ParseDescriptionResponse(resp)
	if !errors.Is(err, wire.ErrNotResponse) {
		t.Fatalf("expected ErrNotResponse, got %v", err)
	}
}

func TestParseDescriptionResponseLengthMismatch(t *testing.T) {
	t.Parallel()
	resp := buildResp("MDT IP Interface")
	binary.BigEndian.PutUint16(resp[4:6], 0xFFFF) // declared length way past buffer
	_, err := wire.ParseDescriptionResponse(resp)
	if !errors.Is(err, wire.ErrLengthMismatch) {
		t.Fatalf("expected ErrLengthMismatch, got %v", err)
	}
}

func TestParseDescriptionResponseMissingDIB(t *testing.T) {
	t.Parallel()
	resp := buildResp("MDT IP Interface")
	resp[7] = 0x02 // DIB type 2 (supported services), not 1 (device info)
	_, err := wire.ParseDescriptionResponse(resp)
	if !errors.Is(err, wire.ErrMissingDeviceInfoDIB) {
		t.Fatalf("expected ErrMissingDeviceInfoDIB, got %v", err)
	}
}

func TestParseDescriptionResponseTrimsNUL(t *testing.T) {
	t.Parallel()
	// Friendly name "Gira" plus 26 NULs.
	resp := buildResp("Gira")
	di, err := wire.ParseDescriptionResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if di.FriendlyName != "Gira" {
		t.Fatalf("FriendlyName trim: got %q", di.FriendlyName)
	}
}

func TestIsDescriptionResponseTrueOnly(t *testing.T) {
	t.Parallel()
	resp := buildResp("MDT IP Interface")
	if !wire.IsDescriptionResponse(resp) {
		t.Fatalf("expected true on valid response")
	}
	req := wire.BuildDescriptionRequest()
	if wire.IsDescriptionResponse(req) {
		t.Fatalf("expected false on request frame")
	}
	if wire.IsDescriptionResponse(nil) {
		t.Fatalf("nil should not be a response")
	}
	short := make([]byte, 59)
	short[0] = 0x06
	short[1] = 0x10
	binary.BigEndian.PutUint16(short[2:4], 0x0205)
	if wire.IsDescriptionResponse(short) {
		t.Fatalf("59-byte buffer too short")
	}
}

// buildResp produces a 60-byte DESCRIPTION_RESPONSE with the
// given friendly name (right-padded with NUL to 30 bytes). The
// remaining device-info DIB fields (medium, device status,
// individual address) are hardcoded to canonical TP1 values.
func buildResp(friendlyName string) []byte {
	resp := make([]byte, 60)
	resp[0] = 0x06
	resp[1] = 0x10
	binary.BigEndian.PutUint16(resp[2:4], 0x0205) // DESCRIPTION_RESPONSE
	binary.BigEndian.PutUint16(resp[4:6], 60)
	resp[6] = 0x36 // device-info DIB length: 54
	resp[7] = 0x01 // DIB type: device info
	resp[8] = 0x02 // medium: TP1
	resp[9] = 0x00 // device status: not in programming mode
	binary.BigEndian.PutUint16(resp[10:12], 0x1101)
	// resp[12..29] = 0 (project installation, serial, multicast, MAC)
	copy(resp[30:60], friendlyName)
	return resp
}
