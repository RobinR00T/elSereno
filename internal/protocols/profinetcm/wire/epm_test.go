package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// nmapRequest is the request published with Nmap's profinet-cm-lookup
// script (activity id 01000000-0100-0100-0100-000100010001, seqnum 12).
const nmapRequest = "0400200010000000000000000000000000000000000000000883afe11f5dc91191a40800" +
	"2b14a0fa0100000001000100010000010001000100000000030000000c0000000200ffff" +
	"ffff4c000000000000000000010000000000000000000000000000000000000002000000" +
	"0100a0de976cd111827100a02442df7d0100000001000000000000000000000000000000" +
	"000000000000000001000000"

var nmapActivity = [16]byte{1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1}

func TestBuildLookupMatchesNmap(t *testing.T) {
	b := BuildLookup(nmapActivity)
	b[64] = 0x0c // nmap uses sequence number 12; ours is 0
	if got := hex.EncodeToString(b); got != nmapRequest {
		t.Fatalf("request\n got %s\nwant %s", got, nmapRequest)
	}
}

// exampleAnnotation is the S7-1500 annotation shown in the Nmap script's
// documented output.
const exampleAnnotation = "S7-1500                   6ES7 672-5DC01-0YA0      0 V  2  1  7"

func response(activity [16]byte, annot string) []byte {
	b := make([]byte, headerLen)
	b[0], b[1], b[4] = 4, PTypeResponse, ndrLittle
	copy(b[40:56], activity[:])
	body := make([]byte, 20)                                            // context handle
	body = binary.LittleEndian.AppendUint32(body, 1)                    // num entries
	body = binary.LittleEndian.AppendUint32(body, 1)                    // max count
	body = binary.LittleEndian.AppendUint32(body, 0)                    // offset
	body = binary.LittleEndian.AppendUint32(body, 1)                    // actual count
	body = append(body, make([]byte, 16)...)                            // object
	body = binary.LittleEndian.AppendUint32(body, 3)                    // tower pointer
	body = binary.LittleEndian.AppendUint32(body, 0)                    // annotation offset
	body = binary.LittleEndian.AppendUint32(body, uint32(len(annot)+1)) // #nosec G115 -- test fixture, fixed string
	body = append(body, annot...)
	body = append(body, 0)
	return append(b, body...)
}

func TestClassifyResponse(t *testing.T) {
	r, err := Classify(response(nmapActivity, exampleAnnotation), nmapActivity)
	if err != nil {
		t.Fatal(err)
	}
	if r.DeviceType != "S7-1500" || r.OrderID != "6ES7 672-5DC01-0YA0" || r.HWRevision != "0" || r.SWRevision != "V  2  1  7" {
		t.Fatalf("%+v", r)
	}
}

func TestClassifyRejects(t *testing.T) {
	req := BuildLookup(nmapActivity)
	if _, err := Classify(req, nmapActivity); !errors.Is(err, ErrNotResponse) {
		t.Errorf("echoed request: %v", err)
	}
	other := nmapActivity
	other[0] = 9
	if _, err := Classify(response(nmapActivity, "x"), other); !errors.Is(err, ErrActivity) {
		t.Errorf("activity: %v", err)
	}
	fault := response(nmapActivity, "")[:headerLen]
	fault[1] = PTypeFault
	if r, err := Classify(fault, nmapActivity); err != nil || r.PType != PTypeFault {
		t.Errorf("fault: %+v %v", r, err)
	}
	if _, err := Classify([]byte{4, 2}, nmapActivity); !errors.Is(err, ErrShort) {
		t.Errorf("short: %v", err)
	}
	empty := response(nmapActivity, "x")
	binary.LittleEndian.PutUint32(empty[headerLen+20:], 0)
	if _, err := Classify(empty, nmapActivity); !errors.Is(err, ErrNoEntry) {
		t.Errorf("no entry: %v", err)
	}
	if !bytes.Equal(BuildLookup(nmapActivity)[24:40], epmInterface[:]) {
		t.Error("interface")
	}
}

func FuzzClassify(f *testing.F) {
	f.Add(response(nmapActivity, exampleAnnotation))
	f.Add(BuildLookup(nmapActivity))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = Classify(b, nmapActivity)
	})
}
