//go:build offensive

package harvest

import "testing"

func TestBuildSNMPGetSysDescr_BytesLookSane(t *testing.T) {
	pkt := BuildSNMPGetSysDescr("public", 0x01020304)
	// Must start with SEQUENCE.
	if pkt[0] != 0x30 {
		t.Fatalf("byte 0 = 0x%02x, want 0x30", pkt[0])
	}
	// sysDescr OID must appear verbatim inside.
	needle := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	if !containsSeq(pkt, needle) {
		t.Fatalf("packet does not contain sysDescr OID: % x", pkt)
	}
	// GetRequest tag 0xA0 must be present.
	if !containsSeq(pkt, []byte{0xA0}) {
		t.Fatalf("GetRequest tag missing: % x", pkt)
	}
}

func containsSeq(hay, needle []byte) bool {
outer:
	for i := 0; i+len(needle) <= len(hay); i++ {
		for j := 0; j < len(needle); j++ {
			if hay[i+j] != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

// craftGetResponse returns a fake SNMPv2c GetResponse for sysDescr.0
// with the given community and descr string.
func craftGetResponse(community, descr string, errStatus byte) []byte {
	descrField := wrap(0x04, []byte(descr))
	oidBytes := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	varbind := append([]byte{}, oidBytes...)
	varbind = append(varbind, descrField...)
	vbSeq := wrap(0x30, varbind)
	vbList := wrap(0x30, vbSeq)

	rid := wrap(0x02, []byte{0x00, 0x00, 0x00, 0x01})
	errStat := wrap(0x02, []byte{errStatus})
	errIdx := wrap(0x02, []byte{0x00})
	pduBody := append([]byte{}, rid...)
	pduBody = append(pduBody, errStat...)
	pduBody = append(pduBody, errIdx...)
	pduBody = append(pduBody, vbList...)
	pdu := wrap(0xA2, pduBody)

	version := wrap(0x02, []byte{0x01})
	comm := wrap(0x04, []byte(community))
	msgBody := append([]byte{}, version...)
	msgBody = append(msgBody, comm...)
	msgBody = append(msgBody, pdu...)
	return wrap(0x30, msgBody)
}

func TestParseSNMPGetResponse_Success(t *testing.T) {
	pkt := craftGetResponse("public", "Cisco IOS 15.1", 0)
	ok, descr, err := ParseSNMPGetResponse(pkt, "public")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if descr != "Cisco IOS 15.1" {
		t.Fatalf("descr = %q", descr)
	}
}

func TestParseSNMPGetResponse_WrongCommunity(t *testing.T) {
	pkt := craftGetResponse("wrong", "x", 0)
	ok, _, err := ParseSNMPGetResponse(pkt, "public")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false on wrong community")
	}
}

func TestParseSNMPGetResponse_ErrorStatus(t *testing.T) {
	pkt := craftGetResponse("public", "x", 2) // noSuchName
	ok, _, err := ParseSNMPGetResponse(pkt, "public")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false on non-zero errStatus")
	}
}
