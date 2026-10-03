package wire

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestParseResponse_RealCapture validates the SIP response parser against a
// real response, byte for byte from goffinet/sip_captures SIP-SDP-Example.pcap
// (an IPP VoIP device on UDP/5060). The response is "SIP/2.0 100 Trying" with
// a Server identity header and an Allow list.
func TestParseResponse_RealCapture(t *testing.T) {
	raw, err := hex.DecodeString("5349502f322e302031303020547279696e670d0a5669613a205349502f322e302f5544502031302e33332e362e3130313b6272616e63683d7a39684734624b6163313435303533333939310d0a46726f6d3a203c7369703a3230314031302e33332e362e3130313e3b7461673d3163313435303533303934330d0a546f3a203c7369703a3130314031302e33332e362e3130303b757365723d70686f6e653e3b7461673d31633738323630393332310d0a43616c6c2d49443a20313435303533303337373135323230313036323232314031302e33332e362e3130310d0a435365713a203120494e564954450d0a537570706f727465643a20656d2c74696d65722c7265706c616365732c706174682c7265736f757263652d7072696f726974790d0a416c6c6f773a2052454749535445522c4f5054494f4e532c494e564954452c41434b2c43414e43454c2c4259452c4e4f544946592c505241434b2c52454645522c494e464f2c5355425343524942452c5550444154450d0a5365727665723a204950502f762e362e3230412e3032372e3031320d0a436f6e74656e742d4c656e6774683a20300d0a0d0a")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ParseResponse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse on a real SIP response: %v", err)
	}
	if resp.Code != 100 {
		t.Errorf("Code = %d, want 100", resp.Code)
	}
	if resp.Reason != "Trying" {
		t.Errorf("Reason = %q, want Trying", resp.Reason)
	}
	if resp.Server != "IPP/v.6.20A.027.012" {
		t.Errorf("Server = %q, want IPP/v.6.20A.027.012", resp.Server)
	}
	if !strings.Contains(resp.Allow, "OPTIONS") {
		t.Errorf("Allow = %q, want it to contain OPTIONS", resp.Allow)
	}
}
