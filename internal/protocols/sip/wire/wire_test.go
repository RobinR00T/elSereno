package wire_test

import (
	"strings"
	"testing"

	"local/elsereno/internal/protocols/sip/wire"
)

func TestBuildOPTIONS_HasRequiredHeaders(t *testing.T) {
	out := string(wire.BuildOPTIONS("plc.example:5060", "abc123"))
	required := []string{
		"OPTIONS sip:plc.example:5060 SIP/2.0",
		"Via: SIP/2.0/UDP plc.example:5060;branch=z9hG4bKabc123",
		"Max-Forwards: 70",
		"From: <sip:elsereno@plc.example:5060>;tag=probe-abc123",
		"To: <sip:plc.example:5060>",
		"Call-ID: abc123@plc.example:5060",
		"CSeq: 1 OPTIONS",
		"Content-Length: 0",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("missing header: %q\nfull:\n%s", want, out)
		}
	}
	// Must end with the blank-line separator.
	if !strings.HasSuffix(out, "\r\n\r\n") {
		t.Errorf("message must end with CRLFCRLF; got last 4 bytes = %q", out[len(out)-4:])
	}
}

func TestParseResponse_AsteriskOK(t *testing.T) {
	raw := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-xyz\r\n" +
		"From: <sip:elsereno@10.0.0.1>;tag=probe-xyz\r\n" +
		"To: <sip:10.0.0.1>;tag=as5a6b\r\n" +
		"Call-ID: xyz@10.0.0.1\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Server: Asterisk PBX 18.20.0\r\n" +
		"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	resp, err := wire.ParseResponse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != 200 {
		t.Errorf("code = %d, want 200", resp.Code)
	}
	if resp.Reason != "OK" {
		t.Errorf("reason = %q, want OK", resp.Reason)
	}
	if resp.Server != "Asterisk PBX 18.20.0" {
		t.Errorf("server = %q", resp.Server)
	}
	if !strings.Contains(resp.Allow, "INVITE") {
		t.Errorf("allow missing INVITE: %q", resp.Allow)
	}
}

func TestParseResponse_CiscoUCM(t *testing.T) {
	raw := "SIP/2.0 401 Unauthorized\r\n" + //nolint:misspell // RFC 3261 §21.4 spelling is US-English
		"Via: SIP/2.0/UDP 10.0.0.2:5060\r\n" +
		"From: <sip:elsereno@10.0.0.2>;tag=probe-abc\r\n" +
		"To: <sip:10.0.0.2>\r\n" +
		"Call-ID: abc@10.0.0.2\r\n" +
		"Server: Cisco-CUCM11.5\r\n" +
		"WWW-Authenticate: Digest realm=\"ccmsipline\"\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	resp, err := wire.ParseResponse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != 401 {
		t.Errorf("code = %d, want 401", resp.Code)
	}
	if resp.Server != "Cisco-CUCM11.5" {
		t.Errorf("server = %q", resp.Server)
	}
}

func TestParseResponse_3CX(t *testing.T) {
	raw := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.3:5060\r\n" +
		"From: <sip:elsereno@10.0.0.3>;tag=x\r\n" +
		"To: <sip:10.0.0.3>;tag=3cx1\r\n" +
		"Call-ID: x@10.0.0.3\r\n" +
		"User-Agent: 3CX Phone System 20.0.0.123 (Linux)\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	resp, err := wire.ParseResponse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if resp.UserAgent != "3CX Phone System 20.0.0.123 (Linux)" {
		t.Errorf("UA = %q", resp.UserAgent)
	}
}

func TestParseResponse_NonSIPStatus(t *testing.T) {
	raw := "HTTP/1.1 400 Bad Request\r\n\r\n"
	resp, err := wire.ParseResponse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != 0 {
		t.Errorf("expected Code=0 for non-SIP line; got %d", resp.Code)
	}
	if wire.IsSIPStatus(resp.StatusLine) {
		t.Errorf("IsSIPStatus should return false for %q", resp.StatusLine)
	}
}

func TestIsSIPStatus(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"SIP/2.0 200 OK", true},
		{"SIP/2.0 401 Unauthorized", true}, //nolint:misspell // RFC 3261 §21.4 spelling
		{"HTTP/1.1 200 OK", false},
		{"", false},
		{"SIP/1.0 200 OK", false},
	}
	for _, c := range cases {
		if got := wire.IsSIPStatus(c.line); got != c.want {
			t.Errorf("IsSIPStatus(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}
