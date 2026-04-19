package nmapxml_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"local/elsereno/internal/inputs/nmapxml"
)

const sampleXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -p 502,102 10.0.0.0/30" start="1" version="7.94">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="502">
        <state state="open"/>
      </port>
      <port protocol="tcp" portid="102">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="102">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
`

func TestParseSample(t *testing.T) {
	t.Parallel()
	ts, err := nmapxml.Parse(context.Background(), strings.NewReader(sampleXML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(ts) != 2 {
		t.Fatalf("got %d targets, want 2", len(ts))
	}
	if ts[0].Address.String() != "10.0.0.1" || int(ts[0].Port) != 502 {
		t.Fatalf("target[0] unexpected: %v", ts[0])
	}
	if ts[1].Address.String() != "2001:db8::1" || int(ts[1].Port) != 102 {
		t.Fatalf("target[1] unexpected: %v", ts[1])
	}
}

func TestParseEmpty(t *testing.T) {
	t.Parallel()
	_, err := nmapxml.Parse(context.Background(), strings.NewReader(`<?xml version="1.0"?><nmaprun/>`))
	if !errors.Is(err, nmapxml.ErrEmpty) {
		t.Fatalf("got %v, want ErrEmpty", err)
	}
}

func TestParseMalformed(t *testing.T) {
	t.Parallel()
	_, err := nmapxml.Parse(context.Background(), strings.NewReader(`<nmaprun>`))
	if err == nil {
		t.Fatal("expected decode error")
	}
}
