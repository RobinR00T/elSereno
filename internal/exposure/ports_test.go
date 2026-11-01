package exposure

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestPorts_SortedUniqueAndComplete(t *testing.T) {
	ps := Ports()
	seen := map[string]bool{}
	for i, e := range ps {
		key := e.Transport + "/" + strconv.Itoa(e.Port)
		if seen[key] {
			t.Errorf("duplicate catalogue row %d/%s", e.Port, e.Transport)
		}
		seen[key] = true
		if i > 0 && ps[i-1].Port > e.Port {
			t.Errorf("Ports() not sorted at %d", i)
		}
		if e.Protocol == "" || e.Category == "" {
			t.Errorf("port %d: empty protocol or category", e.Port)
		}
		if e.Transport != TransportTCP && e.Transport != TransportUDP {
			t.Errorf("port %d: transport %q", e.Port, e.Transport)
		}
		if e.Transport == TransportUDP && e.TLSCheck {
			t.Errorf("port %d: a UDP row cannot take the TCP TLS check", e.Port)
		}
	}
	// Every port in the OT/IT default-port list that motivated the
	// catalogue (22, 80, 102, 161, 443, 502, 1433, 1883, 3389, 4840,
	// 20000, 34964, 44818, 47808) must be present.
	for _, p := range []int{22, 80, 102, 161, 443, 502, 1433, 1883, 3389, 4840, 20000, 34964, 44818, 47808} {
		if _, ok := Lookup(p); !ok {
			t.Errorf("port %d missing from the catalogue", p)
		}
	}
}

func TestLookup(t *testing.T) {
	cases := []struct {
		port      int
		transport string
		category  Category
		tlsCheck  bool
	}{
		{3389, TransportTCP, CategoryITManagement, false},
		{22, TransportTCP, CategoryITManagement, false},
		{443, TransportTCP, CategoryITEncrypted, true},
		{80, TransportTCP, CategoryITCleartext, true},
		{502, TransportTCP, CategoryOT, true},
		{47808, TransportUDP, CategoryOT, false},
		{1502, TransportUDP, CategoryOT, false},
		{34964, TransportUDP, CategoryOT, false},
	}
	for _, c := range cases {
		e, ok := Lookup(c.port)
		if !ok {
			t.Fatalf("Lookup(%d) not found", c.port)
		}
		if e.Transport != c.transport || e.Category != c.category || e.TLSCheck != c.tlsCheck {
			t.Errorf("Lookup(%d) = %+v", c.port, e)
		}
	}
	if _, ok := Lookup(9); ok {
		t.Error("Lookup(9) found a row for an uncatalogued port")
	}
}

func TestProbeCleartext_UDPPortNotDialled(t *testing.T) {
	res, err := ProbeCleartext(context.Background(), "192.0.2.10:47808", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reachable || res.Cleartext || res.Transport != TransportUDP || res.Protocol != "bacnet" {
		t.Errorf("UDP port result = %+v", res)
	}
}

// TestProbeCleartext_ManagementNeverCleartext: a reachable RDP-like
// service that does not speak TLS on connect is reported as an IT
// management service, never as cleartext. The listener is on an
// ephemeral port, so the catalogue entry is injected through the
// unexported helper.
func TestProbeCleartext_ManagementNeverCleartext(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T", ln.Addr())
	}
	port := tcpAddr.Port
	wellKnownPorts = append(wellKnownPorts, PortEntry{port, TransportTCP, "rdp", CategoryITManagement, "", false, ""})
	defer func() { wellKnownPorts = wellKnownPorts[:len(wellKnownPorts)-1] }()

	res, err := ProbeCleartext(context.Background(), ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reachable || !res.ITManagement || res.Cleartext || res.TLS {
		t.Errorf("management result = %+v", res)
	}
}
