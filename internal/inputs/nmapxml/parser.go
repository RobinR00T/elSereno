package nmapxml

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"strconv"

	"local/elsereno/internal/core"
)

// ErrEmpty is returned when the document contains no open ports.
var ErrEmpty = fmt.Errorf("inputs/nmapxml: no open ports parsed")

// nmapRun is a minimal projection of the nmap XML schema. We only need
// address, port, and state for the scanner hand-off.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   string    `xml:"portid,attr"`
	State    nmapState `xml:"state"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

// Parse decodes an nmap -oX document into core.Target values. Only
// open TCP/UDP ports with a parseable address are emitted; IPv6 and
// IPv4 are both accepted. Duplicate (address, port) tuples are preserved
// here; deduplication is the scanner's job.
func Parse(_ context.Context, r io.Reader) ([]core.Target, error) {
	dec := xml.NewDecoder(r)
	// Avoid XML external entity expansion (XXE) attacks.
	dec.Strict = true

	var doc nmapRun
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("inputs/nmapxml: decode: %w", err)
	}

	var out []core.Target
	for _, h := range doc.Hosts {
		addr, ok := pickAddress(h.Addresses)
		if !ok {
			continue
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			n, err := strconv.Atoi(p.PortID)
			if err != nil {
				continue
			}
			port, err := core.NewPort(n)
			if err != nil {
				continue
			}
			out = append(out, core.Target{Address: addr, Port: port})
		}
	}
	if len(out) == 0 {
		return nil, ErrEmpty
	}
	return out, nil
}

// pickAddress selects the first parseable IPv4 or IPv6 address from the
// address list; MAC addresses are ignored.
func pickAddress(addrs []nmapAddress) (netip.Addr, bool) {
	for _, a := range addrs {
		switch a.Type {
		case "ipv4", "ipv6":
			addr, err := netip.ParseAddr(a.Addr)
			if err == nil {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}
