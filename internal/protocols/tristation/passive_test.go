package tristation

import (
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
	"testing"

	"local/elsereno/internal/pcapfile"
	"local/elsereno/internal/protocols/tristation/wire"
)

func TestAnalyse(t *testing.T) {
	b, err := os.ReadFile("wire/testdata/cp_status_response.hex")
	if err != nil {
		t.Fatal(err)
	}
	status, _ := hex.DecodeString(strings.TrimSpace(string(b)))
	run, err := wire.BuildCommand(wire.CmdRunProgram, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	ws := netip.MustParseAddrPort("192.0.2.10:40000")
	sis := netip.MustParseAddrPort("192.0.2.20:1502")
	ds := []pcapfile.Datagram{
		{Src: ws, Dst: sis, Payload: wire.BuildGetCPStatus(0)},
		{Src: sis, Dst: ws, Payload: status},
		{Src: ws, Dst: sis, Payload: wire.BuildGetCPStatus(0)},
		{Src: sis, Dst: ws, Payload: status}, // same status: not repeated
		{Src: ws, Dst: sis, Payload: run},
		{Src: ws, Dst: sis, Payload: []byte{5, 0}}, // undecodable
		{Src: ws, Dst: netip.MustParseAddrPort("192.0.2.30:53"), Payload: []byte{1}},
	}
	r := Analyse(ds)
	if r.TriStation != 5 || r.BadFrames != 1 || len(r.Controllers) != 1 || r.Controllers[0] != sis.String() {
		t.Fatalf("report %+v", r)
	}
	if len(r.Statuses) != 1 || r.Statuses[0].Status.Project != "NOZOMI" {
		t.Fatalf("statuses %+v", r.Statuses)
	}
	if len(r.Changes) != 1 || r.Changes[0].Command != wire.CmdRunProgram {
		t.Fatalf("changes %+v", r.Changes)
	}
}
