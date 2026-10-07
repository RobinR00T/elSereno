package fox

import (
	"encoding/hex"
	"strings"
	"testing"
)

// realFoxBanner is the server-side Niagara Fox hello (TCP/1911) from
// w3h/icsmaster pcap/fox/fox_info.pcap, taken verbatim. It is a real
// Tridium Niagara station ANSWERING the Workbench's client hello (the
// client speaks first in that capture): "fox a 0 -1 fox hello" followed by
// the {fox.version=...} dictionary (app.name=Station, os.name=QNX,
// station.name=Legion_HQ_V4, brandId=vykon). This is what the fox probe
// reads after its own hello, so it validates the classifier against real
// device output rather than a hand-built fixture.
const realFoxBanner = "666f7820612030202d3120666f782068656c6c6f0a7b0a666f782e76657273696f" +
	"6e3d733a312e300a69643d693a320a686f73744e616d653d733a3139322e313638" +
	"2e322e31350a686f7374416464726573733d733a3139322e3136382e322e31350a" +
	"6170702e6e616d653d733a53746174696f6e0a6170702e76657273696f6e3d733a" +
	"332e352e34312e310a766d2e6e616d653d733a4a390a766d2e76657273696f6e3d" +
	"733a322e330a6f732e6e616d653d733a514e580a6f732e76657273696f6e3d733a" +
	"362e332e320a73746174696f6e2e6e616d653d733a4c6567696f6e5f48515f5634" +
	"0a6c616e673d733a656e0a"

// TestProbe_RealNiagaraBanner replays the real Niagara Fox server banner to
// the probe and confirms it classifies the host as Fox (capability jumps to
// 70). This is the "real capture" leg of the parser-validation matrix for
// the Fox banner classifier.
func TestProbe_RealNiagaraBanner(t *testing.T) {
	t.Parallel()
	banner, err := hex.DecodeString(realFoxBanner)
	if err != nil {
		t.Fatal(err)
	}
	if !IsFoxBanner(string(banner)) {
		t.Fatalf("IsFoxBanner = false for a real Niagara Fox hello: %q", banner[:40])
	}
	f := probeAgainstBanner(t, banner)
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability on a real Niagara banner: got %d want 70", f.Factors["capability"])
	}
}

// TestHelloRequest_Reference validates the probe REQUEST, not only the
// classifier (PITF-078): HelloRequest is byte for byte the query of
// nmap's fox-info.nse, and the Workbench hello in fox_info.pcap opens
// with the same header and the same first two dictionary entries.
func TestHelloRequest_Reference(t *testing.T) {
	const nse = "fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n"
	if HelloRequest != nse {
		t.Fatalf("HelloRequest = %q, want the fox-info.nse query %q", HelloRequest, nse)
	}
	// First bytes of the client hello in fox_info.pcap (10.1.3.4 -> :1911).
	workbench, err := hex.DecodeString("666f7820612031202d3120666f782068656c6c6f0a7b0a666f782e76657273696f6e3d733a312e300a69643d693a310a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(HelloRequest, string(workbench)) {
		t.Fatalf("HelloRequest does not open like the captured client hello %q", workbench)
	}
	if IsFoxBanner(HelloRequest) {
		t.Fatal("our own hello must not classify as a station reply")
	}
}
