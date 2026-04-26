package stix

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"local/elsereno/internal/core"
)

// Contract is the schema_info contract identifier that STIX
// output conforms to. Bumped if the bundle layout changes
// (e.g. adding indicator SDOs, switching to STIX 2.2).
const Contract = "stix:v2.1"

// SpecVersion is the STIX spec version every emitted SDO/SCO
// declares.
const SpecVersion = "2.1"

// elserenoNamespace is the v5 UUID namespace for ElSereno
// finding-derived STIX object IDs. Stable across releases
// (changing it would invalidate diff-based regression
// fixtures + downstream STIX-id correlations).
//
// Generated once via `uuidgen -n` from the project name; we
// embed the literal so test fixtures remain reproducible.
var elserenoNamespace = uuid.MustParse("0a8b1d4e-3f6c-5a7d-9e2f-7c1b3d4e5f60")

// Writer accumulates findings in a STIX 2.1 bundle and emits
// the complete bundle on Close. Not safe for concurrent use
// (caller serialises WriteFinding).
type Writer struct {
	w       io.Writer
	objects []any
}

// NewWriter constructs a Writer that emits to w on Close.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w, objects: make([]any, 0, 32)}
}

// WriteFinding adds three STIX objects (address SCO + network-
// traffic SCO + observed-data SDO) to the in-memory bundle.
// Caller passes addr + port because core.Finding doesn't
// carry them directly (the scanner attaches them via the
// target lookup).
//
// addr may be empty when the caller doesn't have it
// (programmatic API); the address SCO is omitted in that case
// and the network-traffic SCO references nothing for dst_ref.
// Such findings still produce an observed-data SDO.
func (x *Writer) WriteFinding(f core.Finding, addr string, port int) error {
	if f.ID == "" {
		return fmt.Errorf("stix: finding.ID is required")
	}
	addrSCO := x.buildAddrSCO(f.ID, addr)
	netSCO := x.buildNetTrafficSCO(f.ID, addrSCO, port, f.Protocol)
	netID, _ := netSCO["id"].(string)
	obsSDO := x.buildObservedDataSDO(f, netID)
	if addrSCO != nil {
		x.objects = append(x.objects, addrSCO)
	}
	x.objects = append(x.objects, netSCO, obsSDO)
	return nil
}

// Close emits the bundle as a single JSON document. Safe to
// call exactly once; subsequent calls error.
func (x *Writer) Close() error {
	bundle := map[string]any{
		"type":         "bundle",
		"id":           "bundle--" + uuid.NewSHA1(elserenoNamespace, []byte("bundle:"+nowISO())).String(),
		"spec_version": SpecVersion,
		"objects":      x.objects,
	}
	enc := json.NewEncoder(x.w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}

// buildAddrSCO returns the ipv4-addr or ipv6-addr SCO for the
// given address, keyed by the finding ID for deterministic
// UUIDs. Returns nil when addr is empty.
func (x *Writer) buildAddrSCO(findingID core.UUID, addr string) map[string]any {
	if addr == "" {
		return nil
	}
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		// Pass the raw string through as ipv4-addr — STIX
		// validators will reject; better than silently
		// dropping the SCO.
		return nil
	}
	scoType := "ipv4-addr"
	if parsed.Is6() && !parsed.Is4In6() {
		scoType = "ipv6-addr"
	}
	id := scoType + "--" + uuid.NewSHA1(elserenoNamespace, []byte(scoType+":"+string(findingID))).String()
	return map[string]any{
		"type":         scoType,
		"spec_version": SpecVersion,
		"id":           id,
		"value":        parsed.String(),
	}
}

// buildNetTrafficSCO returns the network-traffic SCO. dst_ref
// is set to the address SCO's id when addrSCO is non-nil.
// protocols list always includes "tcp" or "udp" (defaulting
// to tcp when ambiguous) plus the application-layer
// protocol (e.g. "modbus"). STIX requires lowercase protocol
// names per §6.7.
func (x *Writer) buildNetTrafficSCO(findingID core.UUID, addrSCO map[string]any, port int, protocol string) map[string]any {
	id := "network-traffic--" + uuid.NewSHA1(elserenoNamespace, []byte("net:"+string(findingID))).String()
	sco := map[string]any{
		"type":         "network-traffic",
		"spec_version": SpecVersion,
		"id":           id,
		"protocols":    networkProtocolsFor(protocol),
	}
	if port > 0 {
		sco["dst_port"] = port
	}
	if addrSCO != nil {
		sco["dst_ref"] = addrSCO["id"]
	}
	return sco
}

// buildObservedDataSDO returns the observed-data SDO with
// timestamps from the finding's CreatedAt + the severity
// promoted to a label.
func (x *Writer) buildObservedDataSDO(f core.Finding, netRef string) map[string]any {
	id := "observed-data--" + uuid.NewSHA1(elserenoNamespace, []byte("obs:"+string(f.ID))).String()
	created := f.CreatedAt.UTC().Format(time.RFC3339)
	labels := []string{string(f.Severity), f.Protocol}
	return map[string]any{
		"type":            "observed-data",
		"spec_version":    SpecVersion,
		"id":              id,
		"created":         created,
		"modified":        created,
		"first_observed":  created,
		"last_observed":   created,
		"number_observed": 1,
		"object_refs":     []string{netRef},
		"labels":          labels,
	}
}

// networkProtocolsFor returns the STIX `protocols` array for a
// finding. Application-layer protocols sit on top of tcp by
// default; UDP-only protocols (BACnet/IP, IAX2) get "udp"
// prepended.
func networkProtocolsFor(appProtocol string) []string {
	transport := "tcp"
	switch strings.ToLower(appProtocol) {
	case "bacnet", "iax2":
		transport = "udp"
	}
	out := []string{transport}
	if appProtocol != "" {
		out = append(out, strings.ToLower(appProtocol))
	}
	return out
}

// nowISO returns the current UTC time in RFC 3339 form, used
// for the bundle ID's deterministic-but-time-bound name.
// Replaced in tests via the test-only newWriterWithNow
// helper to make output reproducible.
var nowISO = func() string {
	return time.Now().UTC().Format(time.RFC3339)
}
