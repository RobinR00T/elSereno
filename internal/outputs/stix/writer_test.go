package stix_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/stix"
)

// fixtureFinding produces a stable Finding for golden-output
// tests. CreatedAt is a fixed timestamp so the deterministic
// UUIDs are reproducible.
func fixtureFinding() core.Finding {
	return core.Finding{
		ID:        core.UUID("00000000-0000-0000-0000-000000000001"),
		RunID:     core.UUID("00000000-0000-0000-0000-0000000000aa"),
		TargetID:  core.UUID("00000000-0000-0000-0000-0000000000bb"),
		Protocol:  "modbus",
		Severity:  core.Severity("high"),
		Score:     78,
		CreatedAt: time.Date(2026, 4, 26, 15, 0, 0, 0, time.UTC),
		Factors:   map[string]int{"protocol_risk": 80},
	}
}

// TestWriteFinding_BundleEmitsThreeObjects — every finding
// produces address SCO + network-traffic SCO + observed-data
// SDO (3 objects in the bundle).
func TestWriteFinding_BundleEmitsThreeObjects(t *testing.T) {
	var buf bytes.Buffer
	w := stix.NewWriter(&buf)
	if err := w.WriteFinding(fixtureFinding(), "192.168.1.5", 502); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(buf.Bytes(), &bundle); err != nil {
		t.Fatalf("emitted bytes are not valid JSON: %v\n%s", err, buf.String())
	}
	if bundle["type"] != "bundle" {
		t.Errorf("type = %q, want bundle", bundle["type"])
	}
	if bundle["spec_version"] != "2.1" {
		t.Errorf("spec_version = %q", bundle["spec_version"])
	}
	objects, ok := bundle["objects"].([]any)
	if !ok {
		t.Fatalf("objects field is not a slice: %T", bundle["objects"])
	}
	if len(objects) != 3 {
		t.Fatalf("got %d objects, want 3", len(objects))
	}
}

// TestWriteFinding_IPv4AddrSCO — IPv4 input produces an
// ipv4-addr SCO with the correct value.
func TestWriteFinding_IPv4AddrSCO(t *testing.T) {
	var buf bytes.Buffer
	w := stix.NewWriter(&buf)
	if err := w.WriteFinding(fixtureFinding(), "192.168.1.5", 502); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	got := buf.String()
	if !strings.Contains(got, `"type": "ipv4-addr"`) {
		t.Errorf("missing ipv4-addr SCO:\n%s", got)
	}
	if !strings.Contains(got, `"value": "192.168.1.5"`) {
		t.Errorf("missing IPv4 value:\n%s", got)
	}
}

// TestWriteFinding_IPv6AddrSCO — IPv6 input produces an
// ipv6-addr SCO with the canonical value.
func TestWriteFinding_IPv6AddrSCO(t *testing.T) {
	var buf bytes.Buffer
	w := stix.NewWriter(&buf)
	if err := w.WriteFinding(fixtureFinding(), "2001:db8::1", 47808); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	got := buf.String()
	if !strings.Contains(got, `"type": "ipv6-addr"`) {
		t.Errorf("missing ipv6-addr SCO:\n%s", got)
	}
	if !strings.Contains(got, `"value": "2001:db8::1"`) {
		t.Errorf("missing IPv6 value:\n%s", got)
	}
}

// TestWriteFinding_NetworkTrafficSCO — port + protocols
// populated correctly.
func TestWriteFinding_NetworkTrafficSCO(t *testing.T) {
	var buf bytes.Buffer
	w := stix.NewWriter(&buf)
	if err := w.WriteFinding(fixtureFinding(), "192.168.1.5", 502); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	got := buf.String()
	if !strings.Contains(got, `"type": "network-traffic"`) {
		t.Errorf("missing network-traffic SCO")
	}
	if !strings.Contains(got, `"dst_port": 502`) {
		t.Errorf("missing dst_port: %s", got)
	}
	// Modbus over TCP — protocols should be ["tcp", "modbus"].
	if !strings.Contains(got, `"tcp"`) || !strings.Contains(got, `"modbus"`) {
		t.Errorf("missing protocols list: %s", got)
	}
}

// TestWriteFinding_BACnetUsesUDPTransport — BACnet runs over
// UDP per ASHRAE 135; the STIX `protocols` array reflects
// that.
func TestWriteFinding_BACnetUsesUDPTransport(t *testing.T) {
	f := fixtureFinding()
	f.Protocol = "bacnet"
	var buf bytes.Buffer
	w := stix.NewWriter(&buf)
	if err := w.WriteFinding(f, "192.168.1.5", 47808); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	got := buf.String()
	if !strings.Contains(got, `"udp"`) {
		t.Errorf("BACnet protocol must use udp transport: %s", got)
	}
}

// TestWriteFinding_ObservedDataSDO — the SDO carries severity
// + protocol in labels and the timestamps line up with the
// finding's CreatedAt.
func TestWriteFinding_ObservedDataSDO(t *testing.T) {
	var buf bytes.Buffer
	w := stix.NewWriter(&buf)
	if err := w.WriteFinding(fixtureFinding(), "192.168.1.5", 502); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	got := buf.String()
	if !strings.Contains(got, `"type": "observed-data"`) {
		t.Errorf("missing observed-data SDO")
	}
	if !strings.Contains(got, `"first_observed": "2026-04-26T15:00:00Z"`) {
		t.Errorf("first_observed timestamp wrong")
	}
	if !strings.Contains(got, `"high"`) || !strings.Contains(got, `"modbus"`) {
		t.Errorf("severity + protocol must be in labels")
	}
}

// TestWriteFinding_DeterministicIDs — running twice with
// identical input produces identical SCO/SDO IDs. The bundle
// id itself contains a timestamp so it differs run-to-run,
// but the inner objects are stable for diff-testing.
func TestWriteFinding_DeterministicIDs(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	w1 := stix.NewWriter(&buf1)
	if err := w1.WriteFinding(fixtureFinding(), "192.168.1.5", 502); err != nil {
		t.Fatal(err)
	}
	_ = w1.Close()
	w2 := stix.NewWriter(&buf2)
	if err := w2.WriteFinding(fixtureFinding(), "192.168.1.5", 502); err != nil {
		t.Fatal(err)
	}
	_ = w2.Close()
	var b1, b2 map[string]any
	_ = json.Unmarshal(buf1.Bytes(), &b1)
	_ = json.Unmarshal(buf2.Bytes(), &b2)
	o1, ok1 := b1["objects"].([]any)
	o2, ok2 := b2["objects"].([]any)
	if !ok1 || !ok2 {
		t.Fatalf("objects field is not a slice (b1=%T b2=%T)", b1["objects"], b2["objects"])
	}
	for i := range o1 {
		m1, mok1 := o1[i].(map[string]any)
		m2, mok2 := o2[i].(map[string]any)
		if !mok1 || !mok2 {
			t.Fatalf("object %d not a map (o1=%T o2=%T)", i, o1[i], o2[i])
		}
		id1, _ := m1["id"].(string)
		id2, _ := m2["id"].(string)
		if id1 != id2 {
			t.Errorf("object %d id mismatch: %q vs %q", i, id1, id2)
		}
	}
}

// TestWriteFinding_EmptyAddrSkipsAddrSCO — when the caller
// can't resolve the address, the bundle still emits the
// network-traffic + observed-data pair (just no dst_ref).
func TestWriteFinding_EmptyAddrSkipsAddrSCO(t *testing.T) {
	var buf bytes.Buffer
	w := stix.NewWriter(&buf)
	if err := w.WriteFinding(fixtureFinding(), "", 502); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	var bundle map[string]any
	_ = json.Unmarshal(buf.Bytes(), &bundle)
	objects, ok := bundle["objects"].([]any)
	if !ok {
		t.Fatalf("objects field is not a slice: %T", bundle["objects"])
	}
	if len(objects) != 2 {
		t.Errorf("got %d objects, want 2 when addr is empty", len(objects))
	}
}

// TestWriteFinding_RequiresID — empty Finding.ID returns an
// error (caller must populate the ID upstream).
func TestWriteFinding_RequiresID(t *testing.T) {
	var buf bytes.Buffer
	w := stix.NewWriter(&buf)
	f := fixtureFinding()
	f.ID = ""
	err := w.WriteFinding(f, "1.2.3.4", 502)
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

// TestWriteFinding_BundleSpecVersion — every bundle declares
// spec_version 2.1 (STIX 2.1 conformance).
func TestWriteFinding_BundleSpecVersion(t *testing.T) {
	var buf bytes.Buffer
	w := stix.NewWriter(&buf)
	if err := w.WriteFinding(fixtureFinding(), "1.2.3.4", 502); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if !strings.Contains(buf.String(), `"spec_version": "2.1"`) {
		t.Error("bundle must declare spec_version 2.1")
	}
}
