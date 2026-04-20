package audit_test

import (
	"encoding/json"
	"testing"
	"time"

	"local/elsereno/internal/audit"
)

// BenchmarkCanonicalise measures the JCS pass the audit writer
// performs for every INSERT. 256-byte payload matches a typical
// protocol_probe record.
func BenchmarkCanonicalise(b *testing.B) {
	payload, _ := json.Marshal(map[string]any{
		"proto":      "modbus",
		"target":     "203.0.113.42:502",
		"score":      85,
		"factors":    map[string]int{"protocol_risk": 85, "exposure": 80},
		"finding_id": "2f3d6a0d7c6e4b2aafb8c4e6e8f1b3a0",
		"plugin":     "modbus",
		"build":      "default",
	})
	e := audit.Entry{
		ID:         12345,
		OccurredAt: time.Unix(1_700_000_000, 0).UTC(),
		Actor:      "operator",
		EventType:  audit.EventProtoProbe,
		Payload:    payload,
		PrevHash:   make([]byte, 32),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := audit.Canonicalise(e); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkComputeHash exercises the full write-path: canonicalise
// + SHA-256. Sets the "how fast can we emit an audit row" upper
// bound for the chain's throughput.
func BenchmarkComputeHash(b *testing.B) {
	payload, _ := json.Marshal(map[string]any{
		"proto": "modbus", "target": "10.0.0.1:502", "score": 75,
	})
	e := audit.Entry{
		ID:         1,
		OccurredAt: time.Unix(1_700_000_000, 0).UTC(),
		Actor:      "system",
		EventType:  audit.EventProtoProbe,
		Payload:    payload,
		PrevHash:   make([]byte, 32),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := audit.ComputeHash(e); err != nil {
			b.Fatal(err)
		}
	}
}
