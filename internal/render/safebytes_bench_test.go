package render_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/render"
)

// BenchmarkSafeBytes_ASCII measures the cheap path — all-printable
// input is the most common scanner banner shape.
func BenchmarkSafeBytes_ASCII(b *testing.B) {
	payload := bytes.Repeat([]byte("Siemens SIMATIC S7-1200 FW 4.5.0"), 32) // 1 KiB
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = render.SafeBytes(payload)
	}
}

// BenchmarkSafeBytes_Binary measures the escape-heavy path. A
// modbus packet + random high bytes exercises both control and
// UTF-8 fallbacks.
func BenchmarkSafeBytes_Binary(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i) // sweep 0..255
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = render.SafeBytes(payload)
	}
}
