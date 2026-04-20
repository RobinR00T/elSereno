package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/modbus/wire"
)

// BenchmarkReadFrame measures the hot path for the proxy — every
// forwarded byte passes through ReadFrame. Re-uses a single pre-
// baked buffer so the allocator is the variable under test.
func BenchmarkReadFrame(b *testing.B) {
	frame := wire.BuildReadCoilsRequest(1, 1)
	var buf bytes.Buffer
	if err := wire.WriteFrame(&buf, frame); err != nil {
		b.Fatal(err)
	}
	payload := buf.Bytes()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(payload)
		if _, err := wire.ReadFrame(r); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriteFrame bounds the cost of emitting a Modbus frame —
// the proxy's write-ban refusal path relies on it.
func BenchmarkWriteFrame(b *testing.B) {
	frame := wire.BuildReadDeviceIDRequest(1, 1)
	var buf bytes.Buffer
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := wire.WriteFrame(&buf, frame); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkClassify is a tight loop over the function-code
// dispatcher. Proxies parse every client frame through it, so its
// per-call cost caps the proxy's effective throughput.
func BenchmarkClassify(b *testing.B) {
	b.ReportAllocs()
	codes := []wire.FunctionCode{
		wire.FCReadCoils, wire.FCWriteSingleRegister,
		wire.FCEncapsulatedInterface, wire.FCDiagnostics,
		0x99,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wire.Classify(codes[i%len(codes)])
	}
}
