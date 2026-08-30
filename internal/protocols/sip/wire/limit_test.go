package wire_test

import (
	"io"
	"testing"

	"local/elsereno/internal/protocols/sip/wire"
)

// countingInfiniteReader yields status-line bytes forever (never a
// newline), counting how many are read from it.
type countingInfiniteReader struct{ n int64 }

func (r *countingInfiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	r.n += int64(len(p))
	return len(p), nil
}

// TestParseResponse_CappedReaderBoundsInput: over an io.LimitReader (as
// the TCP recon path wraps the connection) the parser cannot ingest
// more than the cap even when the peer streams an endless status line.
// It returns an error rather than hanging or allocating without bound.
func TestParseResponse_CappedReaderBoundsInput(t *testing.T) {
	const limit = 64 << 10
	src := &countingInfiniteReader{}
	if _, err := wire.ParseResponse(io.LimitReader(src, limit)); err == nil {
		t.Fatal("expected an error parsing an endless header stream")
	}
	if src.n > limit {
		t.Fatalf("read %d bytes from the source, want <= %d: LimitReader must bound ingestion", src.n, limit)
	}
}
