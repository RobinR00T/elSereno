package csv

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"time"

	"local/elsereno/internal/core"
)

// HeaderRow is the stable column ordering. Downstream tools can rely on
// this without schema introspection; adding columns is a breaking change
// that requires a new contract version.
var HeaderRow = []string{
	"schema",
	"run_id",
	"target_id",
	"address",
	"port",
	"protocol",
	"severity",
	"score",
	"created_at",
}

// Contract is the schema_info identifier for CSV v1.
const Contract = "csv:v1"

// Writer streams findings as CSV with a fixed column order. The header
// is written on the first call.
type Writer struct {
	w        *csv.Writer
	hdrDone  bool
	closeErr error
}

// NewWriter constructs a Writer that emits to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: csv.NewWriter(w)}
}

// WriteHeader writes the header row immediately; otherwise the header
// is emitted lazily before the first finding.
func (x *Writer) WriteHeader() error {
	if x.hdrDone {
		return nil
	}
	x.hdrDone = true
	return x.w.Write(HeaderRow)
}

// WriteFinding serialises a single finding.
func (x *Writer) WriteFinding(f core.Finding, addr string, port core.Port) error {
	if !x.hdrDone {
		if err := x.WriteHeader(); err != nil {
			return err
		}
	}
	if f.ID == "" {
		return fmt.Errorf("csv: finding.ID is required")
	}
	row := []string{
		Contract,
		string(f.RunID),
		string(f.TargetID),
		addr,
		strconv.Itoa(int(port)),
		f.Protocol,
		string(f.Severity),
		strconv.Itoa(f.Score),
		f.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	return x.w.Write(row)
}

// Flush flushes any buffered rows.
func (x *Writer) Flush() error {
	x.w.Flush()
	return x.w.Error()
}

// Close flushes the writer. Calling Close twice is safe.
func (x *Writer) Close() error {
	if x.closeErr != nil {
		return x.closeErr
	}
	x.closeErr = x.Flush()
	return x.closeErr
}
