package ndjson

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"local/elsereno/internal/core"
)

// Contract is the schema_info contract identifier that ndjson v1
// output conforms to. Keep in sync with migrations/00001 schema_info
// seed data.
const Contract = "ndjson:v1"

// Record is the v1 on-disk shape. Fields are flat; downstream tools
// (jq, awk) can filter without schema introspection.
type Record struct {
	Schema    string         `json:"schema"`
	Run       string         `json:"run_id"`
	Target    string         `json:"target_id"`
	Address   string         `json:"address"`
	Port      int            `json:"port"`
	Protocol  string         `json:"protocol"`
	Severity  string         `json:"severity"`
	Score     int            `json:"score"`
	Factors   map[string]int `json:"factors"`
	CreatedAt string         `json:"created_at"`
}

// Writer streams findings to an io.Writer as newline-delimited JSON.
type Writer struct {
	w   io.Writer
	enc *json.Encoder
}

// NewWriter constructs a Writer that emits to w.
func NewWriter(w io.Writer) *Writer {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Writer{w: w, enc: enc}
}

// WriteFinding serialises a single finding and appends a newline. The
// encoder itself appends a newline after each object, so a single
// Encode suffices.
func (x *Writer) WriteFinding(f core.Finding, addr string) error {
	if f.ID == "" {
		return fmt.Errorf("ndjson: finding.ID is required")
	}
	r := Record{
		Schema:    Contract,
		Run:       string(f.RunID),
		Target:    string(f.TargetID),
		Address:   addr,
		Port:      0, // port lives on core.Target; populated by caller via subsequent call
		Protocol:  f.Protocol,
		Severity:  string(f.Severity),
		Score:     f.Score,
		Factors:   f.Factors,
		CreatedAt: f.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	return x.enc.Encode(r)
}
