package audit

import (
	"context"
	"errors"
	"fmt"
)

// MultiWriter fan-outs Append to a list of Writers while keeping
// the canonical chain consistent. The FIRST writer is the
// "primary" — it computes the ID + PrevHash + EntryHash by
// calling Append on itself (using its own chain state). Every
// subsequent writer is a "mirror" that receives a pre-filled
// Entry with those fields set; the mirror must persist the row
// verbatim without recomputing the hash.
//
// Why not just call Append on every writer? Two independent
// writers can't agree on IDs or timestamps unless they share
// state. The primary owns the chain; mirrors mirror.
//
// Typical operator setup: primary = DBWriter (for the dashboard
// panels), mirror = FileWriter (for `tail -f`). The fastest
// path to `audit verify-file` still works against the FileWriter
// output alone.
type MultiWriter struct {
	primary Writer
	mirrors []MirrorWriter
}

// MirrorWriter persists an Entry whose ID / OccurredAt /
// PrevHash / EntryHash are already set by the primary. It is a
// strict subset of Writer: no chain logic, just storage.
type MirrorWriter interface {
	// Mirror persists e exactly as given. The implementation must
	// NOT recompute the hash, generate a new ID, or mutate any
	// field. Any persistence error returns; the MultiWriter
	// surfaces it to the caller.
	Mirror(ctx context.Context, e Entry) error
}

// NewMultiWriter constructs a MultiWriter with `primary` as the
// chain owner and `mirrors` as the fan-out targets. Returns an
// error if primary is nil (mirrors alone can't bootstrap a
// chain — they need the primary's IDs).
func NewMultiWriter(primary Writer, mirrors ...MirrorWriter) (*MultiWriter, error) {
	if primary == nil {
		return nil, errors.New("audit: MultiWriter requires a primary Writer")
	}
	return &MultiWriter{primary: primary, mirrors: mirrors}, nil
}

// Append implements Writer. The primary fills the Entry first;
// if the primary errors, no mirror is called (the chain stays
// consistent). If a mirror errors, the primary row is ALREADY
// committed — we return a joined error so the caller sees which
// mirror failed, but the audit chain on the primary is intact.
func (m *MultiWriter) Append(ctx context.Context, e Entry) (Entry, error) {
	filled, err := m.primary.Append(ctx, e)
	if err != nil {
		return Entry{}, err
	}
	var mirrorErrs []error
	for i, mir := range m.mirrors {
		if err := mir.Mirror(ctx, filled); err != nil {
			mirrorErrs = append(mirrorErrs, fmt.Errorf("mirror[%d]: %w", i, err))
		}
	}
	if len(mirrorErrs) > 0 {
		return filled, fmt.Errorf("audit: primary committed, %d mirror(s) failed: %w",
			len(mirrorErrs), errors.Join(mirrorErrs...))
	}
	return filled, nil
}

// FileMirror adapts a *FileWriter so it can be used as a mirror
// in a MultiWriter. It calls a pre-filled-append method that
// bypasses the FileWriter's chain logic.
type FileMirror struct {
	fw *FileWriter
}

// NewFileMirror wraps fw for use as a MultiWriter mirror.
func NewFileMirror(fw *FileWriter) *FileMirror { return &FileMirror{fw: fw} }

// Mirror implements MirrorWriter by delegating to FileWriter's
// append-verbatim path.
func (m *FileMirror) Mirror(ctx context.Context, e Entry) error {
	return m.fw.appendVerbatim(ctx, e)
}

// DBMirror adapts a *DBWriter for the same purpose.
type DBMirror struct {
	dw *DBWriter
}

// NewDBMirror wraps dw for use as a MultiWriter mirror.
func NewDBMirror(dw *DBWriter) *DBMirror { return &DBMirror{dw: dw} }

// Mirror implements MirrorWriter by delegating to DBWriter's
// append-verbatim path.
func (m *DBMirror) Mirror(ctx context.Context, e Entry) error {
	return m.dw.appendVerbatim(ctx, e)
}
