package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5"
)

// SyncFromFile streams every entry from a JSONL audit file into
// target (typically a DBWriter) verbatim, preserving IDs and
// hash chain. Useful for bootstrapping a fresh Postgres from
// an operator's existing `~/.elsereno/audit.jsonl` produced by
// the FileWriter — lets them keep continuity of the chain
// when they promote the DB writer to primary.
//
// Behaviour:
//   - Reads the file line-by-line as JSON entries.
//   - For each entry: verifies ComputeHash matches EntryHash,
//     ensures the chain is intact (PrevHash = previous
//     EntryHash), then calls target.Mirror to persist.
//   - Entries already present in target (same ID) are skipped
//     silently — duplicate SyncFromFile invocations are safe.
//   - Returns the number of entries imported + an error on
//     any chain inconsistency.
//
// target MUST be an MirrorWriter that accepts fully-filled
// entries (DBMirror, FileMirror). A regular Writer would
// regenerate IDs + hashes and break chain continuity.
func SyncFromFile(ctx context.Context, path string, target MirrorWriter, existingIDs ExistingIDFunc) (int, error) {
	// #nosec G304 — operator-supplied audit path
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("audit sync: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return syncStream(ctx, f, target, existingIDs)
}

// ExistingIDFunc reports whether an entry with the given ID
// is already present in target. nil is treated as "everything
// is new" (bulk import into empty target).
type ExistingIDFunc func(ctx context.Context, id int64) (bool, error)

// syncStream runs the import loop. Split out so callers who
// already have an open reader (e.g. a compressed stream) can
// use it without re-opening.
func syncStream(ctx context.Context, r io.Reader, target MirrorWriter, existingIDs ExistingIDFunc) (int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	prev := append([]byte(nil), GenesisPrevHash...)
	imported := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return imported, err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return imported, fmt.Errorf("audit sync: line %d parse: %w", imported+1, err)
		}
		// Chain validation.
		if !bytesEqual(e.PrevHash, prev) {
			return imported, fmt.Errorf("%w: id=%d prev_hash mismatch", ErrChainBroken, e.ID)
		}
		wantHash, err := ComputeHash(e)
		if err != nil {
			return imported, fmt.Errorf("audit sync: id=%d compute: %w", e.ID, err)
		}
		if !bytesEqual(wantHash, e.EntryHash) {
			return imported, fmt.Errorf("%w: id=%d entry_hash mismatch", ErrChainBroken, e.ID)
		}
		prev = e.EntryHash
		// Skip entries already in the target.
		if existingIDs != nil {
			exists, err := existingIDs(ctx, e.ID)
			if err != nil {
				return imported, fmt.Errorf("audit sync: id=%d existing check: %w", e.ID, err)
			}
			if exists {
				continue
			}
		}
		if err := target.Mirror(ctx, e); err != nil {
			return imported, fmt.Errorf("audit sync: id=%d mirror: %w", e.ID, err)
		}
		imported++
	}
	if err := scanner.Err(); err != nil {
		return imported, fmt.Errorf("audit sync: scan: %w", err)
	}
	return imported, nil
}

// DBExistingID returns an ExistingIDFunc bound to a DBConn so
// callers can feed it directly into SyncFromFile against a
// DBMirror target. Queries `SELECT 1 FROM audit_log WHERE id = $1`.
func DBExistingID(conn DBConn) ExistingIDFunc {
	return func(ctx context.Context, id int64) (bool, error) {
		var one int
		err := conn.QueryRow(ctx, "SELECT 1 FROM audit_log WHERE id = $1", id).Scan(&one)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, pgx.ErrNoRows):
			return false, nil
		default:
			return false, err
		}
	}
}
