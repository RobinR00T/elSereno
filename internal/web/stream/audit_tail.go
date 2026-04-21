package stream

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"local/elsereno/internal/audit"
)

// TailAudit tails the JSONL audit file at `path` and republishes
// every newly-appended entry onto b as an EventAudit. Runs until
// ctx is cancelled or a non-recoverable error bubbles up from the
// filesystem.
//
// Why file-tail rather than an in-process Observer for the serve
// path? The offensive CLI verbs (`elsereno write modbus send`,
// `exploit run`, etc.) run in a SEPARATE process from `serve`, so
// their audit appends are invisible to the dashboard unless the
// serve process observes the on-disk chain. This closes that loop
// without requiring a DB-backed writer (which is the v1.2 ticket).
//
// `pollInterval` is how often TailAudit re-checks the file when no
// new bytes are available. 500ms is a good default: low enough to
// feel live, high enough to avoid needless syscalls.
//
// The first call reads and DISCARDS the file's current contents
// (operators open the dashboard mid-session and don't want a
// replay of yesterday's chain). Subsequent polls publish every
// new line.
func TailAudit(ctx context.Context, b *Broadcaster, path string, pollInterval time.Duration) error {
	if b == nil {
		return errors.New("stream: TailAudit requires a non-nil Broadcaster")
	}
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}

	// Open in read-only mode; the writer (different process) owns
	// O_APPEND. On first open, seek to end so we don't replay old
	// entries.
	// #nosec G304 -- operator-supplied audit path (same file as FileWriter)
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("stream: open audit tail %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("stream: seek end %s: %w", path, err)
	}

	reader := bufio.NewReader(f)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// partial holds a half-line left over from a previous read (the
	// writer may have flushed part of a line between polls). We
	// stitch it back together on the next iteration.
	var partial []byte

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				if line[len(line)-1] != '\n' {
					// Partial line — writer hasn't flushed the
					// trailing newline yet. Stash and retry later.
					partial = append(partial, line...)
					break
				}
				if len(partial) > 0 {
					line = append(partial, line...)
					partial = nil
				}
				publishAuditLine(b, line[:len(line)-1])
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("stream: audit tail read: %w", err)
			}
		}
	}
}

// publishAuditLine decodes one JSONL line into an audit.Entry and
// publishes it on b. Lines that fail to parse are dropped; we
// cannot break the live feed on one bad line.
func publishAuditLine(b *Broadcaster, line []byte) {
	var e audit.Entry
	if err := json.Unmarshal(line, &e); err != nil {
		return
	}
	// Reuse the same projection as the in-process observer so the
	// wire format is identical regardless of the source.
	AuditObserver(b)(e)
}
