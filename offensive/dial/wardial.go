//go:build offensive

package dial

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/scope"
)

// v2.37+ — wardialing orchestrator. Extends Batch with:
//
//   - Range-spec expansion (offensive/dial/range.go).
//   - Concurrency-controlled classification (configurable workers).
//   - Rate-limiting (max-per-second sweep guard).
//   - Resume-from-checkpoint (operator-supplied path; one line
//     per classified number = resume marker).
//
// Still defensive in disposition: the default is "preview" so
// every audit entry records the operator's intent without
// driving any modem hardware. A future cycle adds the
// delivery channel.

// Wardial is the orchestrator config. Mirrors Batch's scope +
// audit fields and adds the v2.37 batch controls.
type Wardial struct {
	// Scope + Writer + Actor + Disposition + Operation: same
	// semantics as Batch (which Wardial composes internally).
	Scope       *scope.Scope
	Writer      audit.Writer
	Actor       string
	Disposition string
	Operation   string
	// Workers is the parallel classification fan-out.
	// Clamped to [1, MaxWorkers]; defaults to 1 (serial).
	Workers int
	// RatePerSecond limits the global classification rate.
	// 0 = no limit. Operators wanting to avoid carrier
	// throttling typically set 2-5 numbers/second.
	RatePerSecond float64
	// CheckpointPath, when non-empty, is the path to a file
	// where the orchestrator appends each Raw input as it
	// completes classification. On the next run, lines in
	// this file are SKIPPED. This lets a long wardial resume
	// from an interruption without re-doing the early
	// numbers (and re-creating audit entries).
	CheckpointPath string
}

// Wardial guard rails.
const (
	// MaxWorkers caps fan-out so a fat-finger doesn't spawn
	// thousands of goroutines.
	MaxWorkers = 32
	// MinRateInterval is the minimum gap between rate-limited
	// dispatches (1 microsecond, effectively unbounded).
	MinRateInterval = time.Microsecond
)

// ErrWardialNoWriter is returned when Writer is nil.
var ErrWardialNoWriter = errors.New("dial: Wardial.Writer required")

// Run consumes either a range spec or a reader of numbers and
// classifies each through the standard Batch decision tree.
// Returns per-number results in stable order. The audit chain
// is appended to as each decision is made (no buffering — a
// kill -9 mid-run leaves a valid prefix in the chain).
func (w *Wardial) Run(ctx context.Context, rangeOrFile string, r io.Reader) ([]BatchResult, error) {
	if w.Writer == nil {
		return nil, ErrWardialNoWriter
	}
	numbers, err := w.sourceNumbers(rangeOrFile, r)
	if err != nil {
		return nil, err
	}
	skip, err := w.loadCheckpoint()
	if err != nil {
		return nil, err
	}
	filtered := numbers[:0]
	for _, n := range numbers {
		if _, done := skip[n]; done {
			continue
		}
		filtered = append(filtered, n)
	}
	return w.runConcurrent(ctx, filtered)
}

// sourceNumbers normalises the two input modes:
//   - If `rangeOrFile` is a range spec (contains ".."), expand it.
//   - Else if r != nil, read line-by-line.
//   - Else if `rangeOrFile` is a path, open it.
func (w *Wardial) sourceNumbers(rangeOrFile string, r io.Reader) ([]string, error) {
	if rangeOrFile != "" && IsRangeSpec(rangeOrFile) {
		return ExpandRange(rangeOrFile)
	}
	if r == nil {
		return nil, errors.New("dial: Wardial.Run requires either a range spec or a non-nil reader")
	}
	return readLines(r), nil
}

// readLines pulls one number per line; blanks + `#` lines
// skipped. Mirrors Batch.Run's input parsing for consistency.
func readLines(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 128*1024)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		out = append(out, raw)
	}
	return out
}

// loadCheckpoint reads CheckpointPath (if set) into a set of
// already-completed `Raw` lines. Missing file is benign
// (returns empty set). Read errors propagate so operators see
// permission / I/O problems early.
func (w *Wardial) loadCheckpoint() (map[string]struct{}, error) {
	out := make(map[string]struct{})
	if w.CheckpointPath == "" {
		return out, nil
	}
	f, err := os.Open(w.CheckpointPath) // #nosec G304 — operator-supplied path.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, fmt.Errorf("dial: open checkpoint: %w", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 128*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		out[line] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("dial: read checkpoint: %w", err)
	}
	return out, nil
}

// indexedJob is the unit of work shipped through the worker
// pool. idx preserves the input order in `results`.
type indexedJob struct {
	idx int
	raw string
}

// runConcurrent fan-outs the classification across Workers
// goroutines while preserving input order in the returned
// slice. Rate-limiting (when configured) applies globally:
// the dispatcher waits between successive dispatches so the
// downstream system isn't slammed.
func (w *Wardial) runConcurrent(ctx context.Context, numbers []string) ([]BatchResult, error) {
	if len(numbers) == 0 {
		return nil, nil
	}
	workers, rateGap := w.clampedParams()
	b := w.batchFromConfig()

	jobs := make(chan indexedJob)
	results := make([]BatchResult, len(numbers))
	auditErr := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go w.worker(ctx, b, jobs, results, auditErr, &wg)
	}
	go w.dispatch(ctx, jobs, numbers, rateGap)
	wg.Wait()
	close(auditErr)
	for err := range auditErr {
		if err != nil {
			return results, fmt.Errorf("dial: audit append: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

// clampedParams resolves the runtime worker count + rate gap
// from operator-supplied config. Workers clamps to [1,
// MaxWorkers]; rateGap is zero when RatePerSecond is 0/neg.
func (w *Wardial) clampedParams() (int, time.Duration) {
	workers := w.Workers
	if workers < 1 {
		workers = 1
	}
	if workers > MaxWorkers {
		workers = MaxWorkers
	}
	rateGap := time.Duration(0)
	if w.RatePerSecond > 0 {
		rateGap = time.Duration(float64(time.Second) / w.RatePerSecond)
		if rateGap < MinRateInterval {
			rateGap = MinRateInterval
		}
	}
	return workers, rateGap
}

// batchFromConfig builds a Batch with defaults applied — used
// by workers for audit append + scope-aware classify.
func (w *Wardial) batchFromConfig() *Batch {
	b := &Batch{
		Scope:       w.Scope,
		Writer:      w.Writer,
		Actor:       w.Actor,
		Disposition: w.Disposition,
		Operation:   w.Operation,
	}
	if b.Disposition == "" {
		b.Disposition = "preview"
	}
	if b.Operation == "" {
		b.Operation = "dial_wardial"
	}
	if b.Actor == "" {
		b.Actor = "system"
	}
	return b
}

// worker consumes jobs, classifies + audits, and records the
// outcome at the indexed slot in `results`. First audit error
// aborts the worker.
func (w *Wardial) worker(ctx context.Context, b *Batch, jobs <-chan indexedJob, results []BatchResult, auditErr chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		res := classify(job.raw, w.Scope)
		results[job.idx] = res
		if err := b.audit(ctx, res); err != nil {
			auditErr <- err
			return
		}
		w.markCheckpoint(job.raw)
	}
}

// dispatch sends jobs to workers honouring rate-limit + ctx
// cancellation. Closes jobs when done.
func (w *Wardial) dispatch(ctx context.Context, jobs chan<- indexedJob, numbers []string, rateGap time.Duration) {
	defer close(jobs)
	var last time.Time
	for i, raw := range numbers {
		if err := ctx.Err(); err != nil {
			return
		}
		if rateGap > 0 && !last.IsZero() {
			elapsed := time.Since(last)
			if elapsed < rateGap {
				time.Sleep(rateGap - elapsed)
			}
		}
		select {
		case <-ctx.Done():
			return
		case jobs <- indexedJob{idx: i, raw: raw}:
			last = time.Now()
		}
	}
}

// markCheckpoint appends the raw input to the checkpoint file
// so a resumed run skips it. Failures are silent (logging
// would mix into stderr; operator notices via the
// audit-chain reconciliation). Append is the only mode —
// the file grows monotonically.
func (w *Wardial) markCheckpoint(raw string) {
	if w.CheckpointPath == "" {
		return
	}
	f, err := os.OpenFile(w.CheckpointPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(raw + "\n")
}
