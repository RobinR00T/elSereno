package scanorch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the narrow pgx surface scanorch's DBStore needs.
// Both *pgxpool.Pool and *pgx.Conn satisfy it; tests use an
// in-memory fake. Mirrors the repo.Querier shape — kept
// separate to avoid an internal/scanorch → internal/repo
// import (no orchestration → repo dependency yet).
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// DBStore is the postgres-backed Store implementation. The
// migration in 00005_scan_jobs.sql defines the schema. State
// is a CHECK-constrained enum so any out-of-band INSERT can't
// corrupt the worker's state-machine assumptions.
//
// All transitions use atomic UPDATE ... WHERE state IN (...)
// RETURNING * so the from-state check + the actual mutation
// happen in one round-trip. This is concurrency-safe: two
// workers racing for the same queued job will see at most
// one win the UPDATE; the loser gets 0 rows back and surfaces
// ErrInvalidTransition.
type DBStore struct {
	q Querier
}

// NewDBStore wraps the supplied Querier (typically a
// *pgxpool.Pool) as a Store.
func NewDBStore(q Querier) *DBStore { return &DBStore{q: q} }

// Submit inserts a new queued job.
func (s *DBStore) Submit(ctx context.Context, req SubmitRequest, operator string) (Job, error) {
	if req.Input == "" {
		return Job{}, ErrInputRequired
	}
	id, err := generateID()
	if err != nil {
		return Job{}, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	plugins := req.Plugins
	if plugins == nil {
		plugins = []string{} // postgres ARRAY can't take nil
	}
	const sql = `
INSERT INTO scan_jobs(id, state, created_at, input, plugins, default_port, operator)
VALUES ($1, 'queued', $2, $3, $4, $5, $6)`
	if _, err := s.q.Exec(ctx, sql, id, now, req.Input, plugins, req.DefaultPort, operator); err != nil {
		return Job{}, fmt.Errorf("scanorch: insert job: %w", err)
	}
	return Job{
		ID:          id,
		State:       StateQueued,
		CreatedAt:   now,
		Input:       req.Input,
		Plugins:     append([]string(nil), plugins...),
		DefaultPort: req.DefaultPort,
		Operator:    operator,
	}, nil
}

// jobColumns is the column list returned by every Get/List/
// Transition query. Single source of truth for the SELECT
// projection + the rowScanner.
//
// v1.67+: includes findings_by_plugin (JSONB).
const jobColumns = `
id, state, created_at, started_at, finished_at,
input, plugins, default_port,
targets_seen, targets_scanned, findings_count,
error_msg, operator, findings_by_plugin`

// Get returns the job with the given ID.
func (s *DBStore) Get(ctx context.Context, id string) (Job, error) {
	rows, err := s.q.Query(ctx, "SELECT "+jobColumns+" FROM scan_jobs WHERE id = $1", id)
	if err != nil {
		return Job{}, fmt.Errorf("scanorch: query job: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return Job{}, ErrJobNotFound
	}
	return scanJob(rows)
}

// List returns up to `limit` jobs, newest first.
func (s *DBStore) List(ctx context.Context, limit int) ([]Job, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.q.Query(ctx,
		"SELECT "+jobColumns+" FROM scan_jobs ORDER BY created_at DESC LIMIT $1",
		limit)
	if err != nil {
		return nil, fmt.Errorf("scanorch: list jobs: %w", err)
	}
	defer rows.Close()
	jobs := make([]Job, 0, limit)
	for rows.Next() {
		j, scanErr := scanJob(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanorch: list jobs (rows): %w", err)
	}
	return jobs, nil
}

// Transition moves the job to `to`, atomically validating that
// the job's current state allows the transition. Atomicity is
// achieved via UPDATE ... WHERE state IN (valid_from_states):
// at most one of two concurrent transitions wins.
//
// Decision matrix:
//
//	to              valid from-states
//	──────────────  ─────────────────
//	StateRunning    queued
//	StateCompleted  running
//	StateFailed     running
//	StateCancelled  queued, running
func (s *DBStore) Transition(ctx context.Context, id string, to State, fields TransitionFields) (Job, error) {
	fromStates, ok := transitionFromStates[to]
	if !ok {
		return Job{}, ErrInvalidTransition
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	rows, err := s.runTransition(ctx, id, to, fromStates, now, fields)
	if err != nil {
		return Job{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		// 0 rows updated: either job doesn't exist OR current
		// state isn't in fromStates. Distinguish via a follow-up
		// SELECT so the caller gets ErrJobNotFound vs
		// ErrInvalidTransition correctly.
		return s.classifyTransitionMiss(ctx, id)
	}
	return scanJob(rows)
}

// transitionFromStates lists the valid current-states for each
// target state. Mirrors the validTransitions map in job.go but
// inverted (target → valid sources) for the SQL UPDATE.
var transitionFromStates = map[State][]State{
	StateRunning:   {StateQueued},
	StateCompleted: {StateRunning},
	StateFailed:    {StateRunning},
	StateCancelled: {StateQueued, StateRunning},
}

// runTransition issues the actual UPDATE ... RETURNING query.
// Splits the SET clause based on `to` so completed/failed jobs
// always set finished_at + Stats while running just sets
// started_at.
//
// v1.67: completed/failed transitions also persist
// findings_by_plugin (JSONB). Empty / nil maps land as
// '{}'::jsonb so the column never holds NULL.
func (s *DBStore) runTransition(ctx context.Context, id string, to State, fromStates []State, now time.Time, fields TransitionFields) (pgx.Rows, error) {
	stats := orZeroStats(fields.Stats)
	args := []any{id, string(to)}
	// Build the WHERE state IN (...) clause programmatically.
	// We can't pass []State directly to pgx (no driver type for
	// our custom State); we use a varadic predicate.
	in, fromArgs := buildInClause(len(args)+1, fromStates)
	args = append(args, fromArgs...)
	var setClause string
	switch to { //nolint:exhaustive // queued is never a transition target; default unreachable
	case StateRunning:
		setClause = "state = $2, started_at = $" + itoa(len(args)+1)
		args = append(args, now)
	case StateCompleted, StateFailed:
		byPluginJSON, err := encodeFindingsByPlugin(fields.FindingsByPlugin)
		if err != nil {
			return nil, fmt.Errorf("scanorch: encode findings_by_plugin: %w", err)
		}
		setClause = "state = $2, finished_at = $" + itoa(len(args)+1) +
			", targets_seen = $" + itoa(len(args)+2) +
			", targets_scanned = $" + itoa(len(args)+3) +
			", findings_count = $" + itoa(len(args)+4) +
			", error_msg = $" + itoa(len(args)+5) +
			", findings_by_plugin = $" + itoa(len(args)+6)
		args = append(args, now, stats.TargetsSeen, stats.TargetsScanned, stats.FindingsCount, fields.Error, byPluginJSON)
	case StateCancelled:
		setClause = "state = $2, finished_at = $" + itoa(len(args)+1)
		args = append(args, now)
	default:
		return nil, ErrInvalidTransition
	}
	sql := "UPDATE scan_jobs SET " + setClause +
		" WHERE id = $1 AND state IN " + in +
		" RETURNING " + jobColumns
	return s.q.Query(ctx, sql, args...)
}

// encodeFindingsByPlugin produces the JSONB bytes the UPDATE
// query binds. Nil / empty maps yield "{}" so the column never
// holds NULL — the migration NOT NULL DEFAULT depends on this.
func encodeFindingsByPlugin(byPlugin map[string]int) ([]byte, error) {
	if len(byPlugin) == 0 {
		return []byte(`{}`), nil
	}
	return json.Marshal(byPlugin)
}

// classifyTransitionMiss disambiguates the 0-rows-affected
// outcome of a transition UPDATE. Either the job doesn't exist
// (ErrJobNotFound) or its current state didn't allow the
// transition (ErrInvalidTransition).
func (s *DBStore) classifyTransitionMiss(ctx context.Context, id string) (Job, error) {
	rows, err := s.q.Query(ctx, "SELECT "+jobColumns+" FROM scan_jobs WHERE id = $1", id)
	if err != nil {
		return Job{}, fmt.Errorf("scanorch: classify miss: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return Job{}, ErrJobNotFound
	}
	return Job{}, ErrInvalidTransition
}

// orZeroStats returns the dereferenced stats or a zero value.
func orZeroStats(s *Stats) Stats {
	if s == nil {
		return Stats{}
	}
	return *s
}

// buildInClause emits an "(SELECT $N UNION ALL SELECT $N+1 …)"
// or simpler "($N, $N+1, …)" placeholder list for the WHERE IN
// clause. Returns the clause text + the args slice in order.
func buildInClause(start int, states []State) (string, []any) {
	if len(states) == 0 {
		return "()", nil
	}
	out := "("
	args := make([]any, 0, len(states))
	for i, st := range states {
		if i > 0 {
			out += ", "
		}
		out += "$" + itoa(start+i)
		args = append(args, string(st))
	}
	out += ")"
	return out, args
}

// itoa is a stdlib-free uint→decimal-string converter for the
// SQL placeholder builder. (strconv.Itoa would be fine; this
// micro-helper just avoids the import in a wire-shape file.)
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// scanJob converts the next pgx.Rows record into a Job. Caller
// must have called Next() and confirmed it returned true.
//
// v1.67: decodes findings_by_plugin (JSONB) into
// Job.FindingsByPlugin. Empty {} jsonb (the column default for
// rows pre-dating v1.66) yields a nil map (omitempty in JSON
// output, no spurious empty tooltip on the dashboard).
func scanJob(rows pgx.Rows) (Job, error) {
	var (
		j                 Job
		stateStr          string
		startedAt         *time.Time
		finishedAt        *time.Time
		plugins           []string
		errorMsg          string
		operator          string
		defaultPort       int
		seen, scd, fnd    int64
		findingsByPlugRaw []byte
	)
	if err := rows.Scan(
		&j.ID, &stateStr, &j.CreatedAt, &startedAt, &finishedAt,
		&j.Input, &plugins, &defaultPort,
		&seen, &scd, &fnd,
		&errorMsg, &operator, &findingsByPlugRaw,
	); err != nil {
		return Job{}, fmt.Errorf("scanorch: scan job: %w", err)
	}
	j.State = State(stateStr)
	if startedAt != nil {
		j.StartedAt = *startedAt
	}
	if finishedAt != nil {
		j.FinishedAt = *finishedAt
	}
	j.Plugins = plugins
	j.DefaultPort = defaultPort
	j.Stats = Stats{
		TargetsSeen:    int(seen),
		TargetsScanned: int(scd),
		FindingsCount:  int(fnd),
	}
	j.Error = errorMsg
	j.Operator = operator
	if len(findingsByPlugRaw) > 0 {
		var byPlugin map[string]int
		if err := json.Unmarshal(findingsByPlugRaw, &byPlugin); err != nil {
			return Job{}, fmt.Errorf("scanorch: decode findings_by_plugin: %w", err)
		}
		// Empty JSON object decodes to an empty (non-nil) map.
		// Normalise to nil so the JSON output stays clean
		// (omitempty drops nil but keeps empty-non-nil).
		if len(byPlugin) > 0 {
			j.FindingsByPlugin = byPlugin
		}
	}
	return j, nil
}

// Compile-time guard that DBStore satisfies Store.
var _ Store = (*DBStore)(nil)

// Avoid an unused-import pruning in IDEs; pgx.Rows is the
// underlying type behind every Query result, and pgconn is
// used in tests' fake-rows implementations.
var _ = errors.New
