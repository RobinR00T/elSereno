package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// failingPG answers every query with err.
type failingPG struct{ err error }

func (f failingPG) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, f.err
}

func (f failingPG) QueryRow(context.Context, string, ...any) pgx.Row { return errRow(f) }

type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

// TestPGIdempotencyCache_LogsDatabaseFailures: a database failure
// degrades to a miss (Lookup) or to not storing (Store), as before, but
// is logged; until 2026-10-17 both were silent, and a retried request
// could run twice without a trace (PITF-093). A plain miss is not
// logged.
func TestPGIdempotencyCache_LogsDatabaseFailures(t *testing.T) {
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	ctx := context.Background()

	c := NewPGIdempotencyCache(failingPG{errors.New("connection reset")})
	c.logf = logf
	if res, _ := c.Lookup(ctx, "k", []byte("{}")); res != idempotencyMiss {
		t.Fatalf("lookup on a failing database = %v, want miss", res)
	}
	c.Store(ctx, "k", []byte("{}"), 201, []byte("{}"))
	if len(logged) != 2 || !strings.Contains(logged[0], "lookup failed") || !strings.Contains(logged[1], "store failed") {
		t.Fatalf("logged %q, want a lookup and a store failure", logged)
	}

	logged = nil
	miss := NewPGIdempotencyCache(failingPG{pgx.ErrNoRows})
	miss.logf = logf
	if res, _ := miss.Lookup(ctx, "k", []byte("{}")); res != idempotencyMiss {
		t.Fatalf("lookup with no row = %v, want miss", res)
	}
	if len(logged) != 0 {
		t.Fatalf("a plain miss was logged: %q", logged)
	}
}
