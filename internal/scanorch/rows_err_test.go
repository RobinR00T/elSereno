package scanorch_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// errCheck stands for an error pgx reports only through rows.Err, such
// as the CHECK violation a cron schedule hit before migration 00021
// (PITF-086).
var errCheck = errors.New("ERROR: new row violates check constraint (SQLSTATE 23514)")

// TestRowsErr_NotReportedAsNotFound: a statement that fails while
// running yields no row, and pgx reports why only through rows.Err.
// Until 2026-10-16 the stores read that as "not found", so switching a
// schedule to cron answered a false 404 or 412.
func TestRowsErr_NotReportedAsNotFound(t *testing.T) {
	ctx := context.Background()
	update := scanorch.UpdateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}
	cases := map[string]func(q *fakeQuerier) error{
		"schedule Update": func(q *fakeQuerier) error {
			_, err := scanorch.NewDBScheduleStore(q).Update(ctx, "abc", update)
			return err
		},
		"schedule Get": func(q *fakeQuerier) error {
			_, err := scanorch.NewDBScheduleStore(q).Get(ctx, "abc")
			return err
		},
		"job Get": func(q *fakeQuerier) error {
			_, err := scanorch.NewDBStore(q).Get(ctx, "abc")
			return err
		},
		"job Transition": func(q *fakeQuerier) error {
			_, err := scanorch.NewDBStore(q).Transition(ctx, "abc", scanorch.StateRunning, scanorch.TransitionFields{})
			return err
		},
	}
	for name, call := range cases {
		err := call(&fakeQuerier{rowsErr: errCheck})
		if !errors.Is(err, errCheck) {
			t.Errorf("%s: err = %v, want the rows error", name, err)
		}
		if errors.Is(err, scanorch.ErrScheduleNotFound) || errors.Is(err, scanorch.ErrJobNotFound) ||
			errors.Is(err, scanorch.ErrSchedulePreconditionFailed) || errors.Is(err, scanorch.ErrInvalidTransition) {
			t.Errorf("%s: a failed statement reported as %v", name, err)
		}
	}
}

// TestRowsErr_UpdateIfMatchExistsCheck: with If-Match, a 0-row UPDATE
// asks whether the schedule exists; a failure of that check is an
// error, not "missing".
func TestRowsErr_UpdateIfMatchExistsCheck(t *testing.T) {
	q := &fakeQuerier{followUpRowsErr: errCheck}
	ifMatch := time.Now().UTC()
	_, err := scanorch.NewDBScheduleStore(q).Update(context.Background(), "abc", scanorch.UpdateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
		IfMatch:         &ifMatch,
	})
	if !errors.Is(err, errCheck) {
		t.Fatalf("err = %v, want the existence check's rows error", err)
	}
}

// TestRowsErr_FailedUpdateOfAnExistingRecord: the UPDATE fails and the
// follow-up check finds the record. Without the UPDATE's own rows.Err
// check this read as a state conflict (a false 409 when cancelling a
// scan) or a stale If-Match (a false 412).
func TestRowsErr_FailedUpdateOfAnExistingRecord(t *testing.T) {
	ctx := context.Background()
	exists := []map[string]any{{}}

	_, err := scanorch.NewDBStore(&fakeQuerier{rowsErr: errCheck, classifyExistsRows: exists}).
		Transition(ctx, "abc", scanorch.StateRunning, scanorch.TransitionFields{})
	if !errors.Is(err, errCheck) || errors.Is(err, scanorch.ErrInvalidTransition) {
		t.Errorf("job Transition: err = %v, want the UPDATE's rows error", err)
	}

	ifMatch := time.Now().UTC()
	_, err = scanorch.NewDBScheduleStore(&fakeQuerier{rowsErr: errCheck, classifyExistsRows: exists}).
		Update(ctx, "abc", scanorch.UpdateScheduleRequest{
			Name:            "x",
			Template:        scanorch.SubmitRequest{Input: "stdin"},
			IntervalSeconds: 60,
			IfMatch:         &ifMatch,
		})
	if !errors.Is(err, errCheck) || errors.Is(err, scanorch.ErrSchedulePreconditionFailed) {
		t.Errorf("schedule Update with If-Match: err = %v, want the UPDATE's rows error", err)
	}
}

// TestRowsErr_TransitionClassifyCheck: after a 0-row transition the
// store asks whether the job exists; a failure of that check is an
// error, not ErrJobNotFound.
func TestRowsErr_TransitionClassifyCheck(t *testing.T) {
	q := &fakeQuerier{followUpRowsErr: errCheck}
	_, err := scanorch.NewDBStore(q).Transition(context.Background(), "abc", scanorch.StateRunning, scanorch.TransitionFields{})
	if !errors.Is(err, errCheck) {
		t.Fatalf("err = %v, want the classify check's rows error", err)
	}
}
