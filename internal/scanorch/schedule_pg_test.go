package scanorch_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// makeScheduleRow returns a baseline scan_schedules row map
// (interval-based; cron_expr empty; timezone empty = UTC).
// Tests override individual columns as needed.
func makeScheduleRow(id, name string) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"id":                    id,
		"name":                  name,
		"template_input":        "list:t.txt",
		"template_plugins":      []string{"banner"},
		"template_default_port": int(0),
		"interval_seconds":      int(3600),
		"cron_expr":             "",
		"timezone":              "",
		"enabled":               true,
		"operator":              "alice",
		"created_at":            now,
		// v1.78: updated_at defaults to created_at; tests
		// override when verifying the precondition path.
		"updated_at": now,
		// v1.89: NULL-able per-schedule audit retention override.
		// nil → inherit global. *int32 pointer to override. Tests
		// override when verifying the v1.89 round-trip.
		"audit_retention_days": (*int32)(nil),
	}
}

// TestDBScheduleStore_Create_Happy: INSERT round-trip.
func TestDBScheduleStore_Create_Happy(t *testing.T) {
	q := &fakeQuerier{}
	store := scanorch.NewDBScheduleStore(q)
	sched, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "daily",
		Template:        scanorch.SubmitRequest{Input: "list:t.txt", Plugins: []string{"banner"}},
		IntervalSeconds: 86400,
	}, "alice")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if sched.Name != "daily" {
		t.Errorf("Name = %q", sched.Name)
	}
	if sched.IntervalSeconds != 86400 {
		t.Errorf("IntervalSeconds = %d", sched.IntervalSeconds)
	}
	if !sched.Enabled {
		t.Errorf("Enabled defaults to true")
	}
	if !strings.Contains(q.lastSQL, "INSERT INTO scan_schedules") {
		t.Errorf("expected INSERT, got: %s", q.lastSQL)
	}
}

// TestDBScheduleStore_Create_NameRequired short-circuits before SQL.
func TestDBScheduleStore_Create_NameRequired(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{})
	_, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	if !errors.Is(err, scanorch.ErrScheduleNameRequired) {
		t.Errorf("err = %v, want ErrScheduleNameRequired", err)
	}
}

// TestDBScheduleStore_Create_TemplateInputRequired.
func TestDBScheduleStore_Create_TemplateInputRequired(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{})
	_, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		IntervalSeconds: 60,
	}, "alice")
	if !errors.Is(err, scanorch.ErrScheduleTemplateInputRequired) {
		t.Errorf("err = %v, want ErrScheduleTemplateInputRequired", err)
	}
}

// TestDBScheduleStore_Create_CadenceRequired: neither
// IntervalSeconds nor CronExpr → ErrScheduleCadenceRequired.
func TestDBScheduleStore_Create_CadenceRequired(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{})
	_, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:     "x",
		Template: scanorch.SubmitRequest{Input: "stdin"},
	}, "alice")
	if !errors.Is(err, scanorch.ErrScheduleCadenceRequired) {
		t.Errorf("err = %v, want ErrScheduleCadenceRequired", err)
	}
}

// TestDBScheduleStore_Create_CadenceConflict: both set →
// ErrScheduleCadenceConflict.
func TestDBScheduleStore_Create_CadenceConflict(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{})
	_, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
		CronExpr:        "* * * * *",
	}, "alice")
	if !errors.Is(err, scanorch.ErrScheduleCadenceConflict) {
		t.Errorf("err = %v, want ErrScheduleCadenceConflict", err)
	}
}

// TestDBScheduleStore_Create_BadCron: cron parse error fails
// fast at Create time.
func TestDBScheduleStore_Create_BadCron(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{})
	_, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:     "x",
		Template: scanorch.SubmitRequest{Input: "stdin"},
		CronExpr: "* * * *", // 4 fields, not 5
	}, "alice")
	if !errors.Is(err, scanorch.ErrCronWrongFieldCount) {
		t.Errorf("err = %v, want ErrCronWrongFieldCount", err)
	}
}

// TestDBScheduleStore_Create_CronHappy: valid cron
// expression bypasses the interval-clamp path and persists
// the cron_expr column.
func TestDBScheduleStore_Create_CronHappy(t *testing.T) {
	q := &fakeQuerier{}
	store := scanorch.NewDBScheduleStore(q)
	sched, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:     "weekday-am",
		Template: scanorch.SubmitRequest{Input: "list:t.txt"},
		CronExpr: "0 9 * * 1-5",
	}, "alice")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if sched.CronExpr != "0 9 * * 1-5" {
		t.Errorf("CronExpr = %q, want '0 9 * * 1-5'", sched.CronExpr)
	}
	if sched.IntervalSeconds != 0 {
		t.Errorf("IntervalSeconds = %d, want 0 for cron schedule", sched.IntervalSeconds)
	}
	if !strings.Contains(q.lastSQL, "cron_expr") {
		t.Errorf("expected cron_expr in SQL: %s", q.lastSQL)
	}
}

// TestDBScheduleStore_Create_IntervalClamping low + high.
func TestDBScheduleStore_Create_IntervalClamping(t *testing.T) {
	q := &fakeQuerier{}
	store := scanorch.NewDBScheduleStore(q)
	low, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "low",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 1,
	}, "alice")
	if low.IntervalSeconds != 60 {
		t.Errorf("low clamp: got %d, want 60", low.IntervalSeconds)
	}
	high, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "high",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 99 * 86400,
	}, "alice")
	if high.IntervalSeconds != 7*86400 {
		t.Errorf("high clamp: got %d, want 604800", high.IntervalSeconds)
	}
}

// TestDBScheduleStore_Get_Happy returns the row.
func TestDBScheduleStore_Get_Happy(t *testing.T) {
	q := &fakeQuerier{queryRows: []map[string]any{makeScheduleRow("abc", "daily")}}
	store := scanorch.NewDBScheduleStore(q)
	sched, err := store.Get(context.Background(), "abc")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if sched.ID != "abc" || sched.Name != "daily" {
		t.Errorf("got %+v", sched)
	}
	if sched.Template.Input != "list:t.txt" {
		t.Errorf("Template.Input = %q", sched.Template.Input)
	}
}

// TestDBScheduleStore_Get_NotFound.
func TestDBScheduleStore_Get_NotFound(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{queryRows: nil})
	_, err := store.Get(context.Background(), "missing")
	if !errors.Is(err, scanorch.ErrScheduleNotFound) {
		t.Errorf("err = %v, want ErrScheduleNotFound", err)
	}
}

// TestDBScheduleStore_List returns multiple sorted by name.
func TestDBScheduleStore_List(t *testing.T) {
	q := &fakeQuerier{queryRows: []map[string]any{
		makeScheduleRow("a", "alpha"),
		makeScheduleRow("b", "beta"),
	}}
	store := scanorch.NewDBScheduleStore(q)
	all, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(all) != 2 {
		t.Errorf("len = %d, want 2", len(all))
	}
	if !strings.Contains(q.lastSQL, "ORDER BY name ASC") {
		t.Errorf("expected ORDER BY name in SQL: %s", q.lastSQL)
	}
}

// TestDBScheduleStore_Delete_Happy: 1-row Exec returns nil.
func TestDBScheduleStore_Delete_Happy(t *testing.T) {
	q := &fakeQuerier{execRowsAffected: 1}
	store := scanorch.NewDBScheduleStore(q)
	if err := store.Delete(context.Background(), "abc"); err != nil {
		t.Errorf("err = %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(q.lastSQL), "DELETE") {
		t.Errorf("expected DELETE, got: %s", q.lastSQL)
	}
}

// TestDBScheduleStore_Delete_NotFound: 0-row Exec → sentinel.
func TestDBScheduleStore_Delete_NotFound(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{execRowsAffected: 0})
	if err := store.Delete(context.Background(), "missing"); !errors.Is(err, scanorch.ErrScheduleNotFound) {
		t.Errorf("err = %v, want ErrScheduleNotFound", err)
	}
}

// TestDBScheduleStore_MarkFired_Happy.
func TestDBScheduleStore_MarkFired_Happy(t *testing.T) {
	q := &fakeQuerier{execRowsAffected: 1}
	store := scanorch.NewDBScheduleStore(q)
	if err := store.MarkFired(context.Background(), "abc", time.Now().UTC()); err != nil {
		t.Errorf("err = %v", err)
	}
	if !strings.Contains(q.lastSQL, "last_fired_at") {
		t.Errorf("expected last_fired_at in SQL: %s", q.lastSQL)
	}
}

// TestDBScheduleStore_MarkFired_NotFound.
func TestDBScheduleStore_MarkFired_NotFound(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{execRowsAffected: 0})
	if err := store.MarkFired(context.Background(), "missing", time.Now().UTC()); !errors.Is(err, scanorch.ErrScheduleNotFound) {
		t.Errorf("err = %v, want ErrScheduleNotFound", err)
	}
}

// TestDBScheduleStore_SetEnabled_Happy.
func TestDBScheduleStore_SetEnabled_Happy(t *testing.T) {
	q := &fakeQuerier{execRowsAffected: 1}
	store := scanorch.NewDBScheduleStore(q)
	if err := store.SetEnabled(context.Background(), "abc", false); err != nil {
		t.Errorf("err = %v", err)
	}
	if !strings.Contains(q.lastSQL, "enabled") {
		t.Errorf("expected enabled in SQL: %s", q.lastSQL)
	}
}

// TestDBScheduleStore_SetEnabled_NotFound.
func TestDBScheduleStore_SetEnabled_NotFound(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{execRowsAffected: 0})
	if err := store.SetEnabled(context.Background(), "missing", true); !errors.Is(err, scanorch.ErrScheduleNotFound) {
		t.Errorf("err = %v, want ErrScheduleNotFound", err)
	}
}

// TestDBScheduleStore_Update_Happy: PUT round-trip via the
// transitionUpdateRows route on the fake.
func TestDBScheduleStore_Update_Happy(t *testing.T) {
	row := makeScheduleRow("abc", "renamed")
	row["cron_expr"] = "0 9 * * 1-5"
	row["interval_seconds"] = int(0)
	q := &fakeQuerier{transitionUpdateRows: []map[string]any{row}}
	store := scanorch.NewDBScheduleStore(q)
	sched, err := store.Update(context.Background(), "abc", scanorch.UpdateScheduleRequest{
		Name:     "renamed",
		Template: scanorch.SubmitRequest{Input: "list:t.txt"},
		CronExpr: "0 9 * * 1-5",
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if sched.Name != "renamed" {
		t.Errorf("Name = %q", sched.Name)
	}
	if sched.CronExpr != "0 9 * * 1-5" {
		t.Errorf("CronExpr = %q", sched.CronExpr)
	}
	if !strings.HasPrefix(strings.TrimSpace(q.lastSQL), "UPDATE") {
		t.Errorf("expected UPDATE, got: %s", q.lastSQL)
	}
}

// TestDBScheduleStore_Update_NotFound: 0-row UPDATE-RETURNING
// surfaces ErrScheduleNotFound.
func TestDBScheduleStore_Update_NotFound(t *testing.T) {
	q := &fakeQuerier{transitionUpdateRows: nil}
	store := scanorch.NewDBScheduleStore(q)
	_, err := store.Update(context.Background(), "missing", scanorch.UpdateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	})
	if !errors.Is(err, scanorch.ErrScheduleNotFound) {
		t.Errorf("err = %v, want ErrScheduleNotFound", err)
	}
}

// TestDBScheduleStore_Update_NameRequired: validation
// short-circuits before SQL.
func TestDBScheduleStore_Update_NameRequired(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{})
	_, err := store.Update(context.Background(), "abc", scanorch.UpdateScheduleRequest{
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	})
	if !errors.Is(err, scanorch.ErrScheduleNameRequired) {
		t.Errorf("err = %v, want ErrScheduleNameRequired", err)
	}
}

// TestDBScheduleStore_Update_BadCron: cron parse error fails
// fast at Update time.
func TestDBScheduleStore_Update_BadCron(t *testing.T) {
	store := scanorch.NewDBScheduleStore(&fakeQuerier{})
	_, err := store.Update(context.Background(), "abc", scanorch.UpdateScheduleRequest{
		Name:     "x",
		Template: scanorch.SubmitRequest{Input: "stdin"},
		CronExpr: "* * * *", // 4 fields
	})
	if !errors.Is(err, scanorch.ErrCronWrongFieldCount) {
		t.Errorf("err = %v, want ErrCronWrongFieldCount", err)
	}
}

// TestDBScheduleStore_Update_IfMatchHappy: matching IfMatch
// → row returned (the conditional UPDATE returns the row).
func TestDBScheduleStore_Update_IfMatchHappy(t *testing.T) {
	row := makeScheduleRow("abc", "renamed")
	q := &fakeQuerier{transitionUpdateRows: []map[string]any{row}}
	store := scanorch.NewDBScheduleStore(q)
	stamp, ok := row["updated_at"].(time.Time)
	if !ok {
		t.Fatalf("updated_at not a time.Time")
	}
	_, err := store.Update(context.Background(), "abc", scanorch.UpdateScheduleRequest{
		Name:            "renamed",
		Template:        scanorch.SubmitRequest{Input: "list:t.txt"},
		IntervalSeconds: 3600,
		IfMatch:         &stamp,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// Verify the SQL bound the IfMatch arg ($9 in the
	// conditional path).
	if len(q.lastArgs) < 9 {
		t.Fatalf("lastArgs has %d items, want ≥ 9", len(q.lastArgs))
	}
	if got, _ := q.lastArgs[8].(time.Time); !got.Equal(stamp) {
		t.Errorf("$9 (IfMatch) = %v, want %v", q.lastArgs[8], stamp)
	}
}

// TestDBScheduleStore_Update_IfMatchMismatchExists: stale
// IfMatch + schedule exists → ErrSchedulePreconditionFailed.
func TestDBScheduleStore_Update_IfMatchMismatchExists(t *testing.T) {
	q := &fakeQuerier{
		transitionUpdateRows: nil, // 0 rows updated → mismatch
		classifyExistsRows: []map[string]any{
			{}, // 1 row → schedule exists
		},
	}
	store := scanorch.NewDBScheduleStore(q)
	stamp := time.Now().Add(-time.Hour)
	_, err := store.Update(context.Background(), "abc", scanorch.UpdateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
		IfMatch:         &stamp,
	})
	if !errors.Is(err, scanorch.ErrSchedulePreconditionFailed) {
		t.Errorf("err = %v, want ErrSchedulePreconditionFailed", err)
	}
}

// TestDBScheduleStore_Update_IfMatchMissing: 0-row UPDATE +
// schedule doesn't exist → ErrScheduleNotFound (NOT
// precondition).
func TestDBScheduleStore_Update_IfMatchMissing(t *testing.T) {
	q := &fakeQuerier{
		transitionUpdateRows: nil,
		classifyExistsRows:   []map[string]any{}, // 0 rows
	}
	store := scanorch.NewDBScheduleStore(q)
	stamp := time.Now().Add(-time.Hour)
	_, err := store.Update(context.Background(), "abc", scanorch.UpdateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
		IfMatch:         &stamp,
	})
	if !errors.Is(err, scanorch.ErrScheduleNotFound) {
		t.Errorf("err = %v, want ErrScheduleNotFound", err)
	}
}

// TestDBScheduleStore_SatisfiesScheduleStoreInterface.
func TestDBScheduleStore_SatisfiesScheduleStoreInterface(_ *testing.T) {
	var _ scanorch.ScheduleStore = scanorch.NewDBScheduleStore(&fakeQuerier{})
}
