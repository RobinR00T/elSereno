package scanorch_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// makeScheduleRow returns a baseline scan_schedules row map.
// Tests override individual columns as needed.
func makeScheduleRow(id, name string) map[string]any {
	return map[string]any{
		"id":                    id,
		"name":                  name,
		"template_input":        "list:t.txt",
		"template_plugins":      []string{"banner"},
		"template_default_port": int(0),
		"interval_seconds":      int(3600),
		"enabled":               true,
		"operator":              "alice",
		"created_at":            time.Now().UTC(),
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

// TestDBScheduleStore_SatisfiesScheduleStoreInterface.
func TestDBScheduleStore_SatisfiesScheduleStoreInterface(_ *testing.T) {
	var _ scanorch.ScheduleStore = scanorch.NewDBScheduleStore(&fakeQuerier{})
}
