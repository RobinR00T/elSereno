package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/scanorch"
)

func importNDJSON(t *testing.T, store scanorch.ScheduleStore, query, body string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/import"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-ndjson")
	rr := httptest.NewRecorder()
	newSchedRouter(store).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("import status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func scheduleByName(t *testing.T, store scanorch.ScheduleStore, name string) scanorch.ScanSchedule {
	t.Helper()
	all, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("schedule %q not imported", name)
	return scanorch.ScanSchedule{}
}

// TestImportSchedules_KeepsEnabled: an imported row keeps its "enabled",
// and a row without it is imported disabled. Until 2026-10-17 every
// imported schedule was created enabled, and since scans now run, an
// "enabled": false row would have started a real scan on the next tick
// (PITF-094).
func TestImportSchedules_KeepsEnabled(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	importNDJSON(t, store, "",
		`{"name":"on","template":{"input":"stdin"},"interval_seconds":60,"enabled":true}`+"\n"+
			`{"name":"off","template":{"input":"stdin"},"interval_seconds":60,"enabled":false}`+"\n"+
			`{"name":"unset","template":{"input":"stdin"},"interval_seconds":60}`+"\n")
	for name, want := range map[string]bool{"on": true, "off": false, "unset": false} {
		if got := scheduleByName(t, store, name).Enabled; got != want {
			t.Errorf("%s: enabled = %v, want %v", name, got, want)
		}
	}
}

// TestImportSchedules_OverwriteAppliesEnabled: overwriting applies the
// row's "enabled" in both directions.
func TestImportSchedules_OverwriteAppliesEnabled(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	ctx := context.Background()
	on, _ := store.Create(ctx, scanorch.CreateScheduleRequest{Name: "was-on", Template: scanorch.SubmitRequest{Input: "stdin"}, IntervalSeconds: 60}, "alice")
	off, _ := store.Create(ctx, scanorch.CreateScheduleRequest{Name: "was-off", Template: scanorch.SubmitRequest{Input: "stdin"}, IntervalSeconds: 60, StartDisabled: true}, "alice")
	if !on.Enabled || off.Enabled {
		t.Fatalf("setup: on=%v off=%v", on.Enabled, off.Enabled)
	}
	importNDJSON(t, store, "?on_conflict=overwrite",
		`{"name":"was-on","template":{"input":"NEW"},"interval_seconds":120,"enabled":false}`+"\n"+
			`{"name":"was-off","template":{"input":"NEW"},"interval_seconds":120,"enabled":true}`+"\n")
	if got := scheduleByName(t, store, "was-on"); got.Enabled || got.Template.Input != "NEW" {
		t.Errorf("was-on: enabled=%v input=%q, want false NEW", got.Enabled, got.Template.Input)
	}
	if got := scheduleByName(t, store, "was-off"); !got.Enabled || got.Template.Input != "NEW" {
		t.Errorf("was-off: enabled=%v input=%q, want true NEW", got.Enabled, got.Template.Input)
	}
}

// TestCloneSchedule_KeepsDisabled: a clone of a disabled schedule is
// disabled. Until 2026-10-17 every clone started enabled, so cloning a
// disabled schedule fired a real scan on the next tick (PITF-094).
func TestCloneSchedule_KeepsDisabled(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	ctx := context.Background()
	source, err := store.Create(ctx, scanorch.CreateScheduleRequest{
		Name:            "paused-fleet",
		Template:        scanorch.SubmitRequest{Input: "list:fleet.txt", Plugins: []string{"banner"}},
		IntervalSeconds: 3600,
		StartDisabled:   true,
	}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/schedules/"+source.ID+"/clone", nil)
	rr := httptest.NewRecorder()
	newSchedRouter(store).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data scanorch.ScanSchedule `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(ctx, resp.Data.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data.Enabled || stored.Enabled {
		t.Fatal("the clone of a disabled schedule is enabled")
	}
}
