package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/web/handlers"
)

func newSchedRouter(store scanorch.ScheduleStore) http.Handler {
	return handlers.Schedules(store, nil, nil)
}

// newSchedRouterWithAudit (v1.84+) routes the audit-enabled
// path. Used by force-overwrite + audit-list tests.
func newSchedRouterWithAudit(store scanorch.ScheduleStore, audit scanorch.ScheduleAuditStore) http.Handler {
	return handlers.Schedules(store, audit, nil)
}

// newSchedRouterWithScan (v1.92+) routes the scan-store-enabled
// path. Used by run-history tests.
func newSchedRouterWithScan(store scanorch.ScheduleStore, scanStore scanorch.Store) http.Handler {
	return handlers.Schedules(store, nil, scanStore)
}

// TestCreateSchedule_Happy: POST returns 201 + the schedule.
func TestCreateSchedule_Happy(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	body := []byte(`{"name":"daily","template":{"input":"stdin","plugins":["banner"]},"interval_seconds":86400}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules", bytes.NewReader(body))
	req.Header.Set("X-Operator", "alice")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data scanorch.ScanSchedule `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Name != "daily" {
		t.Errorf("Name = %q", resp.Data.Name)
	}
	if resp.Data.Operator != "alice" {
		t.Errorf("Operator = %q", resp.Data.Operator)
	}
	if !resp.Data.Enabled {
		t.Errorf("Enabled = false; want default true")
	}
}

// TestCreateSchedule_NameRequired returns 400.
func TestCreateSchedule_NameRequired(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"template":{"input":"stdin"},"interval_seconds":60}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestCreateSchedule_TemplateInputRequired returns 400.
func TestCreateSchedule_TemplateInputRequired(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","interval_seconds":60}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestListSchedules_NewestSorted returns the schedules
// alphabetically.
func TestListSchedules_NewestSorted(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	for _, name := range []string{"zeta", "alpha", "mike"} {
		_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
			Name:            name,
			Template:        scanorch.SubmitRequest{Input: "stdin"},
			IntervalSeconds: 60,
		}, "alice")
	}
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/schedules", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data []scanorch.ScanSchedule `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Data) != 3 {
		t.Fatalf("len = %d, want 3", len(resp.Data))
	}
	if resp.Data[0].Name != "alpha" || resp.Data[1].Name != "mike" || resp.Data[2].Name != "zeta" {
		t.Errorf("order = [%q, %q, %q], want [alpha, mike, zeta]",
			resp.Data[0].Name, resp.Data[1].Name, resp.Data[2].Name)
	}
}

// TestGetSchedule_NotFound.
func TestGetSchedule_NotFound(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/schedules/no-such", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestDeleteSchedule_Happy + NotFound.
func TestDeleteSchedule(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouter(store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/schedules/"+sched.ID, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rr.Code)
	}

	// Second delete → 404.
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/schedules/"+sched.ID, nil))
	if rr2.Code != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", rr2.Code)
	}
}

// TestEnableDisable: toggling sets the flag.
func TestEnableDisable(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouter(store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/"+sched.ID+"/disable", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable status = %d", rr.Code)
	}
	var resp struct {
		Data scanorch.ScanSchedule `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Data.Enabled {
		t.Errorf("Enabled = true after disable")
	}

	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/"+sched.ID+"/enable", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("enable status = %d", rr2.Code)
	}
	_ = json.NewDecoder(rr2.Body).Decode(&resp)
	if !resp.Data.Enabled {
		t.Errorf("Enabled = false after enable")
	}
}

// TestCreateSchedule_TimezoneHappy: a valid IANA zone is
// preserved in the response.
func TestCreateSchedule_TimezoneHappy(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	body := []byte(`{"name":"ny-9am","template":{"input":"stdin"},"cron_expr":"0 9 * * 1-5","timezone":"America/New_York"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data scanorch.ScanSchedule `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Data.Timezone != "America/New_York" {
		t.Errorf("Timezone = %q", resp.Data.Timezone)
	}
}

// TestCreateSchedule_TimezoneInvalid: bad zone → 400.
func TestCreateSchedule_TimezoneInvalid(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"cron_expr":"0 9 * * *","timezone":"Not/AReal-Zone"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestUpdateSchedule_Happy: PUT round-trip with a renamed
// schedule + cadence swap.
func TestUpdateSchedule_Happy(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "old-name",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouter(store)
	body := []byte(`{"name":"new-name","template":{"input":"list:t.txt","plugins":["modbus"]},"cron_expr":"0 9 * * 1-5"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/"+sched.ID, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data scanorch.ScanSchedule `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Name != "new-name" {
		t.Errorf("Name = %q, want new-name", resp.Data.Name)
	}
	if resp.Data.CronExpr != "0 9 * * 1-5" {
		t.Errorf("CronExpr = %q", resp.Data.CronExpr)
	}
	if resp.Data.IntervalSeconds != 0 {
		t.Errorf("IntervalSeconds = %d, want 0 after switching to cron", resp.Data.IntervalSeconds)
	}
}

// TestUpdateSchedule_NotFound returns 404.
func TestUpdateSchedule_NotFound(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"interval_seconds":60}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/nope", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestUpdateSchedule_BadCron returns 400 with the cron error.
func TestUpdateSchedule_BadCron(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouter(store)
	body := []byte(`{"name":"x","template":{"input":"stdin"},"cron_expr":"abc * * * *"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/"+sched.ID, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "cron") {
		t.Errorf("body should reference cron error: %s", rr.Body.String())
	}
}

// TestUpdateSchedule_CadenceConflict returns 400.
func TestUpdateSchedule_CadenceConflict(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouter(store)
	body := []byte(`{"name":"x","template":{"input":"stdin"},"interval_seconds":60,"cron_expr":"* * * * *"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/"+sched.ID, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestUpdateSchedule_ForceOverwrite_WritesAudit (v1.84+):
// X-Schedule-Force-Overwrite=true with audit store → audit
// row persisted with before/after snapshots.
func TestUpdateSchedule_ForceOverwrite_WritesAudit(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	audit := scanorch.NewMemoryScheduleAuditStore()
	router := newSchedRouterWithAudit(store, audit)
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "before",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	body := []byte(`{"name":"after","template":{"input":"stdin"},"interval_seconds":3600}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/"+sched.ID, bytes.NewReader(body))
	req.Header.Set("X-Operator", "bob")
	req.Header.Set("X-Schedule-Force-Overwrite", "true")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	events, _ := audit.ListBySchedule(context.Background(), sched.ID)
	if len(events) != 1 {
		t.Fatalf("audit len = %d, want 1", len(events))
	}
	if events[0].EventType != scanorch.ScheduleAuditEventForceOverwrite {
		t.Errorf("EventType = %q", events[0].EventType)
	}
	if events[0].Operator != "bob" {
		t.Errorf("Operator = %q, want bob", events[0].Operator)
	}
	// Sanity: the snapshots must contain the names.
	if !strings.Contains(string(events[0].PayloadBefore), `"name":"before"`) {
		t.Errorf("PayloadBefore = %s", events[0].PayloadBefore)
	}
	if !strings.Contains(string(events[0].PayloadAfter), `"name":"after"`) {
		t.Errorf("PayloadAfter = %s", events[0].PayloadAfter)
	}
}

// TestUpdateSchedule_ForceOverwrite_NoAuditStore (v1.84+):
// audit store nil + force header → update succeeds, no
// audit row.
func TestUpdateSchedule_ForceOverwrite_NoAuditStore(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store) // audit = nil
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	body := []byte(`{"name":"y","template":{"input":"stdin"},"interval_seconds":3600}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/"+sched.ID, bytes.NewReader(body))
	req.Header.Set("X-Schedule-Force-Overwrite", "true")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (audit nil is non-fatal)", rr.Code)
	}
}

// TestDeleteSchedule_WritesAudit (v1.88+): DELETE with
// audit store non-nil → "delete" event persisted with
// payload_before = full schedule, payload_after = null.
func TestDeleteSchedule_WritesAudit(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	audit := scanorch.NewMemoryScheduleAuditStore()
	router := newSchedRouterWithAudit(store, audit)
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "doomed",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/schedules/"+sched.ID, nil)
	req.Header.Set("X-Operator", "bob")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	events, _ := audit.ListBySchedule(context.Background(), sched.ID)
	if len(events) != 1 {
		t.Fatalf("audit len = %d, want 1", len(events))
	}
	if events[0].EventType != scanorch.ScheduleAuditEventDelete {
		t.Errorf("EventType = %q, want %q",
			events[0].EventType, scanorch.ScheduleAuditEventDelete)
	}
	if events[0].Operator != "bob" {
		t.Errorf("Operator = %q, want bob", events[0].Operator)
	}
	if !strings.Contains(string(events[0].PayloadBefore), `"name":"doomed"`) {
		t.Errorf("PayloadBefore missing name: %s", events[0].PayloadBefore)
	}
	if strings.TrimSpace(string(events[0].PayloadAfter)) != "null" {
		t.Errorf("PayloadAfter = %s, want null", events[0].PayloadAfter)
	}
}

// TestDeleteSchedule_NoAuditStore_StillSucceeds (v1.88+):
// nil audit store → delete still works, no audit row.
func TestDeleteSchedule_NoAuditStore_StillSucceeds(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store) // audit = nil
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/schedules/"+sched.ID, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rr.Code)
	}
}

// TestSetEnabled_WritesAudit (v1.88+): enable + disable
// each write the corresponding event type.
func TestSetEnabled_WritesAudit(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	audit := scanorch.NewMemoryScheduleAuditStore()
	router := newSchedRouterWithAudit(store, audit)
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	// Schedules start enabled. Disable first.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/"+sched.ID+"/disable", nil)
	req.Header.Set("X-Operator", "bob")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable status = %d", rr.Code)
	}
	// Now re-enable.
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/"+sched.ID+"/enable", nil)
	req.Header.Set("X-Operator", "alice")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable status = %d", rr.Code)
	}
	events, _ := audit.ListBySchedule(context.Background(), sched.ID)
	if len(events) != 2 {
		t.Fatalf("audit len = %d, want 2", len(events))
	}
	// Sorted newest-first: enable was last.
	if events[0].EventType != scanorch.ScheduleAuditEventSetEnabledTrue {
		t.Errorf("events[0].EventType = %q, want set_enabled_true",
			events[0].EventType)
	}
	if events[1].EventType != scanorch.ScheduleAuditEventSetEnabledFalse {
		t.Errorf("events[1].EventType = %q, want set_enabled_false",
			events[1].EventType)
	}
	if events[0].Operator != "alice" || events[1].Operator != "bob" {
		t.Errorf("operators = (%q, %q), want (alice, bob)",
			events[0].Operator, events[1].Operator)
	}
}

// TestSetEnabled_NoAuditStore_StillSucceeds (v1.88+).
func TestSetEnabled_NoAuditStore_StillSucceeds(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store) // audit = nil
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/"+sched.ID+"/disable", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestListScheduleAudit_Happy (v1.84+): GET /audit returns
// the persisted events.
func TestListScheduleAudit_Happy(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	audit := scanorch.NewMemoryScheduleAuditStore()
	router := newSchedRouterWithAudit(store, audit)
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	_, _ = audit.Append(context.Background(), scanorch.ScheduleAuditEvent{
		ScheduleID:    sched.ID,
		EventType:     scanorch.ScheduleAuditEventForceOverwrite,
		Operator:      "alice",
		PayloadBefore: json.RawMessage(`{}`),
		PayloadAfter:  json.RawMessage(`{}`),
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/schedules/"+sched.ID+"/audit", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data []scanorch.ScheduleAuditEvent `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Data) != 1 {
		t.Errorf("len = %d, want 1", len(resp.Data))
	}
}

// TestListScheduleAudit_404OnMissingSchedule (v1.84+).
func TestListScheduleAudit_404OnMissingSchedule(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	audit := scanorch.NewMemoryScheduleAuditStore()
	router := newSchedRouterWithAudit(store, audit)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/schedules/missing/audit", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestPruneScheduleAudit_Happy (v1.86+): DELETE returns the
// number of pruned events.
func TestPruneScheduleAudit_Happy(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	audit := scanorch.NewMemoryScheduleAuditStore()
	router := newSchedRouterWithAudit(store, audit)
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	for i := 0; i < 3; i++ {
		_, _ = audit.Append(context.Background(), scanorch.ScheduleAuditEvent{
			ScheduleID:    sched.ID,
			EventType:     scanorch.ScheduleAuditEventForceOverwrite,
			Operator:      "alice",
			PayloadBefore: json.RawMessage(`{}`),
			PayloadAfter:  json.RawMessage(`{}`),
		})
	}
	// Prune with a future cutoff → removes all 3.
	cutoff := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/schedules/audit?before="+cutoff, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			DeletedCount int `json:"deleted_count"`
		} `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Data.DeletedCount != 3 {
		t.Errorf("deleted_count = %d, want 3", resp.Data.DeletedCount)
	}
}

// TestPruneScheduleAudit_MissingBefore (v1.86+): no
// ?before= → 400.
func TestPruneScheduleAudit_MissingBefore(t *testing.T) {
	router := newSchedRouterWithAudit(
		scanorch.NewMemoryScheduleStore(),
		scanorch.NewMemoryScheduleAuditStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/schedules/audit", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestPruneScheduleAudit_MalformedBefore (v1.86+).
func TestPruneScheduleAudit_MalformedBefore(t *testing.T) {
	router := newSchedRouterWithAudit(
		scanorch.NewMemoryScheduleStore(),
		scanorch.NewMemoryScheduleAuditStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/schedules/audit?before=banana", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestPruneScheduleAudit_NilAuditStore (v1.86+).
func TestPruneScheduleAudit_NilAuditStore(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore()) // audit = nil
	cutoff := time.Now().UTC().Format(time.RFC3339)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/schedules/audit?before="+cutoff, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

// TestListScheduleAudit_503OnNilAuditStore (v1.84+).
func TestListScheduleAudit_503OnNilAuditStore(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store) // audit = nil
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/schedules/"+sched.ID+"/audit", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

// TestUpdateSchedule_IfMatchHappy: matching If-Match → 200.
func TestUpdateSchedule_IfMatchHappy(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	body := []byte(`{"name":"renamed","template":{"input":"stdin"},"interval_seconds":3600}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/"+sched.ID, bytes.NewReader(body))
	req.Header.Set("If-Match", sched.UpdatedAt.UTC().Format(time.RFC3339Nano))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateSchedule_IfMatchMismatch: stale If-Match → 412.
func TestUpdateSchedule_IfMatchMismatch(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	body := []byte(`{"name":"renamed","template":{"input":"stdin"},"interval_seconds":3600}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/"+sched.ID, bytes.NewReader(body))
	// Use a stale stamp.
	stale := sched.UpdatedAt.Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	req.Header.Set("If-Match", stale)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412", rr.Code)
	}
}

// TestUpdateSchedule_IfMatchMalformed: garbage header → 400.
func TestUpdateSchedule_IfMatchMalformed(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	body := []byte(`{"name":"x","template":{"input":"stdin"},"interval_seconds":3600}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/"+sched.ID, bytes.NewReader(body))
	req.Header.Set("If-Match", "not-a-timestamp")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestUpdateSchedule_NoIfMatchSucceeds: missing header skips
// precondition (back-compat with v1.74-v1.77 callers).
func TestUpdateSchedule_NoIfMatchSucceeds(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	body := []byte(`{"name":"y","template":{"input":"stdin"},"interval_seconds":3600}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/schedules/"+sched.ID, bytes.NewReader(body))
	// No If-Match header.
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestPreviewSchedule_IntervalHappy: a never-fired interval
// schedule preview returns 200 + non-zero next_fire_at.
func TestPreviewSchedule_IntervalHappy(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"interval_seconds":3600}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/preview", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			NextFireAt string `json:"next_fire_at"`
			Timezone   string `json:"timezone"`
		} `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Data.NextFireAt == "" {
		t.Errorf("next_fire_at = empty, want a timestamp")
	}
}

// TestPreviewSchedule_CountFives: count=5 returns 5 fires
// (v1.79+).
func TestPreviewSchedule_CountFives(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"cron_expr":"@daily"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/preview?count=5", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			NextFires  []string `json:"next_fires"`
			NextFireAt string   `json:"next_fire_at"`
		} `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Data.NextFires) != 5 {
		t.Errorf("next_fires len = %d, want 5", len(resp.Data.NextFires))
	}
	// Back-compat: next_fire_at = next_fires[0].
	if resp.Data.NextFireAt == "" || resp.Data.NextFireAt != resp.Data.NextFires[0] {
		t.Errorf("next_fire_at = %q, want = next_fires[0] = %q",
			resp.Data.NextFireAt, resp.Data.NextFires[0])
	}
}

// TestPreviewSchedule_CountDefault: no `count` param → 1 fire
// (back-compat with v1.77/v1.78).
func TestPreviewSchedule_CountDefault(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"cron_expr":"@daily"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/preview", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			NextFires []string `json:"next_fires"`
		} `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Data.NextFires) != 1 {
		t.Errorf("default len = %d, want 1", len(resp.Data.NextFires))
	}
}

// TestPreviewSchedule_CountMalformed: garbage count → 400.
func TestPreviewSchedule_CountMalformed(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"cron_expr":"@daily"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/preview?count=banana", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestPreviewSchedule_CountClamp: count=100 clamps to the
// scanorch.PreviewNextFiresMaxCount cap.
func TestPreviewSchedule_CountClamp(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"cron_expr":"@daily"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/preview?count=100", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data struct {
			NextFires []string `json:"next_fires"`
		} `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Data.NextFires) != scanorch.PreviewNextFiresMaxCount {
		t.Errorf("clamped len = %d, want %d",
			len(resp.Data.NextFires), scanorch.PreviewNextFiresMaxCount)
	}
}

// TestPreviewSchedule_CronHappy: a cron-based preview returns
// 200 + the timezone echoed back.
func TestPreviewSchedule_CronHappy(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"cron_expr":"0 9 * * 1-5","timezone":"America/New_York"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/preview", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			NextFireAt string `json:"next_fire_at"`
			Timezone   string `json:"timezone"`
		} `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Data.Timezone != "America/New_York" {
		t.Errorf("timezone = %q, want America/New_York", resp.Data.Timezone)
	}
	if resp.Data.NextFireAt == "" {
		t.Errorf("next_fire_at = empty, want a timestamp")
	}
}

// TestPreviewSchedule_BadCron: invalid cron → 400.
func TestPreviewSchedule_BadCron(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"cron_expr":"garbage"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/preview", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestPreviewSchedule_CadenceRequired: empty cadence → 400.
func TestPreviewSchedule_CadenceRequired(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"}}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/schedules/preview", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestListSchedules_PopulatesNextFireAt: response carries
// next_fire_at on every schedule (v1.77+).
func TestListSchedules_PopulatesNextFireAt(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "every-h",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 3600,
	}, "alice")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/schedules", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data []struct {
			NextFireAt string `json:"next_fire_at"`
		} `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Data) != 1 || resp.Data[0].NextFireAt == "" {
		t.Errorf("next_fire_at not populated on List response (data=%+v)", resp.Data)
	}
}

// TestSchedules_NilStoreReturns503.
func TestSchedules_NilStoreReturns503(t *testing.T) {
	router := newSchedRouter(nil)
	for _, tc := range []struct {
		verb string
		path string
	}{
		{http.MethodPost, "/api/v1/schedules"},
		{http.MethodGet, "/api/v1/schedules"},
		{http.MethodGet, "/api/v1/schedules/abc"},
		{http.MethodPut, "/api/v1/schedules/abc"},
		{http.MethodDelete, "/api/v1/schedules/abc"},
		{http.MethodPost, "/api/v1/schedules/abc/enable"},
		{http.MethodPost, "/api/v1/schedules/abc/disable"},
		{http.MethodPost, "/api/v1/schedules/preview"},
		{http.MethodGet, "/api/v1/schedules/abc/audit"},
		{http.MethodDelete, "/api/v1/schedules/audit"},
	} {
		t.Run(tc.verb+" "+tc.path, func(t *testing.T) {
			var body *strings.Reader
			if tc.verb == http.MethodPost || tc.verb == http.MethodPut {
				body = strings.NewReader(`{"name":"x","template":{"input":"stdin"},"interval_seconds":60}`)
			}
			var req *http.Request
			if body != nil {
				req = httptest.NewRequestWithContext(t.Context(), tc.verb, tc.path, body)
			} else {
				req = httptest.NewRequestWithContext(t.Context(), tc.verb, tc.path, nil)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rr.Code)
			}
		})
	}
}

// TestListScheduleRuns_Happy (v1.92+): scheduler-fired jobs
// surface via GET /schedules/{id}/runs in newest-first order.
func TestListScheduleRuns_Happy(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	scanStore := scanorch.NewMemoryStore()
	sched, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "fleet-hourly",
		Template:        scanorch.SubmitRequest{Input: "list:fleet.txt"},
		IntervalSeconds: 3600,
	}, "alice")
	if err != nil {
		t.Fatalf("Create err = %v", err)
	}
	// Append 3 scheduler-fired jobs.
	for i := 0; i < 3; i++ {
		if _, err := scanStore.SubmitFromSchedule(context.Background(),
			sched.Template, "alice", sched.ID); err != nil {
			t.Fatalf("SubmitFromSchedule err = %v", err)
		}
	}
	// And a manual job that must NOT appear in the listing.
	if _, err := scanStore.Submit(context.Background(),
		scanorch.SubmitRequest{Input: "stdin"}, "alice"); err != nil {
		t.Fatalf("Submit err = %v", err)
	}
	router := newSchedRouterWithScan(store, scanStore)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/runs", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	// v2.0: response is now {items, next_before?} envelope.
	var resp struct {
		Data struct {
			Items      []scanorch.Job `json:"items"`
			NextBefore string         `json:"next_before"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode err = %v", err)
	}
	if len(resp.Data.Items) != 3 {
		t.Errorf("runs = %d, want 3", len(resp.Data.Items))
	}
	for _, j := range resp.Data.Items {
		if j.TriggeredByScheduleID != sched.ID {
			t.Errorf("job %s TriggeredByScheduleID = %q, want %q",
				j.ID, j.TriggeredByScheduleID, sched.ID)
		}
	}
	// 3 jobs < default limit (50) → no next_before cursor.
	if resp.Data.NextBefore != "" {
		t.Errorf("next_before = %q, want empty (full page should be a complete result)", resp.Data.NextBefore)
	}
}

// TestListScheduleRuns_Pagination (v2.0+): full-page request
// returns next_before; using that cursor returns the next page;
// final page omits next_before.
func TestListScheduleRuns_Pagination(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	scanStore := scanorch.NewMemoryStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "paginated",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	// Insert 5 jobs with deterministic ordering. Each Submit
	// stamps a fresh CreatedAt; the in-memory store preserves
	// insert-order.
	for i := 0; i < 5; i++ {
		_, _ = scanStore.SubmitFromSchedule(context.Background(),
			sched.Template, "alice", sched.ID)
		time.Sleep(time.Millisecond) // ensure distinct CreatedAt.
	}
	router := newSchedRouterWithScan(store, scanStore)

	// Page 1: limit=2 → newest 2 jobs + next_before cursor.
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/runs?limit=2", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("page1 status = %d", rr.Code)
	}
	var page1 struct {
		Data struct {
			Items      []scanorch.Job `json:"items"`
			NextBefore string         `json:"next_before"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &page1)
	if len(page1.Data.Items) != 2 {
		t.Fatalf("page1 items = %d, want 2", len(page1.Data.Items))
	}
	if page1.Data.NextBefore == "" {
		t.Fatal("page1 next_before should be present (full page)")
	}

	// Page 2: use cursor → next 2 jobs.
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/runs?limit=2&before="+page1.Data.NextBefore, nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("page2 status = %d body=%s", rr2.Code, rr2.Body.String())
	}
	var page2 struct {
		Data struct {
			Items      []scanorch.Job `json:"items"`
			NextBefore string         `json:"next_before"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr2.Body.Bytes(), &page2)
	if len(page2.Data.Items) != 2 {
		t.Errorf("page2 items = %d, want 2", len(page2.Data.Items))
	}
	if page1.Data.Items[0].ID == page2.Data.Items[0].ID {
		t.Errorf("page1 + page2 should not share IDs; first ID = %q", page1.Data.Items[0].ID)
	}

	// Page 3: last single row (5 total - 4 returned = 1
	// remaining); should NOT have a next_before cursor since
	// the response is partial.
	rr3 := httptest.NewRecorder()
	router.ServeHTTP(rr3, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/runs?limit=2&before="+page2.Data.NextBefore, nil))
	var page3 struct {
		Data struct {
			Items      []scanorch.Job `json:"items"`
			NextBefore string         `json:"next_before"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr3.Body.Bytes(), &page3)
	if len(page3.Data.Items) != 1 {
		t.Errorf("page3 items = %d, want 1", len(page3.Data.Items))
	}
	if page3.Data.NextBefore != "" {
		t.Errorf("page3 next_before = %q, want empty (partial page = last page)", page3.Data.NextBefore)
	}
}

// TestCreateSchedule_Tags (v2.4+): tags round-trip through
// create + canonicalised (deduped + sorted).
func TestCreateSchedule_Tags(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	body := []byte(`{"name":"tagged","template":{"input":"stdin"},"interval_seconds":60,"tags":["prod","net-team","prod"]}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data scanorch.ScanSchedule `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	want := []string{"net-team", "prod"}
	if len(resp.Data.Tags) != len(want) {
		t.Fatalf("tags = %v, want %v", resp.Data.Tags, want)
	}
	for i := range want {
		if resp.Data.Tags[i] != want[i] {
			t.Errorf("tags[%d] = %q, want %q", i, resp.Data.Tags[i], want[i])
		}
	}
}

// TestCreateSchedule_TagsInvalidShape (v2.4+): uppercase /
// space → 400.
func TestCreateSchedule_TagsInvalidShape(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := []byte(`{"name":"x","template":{"input":"stdin"},"interval_seconds":60,"tags":["Bad Tag"]}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestListSchedules_ByTag (v2.4+): ?tag=critical filters.
func TestListSchedules_ByTag(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name: "a", Template: scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60, Tags: []string{"prod", "critical"},
	}, "alice")
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name: "b", Template: scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60, Tags: []string{"dev"},
	}, "alice")
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name: "c", Template: scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60, Tags: []string{"prod"},
	}, "alice")
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules?tag=critical", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data []scanorch.ScanSchedule `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Data) != 1 || resp.Data[0].Name != "a" {
		t.Errorf("filtered = %v, want [a]", resp.Data)
	}
}

// TestScheduleStatsTimeseries (v2.11+): bucketed stats.
func TestScheduleStatsTimeseries(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	scanStore := scanorch.NewMemoryStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name: "ts", Template: scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	// Submit a single completed job at "now".
	job, _ := scanStore.SubmitFromSchedule(context.Background(),
		sched.Template, "alice", sched.ID)
	_, _ = scanStore.Transition(context.Background(), job.ID, scanorch.StateRunning, scanorch.TransitionFields{})
	_, _ = scanStore.Transition(context.Background(), job.ID, scanorch.StateCompleted,
		scanorch.TransitionFields{Stats: &scanorch.Stats{FindingsCount: 7}})
	router := newSchedRouterWithScan(store, scanStore)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/stats/timeseries?bucket=hour&days=2", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			Bucket string                         `json:"bucket"`
			Series []scanorch.ScheduleStatsBucket `json:"series"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Data.Bucket != "hour" {
		t.Errorf("bucket = %q, want hour", resp.Data.Bucket)
	}
	// 2 days = 48 hour buckets (pre-filled).
	if len(resp.Data.Series) < 47 || len(resp.Data.Series) > 49 {
		t.Errorf("series len = %d, want ~48", len(resp.Data.Series))
	}
	// Exactly one bucket should have TotalRuns=1; the rest are zero.
	var nonzeroCount, totalRuns, totalFindings int
	for _, b := range resp.Data.Series {
		if b.TotalRuns > 0 {
			nonzeroCount++
		}
		totalRuns += b.TotalRuns
		totalFindings += b.TotalFindings
	}
	if nonzeroCount != 1 {
		t.Errorf("nonzero buckets = %d, want 1", nonzeroCount)
	}
	if totalRuns != 1 {
		t.Errorf("total runs across series = %d, want 1", totalRuns)
	}
	if totalFindings != 7 {
		t.Errorf("total findings across series = %d, want 7", totalFindings)
	}
}

// TestScheduleStatsTimeseries_BadBucket (v2.11+): unknown
// bucket → 400.
func TestScheduleStatsTimeseries_BadBucket(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	scanStore := scanorch.NewMemoryStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name: "x", Template: scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouterWithScan(store, scanStore)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/stats/timeseries?bucket=month", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestListScheduleClones_AfterClone (v2.10+): clone via POST,
// then /clones returns the new schedule.
func TestListScheduleClones_AfterClone(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	source, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "src",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouter(store)
	// Clone twice with explicit names.
	for _, n := range []string{"clone-a", "clone-b"} {
		body := strings.NewReader(`{"name":"` + n + `"}`)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"/api/v1/schedules/"+source.ID+"/clone", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("clone %q status = %d body=%s", n, rr.Code, rr.Body.String())
		}
	}
	// /clones returns both.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+source.ID+"/clones", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data []scanorch.ScanSchedule `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Data) != 2 {
		t.Fatalf("clones = %d, want 2", len(resp.Data))
	}
	for _, c := range resp.Data {
		if c.SourceScheduleID != source.ID {
			t.Errorf("clone %s has SourceScheduleID = %q, want %q",
				c.Name, c.SourceScheduleID, source.ID)
		}
	}
}

// TestListScheduleClones_None (v2.10+): never-cloned source →
// empty array.
func TestListScheduleClones_None(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	source, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "src",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+source.ID+"/clones", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
}

// TestListSchedules_MultiTag_And (v2.9+): all-of semantics.
func TestListSchedules_MultiTag_And(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	mk := func(name string, tags ...string) {
		_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
			Name: name, Template: scanorch.SubmitRequest{Input: "stdin"},
			IntervalSeconds: 60, Tags: tags,
		}, "alice")
	}
	mk("a", "prod", "critical")
	mk("b", "prod")
	mk("c", "critical")
	mk("d", "dev", "critical")
	router := newSchedRouter(store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules?tag=prod&tag=critical", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data []scanorch.ScanSchedule `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Data) != 1 || resp.Data[0].Name != "a" {
		t.Errorf("AND filter result = %v, want [a]", resp.Data)
	}
}

// TestListSchedules_MultiTag_Or (v2.9+): any-of semantics.
func TestListSchedules_MultiTag_Or(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	mk := func(name string, tags ...string) {
		_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
			Name: name, Template: scanorch.SubmitRequest{Input: "stdin"},
			IntervalSeconds: 60, Tags: tags,
		}, "alice")
	}
	mk("a", "prod", "critical")
	mk("b", "prod")
	mk("c", "critical")
	mk("d", "dev")
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules?tag=prod&tag=critical&op=or", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data []scanorch.ScanSchedule `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Data) != 3 {
		t.Errorf("OR filter count = %d, want 3 (a,b,c)", len(resp.Data))
	}
}

// TestListSchedules_BadOp (v2.9+): unknown op → 400.
func TestListSchedules_BadOp(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules?tag=x&op=xor", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestListScheduleTags (v2.5+): tag aggregate counts across
// the store sorted by count DESC, tag ASC.
func TestListScheduleTags(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	mk := func(name string, tags ...string) {
		_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
			Name: name, Template: scanorch.SubmitRequest{Input: "stdin"},
			IntervalSeconds: 60, Tags: tags,
		}, "alice")
	}
	mk("a", "prod")
	mk("b", "prod", "critical")
	mk("c", "prod", "critical")
	mk("d", "dev")
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/tags", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data []scanorch.TagCount `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Data) != 3 {
		t.Fatalf("tag counts = %d, want 3", len(resp.Data))
	}
	if resp.Data[0].Tag != "prod" || resp.Data[0].Count != 3 {
		t.Errorf("first = (%q, %d), want (prod, 3)", resp.Data[0].Tag, resp.Data[0].Count)
	}
	if resp.Data[1].Tag != "critical" || resp.Data[1].Count != 2 {
		t.Errorf("second = (%q, %d), want (critical, 2)", resp.Data[1].Tag, resp.Data[1].Count)
	}
	if resp.Data[2].Tag != "dev" || resp.Data[2].Count != 1 {
		t.Errorf("third = (%q, %d), want (dev, 1)", resp.Data[2].Tag, resp.Data[2].Count)
	}
}

// TestListSchedules_TagNotIn (v2.17+): exclude schedules
// carrying any of the listed tags.
func TestListSchedules_TagNotIn(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	mk := func(name string, tags ...string) {
		_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
			Name: name, Template: scanorch.SubmitRequest{Input: "stdin"},
			IntervalSeconds: 60, Tags: tags,
		}, "alice")
	}
	mk("a", "prod")             // exclude
	mk("b", "dev")              // exclude
	mk("c", "staging")          // include (not in list)
	mk("d")                     // include (untagged)
	mk("e", "prod", "critical") // exclude (has prod)
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules?tag=prod&tag=dev&op=not_in", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data []scanorch.ScanSchedule `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Data) != 2 {
		t.Fatalf("count = %d, want 2 (c + d)", len(resp.Data))
	}
	names := []string{resp.Data[0].Name, resp.Data[1].Name}
	if names[0] != "c" || names[1] != "d" {
		t.Errorf("names = %v, want [c d]", names)
	}
}

// TestListSchedules_TagNotIn_SingleTag (v2.17+): even with a
// single tag the not_in path bypasses the v2.4 single-tag
// fast path (which would do contains-semantics).
func TestListSchedules_TagNotIn_SingleTag(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	mk := func(name string, tags ...string) {
		_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
			Name: name, Template: scanorch.SubmitRequest{Input: "stdin"},
			IntervalSeconds: 60, Tags: tags,
		}, "alice")
	}
	mk("with-prod", "prod")
	mk("no-prod")
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules?tag=prod&op=not_in", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data []scanorch.ScanSchedule `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Data) != 1 || resp.Data[0].Name != "no-prod" {
		t.Errorf("got %v, want [no-prod]", resp.Data)
	}
}

// TestRenameTag_HappyPath (v2.16+): rename swaps + dedupes.
func TestRenameTag_HappyPath(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	mk := func(name string, tags ...string) {
		_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
			Name: name, Template: scanorch.SubmitRequest{Input: "stdin"},
			IntervalSeconds: 60, Tags: tags,
		}, "alice")
	}
	mk("a", "prod", "critical")
	mk("b", "production", "critical") // already has new tag
	mk("c", "dev")                    // unaffected
	router := newSchedRouter(store)
	body := strings.NewReader(`{"from":"prod","to":"production"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/tags/rename", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			From         string `json:"from"`
			To           string `json:"to"`
			RenamedCount int64  `json:"renamed_count"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Data.RenamedCount != 1 {
		t.Errorf("renamed_count = %d, want 1 (only schedule 'a' had 'prod')", resp.Data.RenamedCount)
	}
	// Verify 'a' now has [critical, production] canonical.
	all, _ := store.List(context.Background())
	for _, s := range all {
		if s.Name == "a" {
			if len(s.Tags) != 2 || s.Tags[0] != "critical" || s.Tags[1] != "production" {
				t.Errorf("a.Tags = %v, want [critical production]", s.Tags)
			}
		}
	}
}

// TestRenameTag_NoOp (v2.16+): from == to → 400.
func TestRenameTag_NoOp(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := strings.NewReader(`{"from":"x","to":"x"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/tags/rename", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestRenameTag_BadShape (v2.16+): to contains bad chars
// → 400.
func TestRenameTag_BadShape(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	body := strings.NewReader(`{"from":"prod","to":"BAD TAG"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/tags/rename", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestListScheduleTags_ETag (v2.7+): first call returns
// ETag header + 200; second call with matching
// If-None-Match returns 304.
func TestListScheduleTags_ETag(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name: "a", Template: scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60, Tags: []string{"prod"},
	}, "alice")
	router := newSchedRouter(store)

	// First request: no If-None-Match → 200 + ETag.
	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/tags", nil))
	if rr1.Code != http.StatusOK {
		t.Fatalf("first call status = %d", rr1.Code)
	}
	etag := rr1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("first call missing ETag header")
	}

	// Second request: matching If-None-Match → 304.
	req2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/tags", nil)
	req2.Header.Set("If-None-Match", etag)
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNotModified {
		t.Errorf("304 expected on matching If-None-Match, got %d", rr2.Code)
	}
	// Body must be empty on 304.
	if rr2.Body.Len() != 0 {
		t.Errorf("304 body len = %d, want 0", rr2.Body.Len())
	}
	// ETag header still set on 304 (RFC 7232).
	if rr2.Header().Get("ETag") != etag {
		t.Errorf("304 ETag mismatch")
	}

	// Third request: mutate the store, then re-send the OLD
	// If-None-Match → 200 + different ETag.
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name: "b", Template: scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60, Tags: []string{"dev"},
	}, "alice")
	req3 := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/tags", nil)
	req3.Header.Set("If-None-Match", etag)
	rr3 := httptest.NewRecorder()
	router.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("post-mutation status = %d, want 200", rr3.Code)
	}
	if rr3.Header().Get("ETag") == etag {
		t.Errorf("ETag should differ after mutation; both = %s", etag)
	}
}

// TestListScheduleTags_Empty (v2.5+): no schedules → empty
// array so dashboards render `tags: []`.
func TestListScheduleTags_Empty(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/tags", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	// Body should contain a `"data"` key whose value is an
	// empty array. Pretty-print whitespace varies; just decode
	// and check len==0 + that Data is non-nil-and-empty (not
	// JSON null).
	var resp struct {
		Data []scanorch.TagCount `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(resp.Data) != 0 {
		t.Errorf("data len = %d, want 0", len(resp.Data))
	}
}

// TestScheduleStats_Empty (v2.2+): no runs → all zeros, valid
// payload (no NaN from division-by-zero).
func TestScheduleStats_Empty(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	scanStore := scanorch.NewMemoryStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "empty",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouterWithScan(store, scanStore)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/stats", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			TotalRuns   int     `json:"total_runs"`
			SuccessRate float64 `json:"success_rate"`
			WindowDays  int     `json:"window_days"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Data.TotalRuns != 0 {
		t.Errorf("total_runs = %d, want 0", resp.Data.TotalRuns)
	}
	if resp.Data.SuccessRate != 0 {
		t.Errorf("success_rate = %f, want 0 (no NaN)", resp.Data.SuccessRate)
	}
	if resp.Data.WindowDays != 7 {
		t.Errorf("window_days = %d, want 7 (default)", resp.Data.WindowDays)
	}
}

// TestScheduleStats_HappyMix (v2.2+): runs in mixed states →
// per-state counters + success rate correct.
func TestScheduleStats_HappyMix(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	scanStore := scanorch.NewMemoryStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "mix",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	// 2 completed + 1 failed = 3 runs. SuccessRate = 2/3.
	for i := 0; i < 3; i++ {
		job, _ := scanStore.SubmitFromSchedule(context.Background(),
			sched.Template, "alice", sched.ID)
		_, _ = scanStore.Transition(context.Background(), job.ID, scanorch.StateRunning, scanorch.TransitionFields{})
		toState := scanorch.StateCompleted
		if i == 2 {
			toState = scanorch.StateFailed
		}
		_, _ = scanStore.Transition(context.Background(), job.ID, toState, scanorch.TransitionFields{
			Stats: &scanorch.Stats{FindingsCount: 5},
		})
	}
	router := newSchedRouterWithScan(store, scanStore)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/stats?days=30", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			TotalRuns         int     `json:"total_runs"`
			Completed         int     `json:"completed"`
			Failed            int     `json:"failed"`
			SuccessRate       float64 `json:"success_rate"`
			TotalFindings     int     `json:"total_findings"`
			AvgFindingsPerRun float64 `json:"avg_findings_per_run"`
			WindowDays        int     `json:"window_days"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Data.TotalRuns != 3 {
		t.Errorf("total_runs = %d, want 3", resp.Data.TotalRuns)
	}
	if resp.Data.Completed != 2 {
		t.Errorf("completed = %d, want 2", resp.Data.Completed)
	}
	if resp.Data.Failed != 1 {
		t.Errorf("failed = %d, want 1", resp.Data.Failed)
	}
	wantRate := 2.0 / 3.0
	if resp.Data.SuccessRate < wantRate-0.001 || resp.Data.SuccessRate > wantRate+0.001 {
		t.Errorf("success_rate = %f, want ~%f", resp.Data.SuccessRate, wantRate)
	}
	if resp.Data.TotalFindings != 15 {
		t.Errorf("total_findings = %d, want 15", resp.Data.TotalFindings)
	}
	if resp.Data.WindowDays != 30 {
		t.Errorf("window_days = %d, want 30", resp.Data.WindowDays)
	}
}

// TestScheduleStats_BadDays (v2.2+): malformed ?days= → 400.
func TestScheduleStats_BadDays(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	scanStore := scanorch.NewMemoryStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouterWithScan(store, scanStore)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/stats?days=abc", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestListScheduleRuns_BadBefore (v2.0+): malformed cursor → 400.
func TestListScheduleRuns_BadBefore(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	scanStore := scanorch.NewMemoryStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouterWithScan(store, scanStore)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/runs?before=not-a-date", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestListScheduleRuns_ScheduleNotFound (v1.92+): unknown
// schedule ID → 404.
func TestListScheduleRuns_ScheduleNotFound(t *testing.T) {
	router := newSchedRouterWithScan(scanorch.NewMemoryScheduleStore(), scanorch.NewMemoryStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/notreal/runs", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestCloneSchedule_DefaultName (v1.93+): empty body → name
// defaults to "<source> (copy)" + everything else copied.
func TestCloneSchedule_DefaultName(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	source, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "nightly-fleet",
		Template:        scanorch.SubmitRequest{Input: "list:fleet.txt", Plugins: []string{"banner"}},
		IntervalSeconds: 86400,
		Timezone:        "UTC",
	}, "alice")
	if err != nil {
		t.Fatalf("Create err = %v", err)
	}
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/"+source.ID+"/clone", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data scanorch.ScanSchedule `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode err = %v", err)
	}
	if resp.Data.Name != "nightly-fleet (copy)" {
		t.Errorf("Name = %q, want %q", resp.Data.Name, "nightly-fleet (copy)")
	}
	if resp.Data.ID == source.ID {
		t.Errorf("clone has same ID as source: %s", resp.Data.ID)
	}
	if resp.Data.IntervalSeconds != source.IntervalSeconds {
		t.Errorf("IntervalSeconds = %d, want %d", resp.Data.IntervalSeconds, source.IntervalSeconds)
	}
	if !resp.Data.Enabled {
		t.Errorf("Enabled = false, want true (clones always start enabled)")
	}
}

// TestCloneSchedule_OverrideName (v1.93+): non-empty name in
// body wins over the default "(copy)".
func TestCloneSchedule_OverrideName(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	source, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "nightly-fleet",
		Template:        scanorch.SubmitRequest{Input: "list:fleet.txt"},
		IntervalSeconds: 86400,
	}, "alice")
	router := newSchedRouter(store)
	body := strings.NewReader(`{"name":"weekly-fleet","interval_seconds":604800}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/"+source.ID+"/clone", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data scanorch.ScanSchedule `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Data.Name != "weekly-fleet" {
		t.Errorf("Name = %q, want %q", resp.Data.Name, "weekly-fleet")
	}
	if resp.Data.IntervalSeconds != 604800 {
		t.Errorf("IntervalSeconds = %d, want 604800", resp.Data.IntervalSeconds)
	}
}

// TestExportSchedules_CSV (v1.97+): CSV export has header row +
// one row per schedule with the 10 documented columns.
func TestExportSchedules_CSV(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "daily-fleet",
		Template:        scanorch.SubmitRequest{Input: "list:fleet.txt", Plugins: []string{"banner", "modbus"}},
		IntervalSeconds: 86400,
	}, "alice")
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:     "cron-1",
		Template: scanorch.SubmitRequest{Input: "stdin"},
		CronExpr: "0 2 * * *",
		Timezone: "Europe/Madrid",
	}, "alice")

	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/export?format=csv", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv*", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "id,name,cadence,enabled,operator,created_at,last_fired_at,audit_retention_days,input,plugins") {
		t.Errorf("missing CSV header in body:\n%s", body)
	}
	if !strings.Contains(body, "daily-fleet,interval=86400s,true,alice") {
		t.Errorf("missing daily-fleet row:\n%s", body)
	}
	if !strings.Contains(body, "cron=0 2 * * * (Europe/Madrid)") {
		t.Errorf("missing cron schedule row:\n%s", body)
	}
}

// TestExportSchedules_NDJSON (v1.97+): NDJSON export is one
// JSON object per line.
func TestExportSchedules_NDJSON(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "a",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "b",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/export?format=ndjson", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", ct)
	}
	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2: %s", len(lines), rr.Body.String())
	}
	for _, line := range lines {
		var s scanorch.ScanSchedule
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Errorf("decode err = %v on line: %s", err, line)
		}
	}
}

// TestImportSchedules_NDJSON_CreateFresh (v1.99+): import 2
// schedules into an empty store; both created with fresh IDs.
func TestImportSchedules_NDJSON_CreateFresh(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	body := strings.NewReader(
		`{"id":"old-id-a","name":"alpha","template":{"input":"stdin"},"interval_seconds":60}` + "\n" +
			`{"id":"old-id-b","name":"beta","template":{"input":"stdin"},"interval_seconds":120}` + "\n",
	)
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/import", body)
	req.Header.Set("Content-Type", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			Imported int                             `json:"imported"`
			Skipped  int                             `json:"skipped"`
			Items    []handlers.ScheduleImportResult `json:"items"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Data.Imported != 2 {
		t.Errorf("imported = %d, want 2", resp.Data.Imported)
	}
	if len(resp.Data.Items) != 2 {
		t.Errorf("items = %d, want 2", len(resp.Data.Items))
	}
	for _, item := range resp.Data.Items {
		if item.Outcome != "created" {
			t.Errorf("item[%d] outcome = %q, want created", item.Index, item.Outcome)
		}
		if strings.HasPrefix(item.ID, "old-id-") {
			t.Errorf("item[%d] ID = %q, expected fresh ID not the source's", item.Index, item.ID)
		}
	}
}

// TestImportSchedules_Skip_OnConflict (v1.99+): default `skip`
// policy leaves existing same-named schedules alone.
func TestImportSchedules_Skip_OnConflict(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	existing, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "alpha",
		Template:        scanorch.SubmitRequest{Input: "ORIG"},
		IntervalSeconds: 60,
	}, "alice")
	body := strings.NewReader(
		`{"name":"alpha","template":{"input":"NEW"},"interval_seconds":120}` + "\n",
	)
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/import", body)
	req.Header.Set("Content-Type", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	got, _ := store.Get(context.Background(), existing.ID)
	if got.Template.Input != "ORIG" {
		t.Errorf("input = %q, want ORIG (skip should not overwrite)", got.Template.Input)
	}
}

// TestImportSchedules_Overwrite (v1.99+): `?on_conflict=overwrite`
// updates the existing row in-place (same ID).
func TestImportSchedules_Overwrite(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	existing, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "alpha",
		Template:        scanorch.SubmitRequest{Input: "ORIG"},
		IntervalSeconds: 60,
	}, "alice")
	body := strings.NewReader(
		`{"name":"alpha","template":{"input":"NEW"},"interval_seconds":120}` + "\n",
	)
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/import?on_conflict=overwrite", body)
	req.Header.Set("Content-Type", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	got, _ := store.Get(context.Background(), existing.ID)
	if got.Template.Input != "NEW" {
		t.Errorf("input = %q, want NEW (overwrite)", got.Template.Input)
	}
	if got.IntervalSeconds != 120 {
		t.Errorf("interval = %d, want 120", got.IntervalSeconds)
	}
}

// TestImportSchedules_Rename (v1.99+): `?on_conflict=rename`
// creates a fresh schedule with " (imported)" suffix.
func TestImportSchedules_Rename(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	_, _ = store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "alpha",
		Template:        scanorch.SubmitRequest{Input: "ORIG"},
		IntervalSeconds: 60,
	}, "alice")
	body := strings.NewReader(
		`{"name":"alpha","template":{"input":"NEW"},"interval_seconds":120}` + "\n",
	)
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/import?on_conflict=rename", body)
	req.Header.Set("Content-Type", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	all, _ := store.List(context.Background())
	if len(all) != 2 {
		t.Fatalf("schedules count = %d, want 2", len(all))
	}
	var renamed *scanorch.ScanSchedule
	for i := range all {
		if all[i].Name == "alpha (imported)" {
			renamed = &all[i]
		}
	}
	if renamed == nil {
		t.Errorf("renamed schedule not found; names = %v", names(all))
	}
}

func names(s []scanorch.ScanSchedule) []string {
	out := make([]string, len(s))
	for i := range s {
		out[i] = s[i].Name
	}
	return out
}

// TestImport_IdempotencyKey_Replays (v2.18+): same key +
// same body → replay; no second write.
func TestImport_IdempotencyKey_Replays(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	doImport := func() *httptest.ResponseRecorder {
		body := strings.NewReader(
			`{"name":"alpha","template":{"input":"stdin"},"interval_seconds":60}` + "\n")
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"/api/v1/schedules/import", body)
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("Idempotency-Key", "test-key-replay-1")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}
	rr1 := doImport()
	if rr1.Code != http.StatusOK {
		t.Fatalf("first call status = %d", rr1.Code)
	}
	if rr1.Header().Get("Idempotency-Replay") == "true" {
		t.Errorf("first call should NOT carry Idempotency-Replay")
	}
	rr2 := doImport()
	if rr2.Code != http.StatusOK {
		t.Fatalf("replay status = %d", rr2.Code)
	}
	if rr2.Header().Get("Idempotency-Replay") != "true" {
		t.Errorf("replay missing Idempotency-Replay header")
	}
	if rr1.Body.String() != rr2.Body.String() {
		t.Errorf("replay body differs")
	}
	all, _ := store.List(context.Background())
	if len(all) != 1 {
		t.Errorf("store len = %d, want 1 (idempotency suppresses duplicate writes)", len(all))
	}
}

// TestImport_IdempotencyKey_BodyMismatchConflict (v2.18+):
// same key + different body → 409.
func TestImport_IdempotencyKey_BodyMismatchConflict(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	router := newSchedRouter(store)
	doImport := func(name string) *httptest.ResponseRecorder {
		body := strings.NewReader(
			`{"name":"` + name + `","template":{"input":"stdin"},"interval_seconds":60}` + "\n")
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"/api/v1/schedules/import", body)
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("Idempotency-Key", "test-key-conflict-1")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}
	rr1 := doImport("first")
	if rr1.Code != http.StatusOK {
		t.Fatalf("first status = %d", rr1.Code)
	}
	rr2 := doImport("DIFFERENT")
	if rr2.Code != http.StatusConflict {
		t.Errorf("conflict status = %d, want 409", rr2.Code)
	}
}

// TestImportSchedules_Atomic_HappyPath (v2.12+): atomic=true
// with all-valid rows → all imported.
func TestImportSchedules_Atomic_HappyPath(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	body := strings.NewReader(
		`{"name":"alpha","template":{"input":"stdin"},"interval_seconds":60}` + "\n" +
			`{"name":"beta","template":{"input":"stdin"},"interval_seconds":120}` + "\n",
	)
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/import?atomic=true", body)
	req.Header.Set("Content-Type", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	all, _ := store.List(context.Background())
	if len(all) != 2 {
		t.Errorf("imported = %d, want 2", len(all))
	}
}

// TestImportSchedules_Atomic_AbortsOnInvalidRow (v2.12+):
// atomic=true with any invalid row → 400 + no writes.
func TestImportSchedules_Atomic_AbortsOnInvalidRow(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	// 1st row valid; 2nd row invalid (bad tag); 3rd valid.
	// Non-atomic mode would have imported 2; atomic must
	// import 0.
	body := strings.NewReader(
		`{"name":"alpha","template":{"input":"stdin"},"interval_seconds":60}` + "\n" +
			`{"name":"bad","template":{"input":"stdin"},"interval_seconds":60,"tags":["BAD TAG"]}` + "\n" +
			`{"name":"gamma","template":{"input":"stdin"},"interval_seconds":60}` + "\n",
	)
	router := newSchedRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/import?atomic=true", body)
	req.Header.Set("Content-Type", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rr.Code, rr.Body.String())
	}
	all, _ := store.List(context.Background())
	if len(all) != 0 {
		t.Errorf("atomic abort: %d schedules written, want 0", len(all))
	}
	// Response includes a failures array with the bad row.
	var resp struct {
		Data struct {
			FailureCount int `json:"failure_count"`
			Failures     []struct {
				Index int    `json:"index"`
				Name  string `json:"name"`
			} `json:"failures"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Data.FailureCount != 1 || len(resp.Data.Failures) != 1 {
		t.Errorf("failure_count = %d, want 1", resp.Data.FailureCount)
	}
	if resp.Data.Failures[0].Index != 1 || resp.Data.Failures[0].Name != "bad" {
		t.Errorf("failure[0] = %+v, want index=1 name=bad", resp.Data.Failures[0])
	}
}

// TestImportSchedules_BadConflict (v1.99+): unsupported
// on_conflict → 400.
func TestImportSchedules_BadConflict(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/import?on_conflict=replace", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestExportSchedules_BadFormat (v1.97+): unsupported format
// → 400.
func TestExportSchedules_BadFormat(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/export?format=xml", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestBulkSetEnabled_DisableAll (v1.95+): bulk-disable affects
// only enabled schedules + writes audit per state change.
func TestBulkSetEnabled_DisableAll(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	audit := scanorch.NewMemoryScheduleAuditStore()
	// Two enabled schedules + one already disabled.
	a, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "a",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	b, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "b",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	c, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "c",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	_ = store.SetEnabled(context.Background(), c.ID, false)

	router := newSchedRouterWithAudit(store, audit)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/bulk/disable", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			Affected     int  `json:"affected"`
			FailedAudits int  `json:"failed_audits"`
			TargetState  bool `json:"target_state"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Data.Affected != 2 {
		t.Errorf("affected = %d, want 2 (c was already disabled)", resp.Data.Affected)
	}
	if resp.Data.TargetState != false {
		t.Errorf("target_state = %v, want false", resp.Data.TargetState)
	}
	// All 3 should now be disabled.
	got, _ := store.Get(context.Background(), a.ID)
	if got.Enabled {
		t.Errorf("a.Enabled = true, want false")
	}
	got, _ = store.Get(context.Background(), b.ID)
	if got.Enabled {
		t.Errorf("b.Enabled = true, want false")
	}
	// Audit log: 2 rows expected (the no-op c skip means no
	// audit row for it).
	evA, _ := audit.ListBySchedule(context.Background(), a.ID)
	if len(evA) != 1 {
		t.Errorf("a audit events = %d, want 1", len(evA))
	}
	evC, _ := audit.ListBySchedule(context.Background(), c.ID)
	if len(evC) != 0 {
		t.Errorf("c audit events = %d, want 0 (no-op transition)", len(evC))
	}
}

// TestCloneSchedule_WritesAudit (v2.1+): clone with audit
// store wired writes one `cloned_from` event keyed on the
// clone's ID with payload_before = source snapshot.
func TestCloneSchedule_WritesAudit(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	audit := scanorch.NewMemoryScheduleAuditStore()
	source, err := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "src",
		Template:        scanorch.SubmitRequest{Input: "list:s.txt"},
		IntervalSeconds: 60,
	}, "alice")
	if err != nil {
		t.Fatalf("Create err = %v", err)
	}
	router := newSchedRouterWithAudit(store, audit)
	body := strings.NewReader(`{"name":"clone"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/"+source.ID+"/clone", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Operator", "bob")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data scanorch.ScanSchedule `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	// Audit row exists on the CLONE's ID.
	events, err := audit.ListBySchedule(context.Background(), resp.Data.ID)
	if err != nil {
		t.Fatalf("ListBySchedule err = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.EventType != scanorch.ScheduleAuditEventClonedFrom {
		t.Errorf("event_type = %q, want cloned_from", ev.EventType)
	}
	if ev.Operator != "bob" {
		t.Errorf("operator = %q, want bob", ev.Operator)
	}
	// Source snapshot in payload_before.
	var srcSnap scanorch.ScanSchedule
	if err := json.Unmarshal(ev.PayloadBefore, &srcSnap); err != nil {
		t.Fatalf("decode payload_before: %v", err)
	}
	if srcSnap.ID != source.ID {
		t.Errorf("payload_before.id = %q, want source ID %q", srcSnap.ID, source.ID)
	}
}

// TestCloneSchedule_NoAuditStore_StillSucceeds (v2.1+): nil
// audit store → clone still works, no audit row written.
func TestCloneSchedule_NoAuditStore_StillSucceeds(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	source, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "src",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouter(store) // nil audit
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/"+source.ID+"/clone", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d", rr.Code)
	}
}

// TestCloneSchedule_NotFound (v1.93+): unknown source → 404.
func TestCloneSchedule_NotFound(t *testing.T) {
	router := newSchedRouter(scanorch.NewMemoryScheduleStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/schedules/notreal/clone", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestListScheduleRuns_NoScanStore (v1.92+): nil scan store
// → 503.
func TestListScheduleRuns_NoScanStore(t *testing.T) {
	store := scanorch.NewMemoryScheduleStore()
	sched, _ := store.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	router := newSchedRouterWithScan(store, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/schedules/"+sched.ID+"/runs", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}
