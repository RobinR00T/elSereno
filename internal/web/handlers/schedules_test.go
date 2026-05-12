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
	var resp struct {
		Data []scanorch.Job `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode err = %v", err)
	}
	if len(resp.Data) != 3 {
		t.Errorf("runs = %d, want 3", len(resp.Data))
	}
	for _, j := range resp.Data {
		if j.TriggeredByScheduleID != sched.ID {
			t.Errorf("job %s TriggeredByScheduleID = %q, want %q",
				j.ID, j.TriggeredByScheduleID, sched.ID)
		}
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
