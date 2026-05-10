package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/web/handlers"
)

func newSchedRouter(store scanorch.ScheduleStore) http.Handler {
	return handlers.Schedules(store)
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
