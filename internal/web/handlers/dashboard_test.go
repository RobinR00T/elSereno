package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/web/handlers"
)

// TestDashboard_ContainsScanPanel pins the v1.62 scan-jobs
// panel into the rendered HTML. Catches an accidental template
// regression that strips the new section.
func TestDashboard_ContainsScanPanel(t *testing.T) {
	h := handlers.Dashboard()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, marker := range []string{
		`id="scans-panel"`,
		`id="scan-submit-form"`,
		`id="scan-input"`,
		`id="scan-plugin"`,
		`id="scans-table"`,
		`id="scans-body"`,
		`/api/v1/scans`,
		`function renderScans`,
		`function submitScan`,
		`function cancelScan`,
		// v1.68: plugin autocomplete via <datalist>.
		`id="scan-plugin-options"`,
		`list="scan-plugin-options"`,
		`function loadPluginDatalist`,
		`/api/v1/plugins`,
		// v1.69: bulk submit panel + handler.
		`id="scan-bulk-panel"`,
		`id="scan-bulk-inputs"`,
		`id="scan-bulk-toggle"`,
		`function bulkSubmitScan`,
		`function toggleBulkPanel`,
		`/api/v1/scans/bulk`,
		// v1.72: scheduled-scans panel + helpers.
		`id="schedules-panel"`,
		`id="schedule-submit-form"`,
		`id="schedule-name"`,
		`id="schedule-interval"`,
		`id="schedules-table"`,
		`id="schedules-body"`,
		`function renderSchedules`,
		`function submitSchedule`,
		`function toggleSchedule`,
		`function deleteSchedule`,
		`/api/v1/schedules`,
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("dashboard HTML missing marker %q", marker)
		}
	}
}

// TestDashboard_HasCSPNonce_OnScanScript: the dashboard renders
// inline scripts with a per-request CSP nonce. The new
// submitScan/cancelScan/renderScans live inside the same
// <script nonce="..."> block as the rest of the JS, so they
// inherit the nonce. We just verify the script tag is still
// nonce-bearing after the v1.62 expansion.
func TestDashboard_HasCSPNonce_OnScanScript(t *testing.T) {
	h := handlers.Dashboard()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	// At least one <script nonce="..."> should be present and
	// must contain the new functions.
	scriptIdx := strings.Index(body, `<script nonce="`)
	if scriptIdx < 0 {
		t.Fatal("dashboard missing nonce-bearing <script> tag")
	}
	tail := body[scriptIdx:]
	if !strings.Contains(tail, "function renderScans") {
		t.Error("renderScans not inside the nonce-bearing script block")
	}
}
