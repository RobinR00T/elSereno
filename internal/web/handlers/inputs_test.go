package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/elsereno/internal/web/handlers"
)

// writeTempFile writes a file under a t.TempDir and returns
// the path. Local helper to keep tests self-contained.
func writeTempFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestPreviewInput_HappyPath_ListFile(t *testing.T) {
	path := writeTempFile(t, "10.0.0.1:502\n10.0.0.2:102\n")
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/inputs/preview?kind=list:"+path, nil)
	w := httptest.NewRecorder()
	handlers.PreviewInput().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var env struct {
		Schema string `json:"schema"`
		Data   struct {
			Count     int  `json:"count"`
			Truncated bool `json:"truncated"`
			Targets   []struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
				Family  string `json:"family"`
			} `json:"targets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v\nbody=%s", err, w.Body.String())
	}
	if env.Schema != "api:v1" {
		t.Errorf("schema = %q, want api:v1", env.Schema)
	}
	if env.Data.Count != 2 {
		t.Errorf("count = %d, want 2", env.Data.Count)
	}
	if env.Data.Truncated {
		t.Errorf("truncated = true, want false (only 2 targets)")
	}
	if len(env.Data.Targets) != 2 {
		t.Errorf("targets sample = %d, want 2", len(env.Data.Targets))
	}
}

func TestPreviewInput_MissingKind(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/inputs/preview", nil)
	w := httptest.NewRecorder()
	handlers.PreviewInput().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "missing required") {
		t.Errorf("body = %q, want 'missing required'", w.Body.String())
	}
}

func TestPreviewInput_BadDefaultPort(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/inputs/preview?kind=stdin&default_port=70000", nil)
	w := httptest.NewRecorder()
	handlers.PreviewInput().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "default_port") {
		t.Errorf("body missing 'default_port': %q", w.Body.String())
	}
}

func TestPreviewInput_UnsupportedKind(t *testing.T) {
	for _, kind := range []string{"shodan:cisco", "fofa:apache", "internetdb:1.2.3.4", "bogus"} {
		t.Run(kind, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				"/api/v1/inputs/preview?kind="+kind, nil)
			w := httptest.NewRecorder()
			handlers.PreviewInput().ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, "unsupported") {
				t.Errorf("body = %q, want 'unsupported'", body)
			}
		})
	}
}

func TestPreviewInput_MissingFile_Returns404(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/inputs/preview?kind=list:"+filepath.Join(t.TempDir(), "nope.txt"), nil)
	w := httptest.NewRecorder()
	handlers.PreviewInput().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestPreviewInput_TruncatedSampleAt200(t *testing.T) {
	// Generate 250 targets so the sample cap triggers.
	var b strings.Builder
	for i := 0; i < 250; i++ {
		b.WriteString("10.0.")
		b.WriteString(itoa(i / 256))
		b.WriteString(".")
		b.WriteString(itoa(i % 256))
		b.WriteString(":502\n")
	}
	path := writeTempFile(t, b.String())
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/inputs/preview?kind=list:"+path, nil)
	w := httptest.NewRecorder()
	handlers.PreviewInput().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var env struct {
		Data struct {
			Count     int                        `json:"count"`
			Truncated bool                       `json:"truncated"`
			Targets   []struct{ Address string } `json:"targets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Data.Count != 250 {
		t.Errorf("count = %d, want 250", env.Data.Count)
	}
	if !env.Data.Truncated {
		t.Errorf("truncated = false, want true (250 > 200 cap)")
	}
	if len(env.Data.Targets) != 200 {
		t.Errorf("sample = %d, want 200 cap", len(env.Data.Targets))
	}
}

// itoa keeps the test self-contained without strconv import.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
