package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"local/elsereno/internal/web/handlers"
)

// stubPoolStatter provides synthetic pool stats for tests.
type stubPoolStatter struct {
	stat *handlers.PoolStat
}

func (s *stubPoolStatter) Stat() *handlers.PoolStat {
	return s.stat
}

func TestPoolHealth_HappyPath(t *testing.T) {
	stub := &stubPoolStatter{
		stat: &handlers.PoolStat{
			AcquireCount:    123,
			AcquireDuration: 5 * time.Millisecond,
			AcquiredConns:   3,
			IdleConns:       7,
			MaxConns:        10,
			TotalConns:      10,
		},
	}
	deps := handlers.APIV1Deps{PoolStatter: stub}
	router := handlers.APIV1(deps)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/health/pool", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			Pool handlers.PoolStat `json:"pool"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}
	if resp.Data.Pool.TotalConns != 10 {
		t.Errorf("TotalConns = %d, want 10", resp.Data.Pool.TotalConns)
	}
	if resp.Data.Pool.IdleConns != 7 {
		t.Errorf("IdleConns = %d, want 7", resp.Data.Pool.IdleConns)
	}
	if resp.Data.Pool.AcquireCount != 123 {
		t.Errorf("AcquireCount = %d, want 123", resp.Data.Pool.AcquireCount)
	}
}

func TestPoolHealth_NoPool(t *testing.T) {
	deps := handlers.APIV1Deps{} // PoolStatter nil
	router := handlers.APIV1(deps)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/health/pool", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestPoolHealth_StatNil(t *testing.T) {
	// PoolStatter returns nil from Stat() — still 503.
	stub := &stubPoolStatter{stat: nil}
	deps := handlers.APIV1Deps{PoolStatter: stub}
	router := handlers.APIV1(deps)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/health/pool", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}
