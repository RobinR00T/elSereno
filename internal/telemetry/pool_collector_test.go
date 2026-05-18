package telemetry_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"local/elsereno/internal/telemetry"
)

type stubProvider struct {
	stat *telemetry.PoolStat
}

func (s *stubProvider) Stat() *telemetry.PoolStat { return s.stat }

// TestPoolCollector_HappyPath: registry surfaces 12 metrics
// with the stubbed values.
func TestPoolCollector_HappyPath(t *testing.T) {
	provider := &stubProvider{
		stat: &telemetry.PoolStat{
			AcquireCount:      1234,
			AcquireDurationNS: 5_000_000_000, // 5s
			AcquiredConns:     3,
			IdleConns:         7,
			MaxConns:          10,
			TotalConns:        10,
			NewConnsCount:     42,
		},
	}
	c := telemetry.NewPoolCollector(provider)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(mfs) != 12 {
		t.Errorf("MetricFamily count = %d, want 12", len(mfs))
	}
	// Collect a name → value map for assertions.
	got := make(map[string]float64, 12)
	for _, mf := range mfs {
		if len(mf.GetMetric()) == 0 {
			continue
		}
		name := mf.GetName()
		m := mf.GetMetric()[0]
		switch {
		case m.GetCounter() != nil:
			got[name] = m.GetCounter().GetValue()
		case m.GetGauge() != nil:
			got[name] = m.GetGauge().GetValue()
		}
	}
	want := map[string]float64{
		"elsereno_pool_acquire_count_total":            1234,
		"elsereno_pool_acquire_duration_seconds_total": 5,
		"elsereno_pool_acquired_conns":                 3,
		"elsereno_pool_idle_conns":                     7,
		"elsereno_pool_max_conns":                      10,
		"elsereno_pool_total_conns":                    10,
		"elsereno_pool_new_conns_count_total":          42,
	}
	for name, wantVal := range want {
		gotVal, ok := got[name]
		if !ok {
			t.Errorf("metric %q not collected", name)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("metric %q = %f, want %f", name, gotVal, wantVal)
		}
	}
}

// TestPoolCollector_NilProvider: no panic + zero metrics.
func TestPoolCollector_NilProvider(t *testing.T) {
	c := telemetry.NewPoolCollector(nil)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if len(mf.GetMetric()) > 0 {
			t.Errorf("expected no samples for nil provider; got %s",
				mf.GetName())
		}
	}
}

// TestPoolCollector_NilStat: provider present but Stat()
// returns nil → no samples.
func TestPoolCollector_NilStat(t *testing.T) {
	c := telemetry.NewPoolCollector(&stubProvider{stat: nil})
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if len(mf.GetMetric()) > 0 {
			t.Errorf("expected no samples for nil stat; got %s",
				mf.GetName())
		}
	}
}
