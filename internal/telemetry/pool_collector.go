package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PoolStatProvider (v2.55+) is the minimum surface PoolCollector
// needs to scrape pgxpool runtime stats. Same shape as
// `handlers.PoolStatter` but defined here to keep the
// telemetry package free of cross-package dep on handlers.
// Callers wire a thin shim that returns a *PoolStat read from
// the live pool.
type PoolStatProvider interface {
	Stat() *PoolStat
}

// PoolStat mirrors the relevant fields from pgxpool.Stat,
// re-declared here so this package is dep-free of pgxpool.
// Sync the field set with `internal/web/handlers.PoolStat`
// when extending (single source of truth: the SQL DB driver).
type PoolStat struct {
	AcquireCount            int64
	AcquireDurationNS       int64 // nanoseconds (already converted)
	AcquiredConns           int32
	CanceledAcquireCount    int64
	ConstructingConns       int32
	EmptyAcquireCount       int64
	IdleConns               int32
	MaxConns                int32
	TotalConns              int32
	NewConnsCount           int64
	MaxLifetimeDestroyCount int64
	MaxIdleDestroyCount     int64
}

// PoolCollector implements prometheus.Collector. Lazy: each
// scrape reads the current PoolStatProvider snapshot, so we
// don't burn CPU on a 1s background poll.
//
// Registers 12 gauges (one per field) under the
// `elsereno_pool_*` namespace. Operators graph
// `elsereno_pool_acquired_conns / elsereno_pool_max_conns`
// to spot saturation.
type PoolCollector struct {
	provider PoolStatProvider

	acquireCount            *prometheus.Desc
	acquireDurationSeconds  *prometheus.Desc
	acquiredConns           *prometheus.Desc
	canceledAcquireCount    *prometheus.Desc
	constructingConns       *prometheus.Desc
	emptyAcquireCount       *prometheus.Desc
	idleConns               *prometheus.Desc
	maxConns                *prometheus.Desc
	totalConns              *prometheus.Desc
	newConnsCount           *prometheus.Desc
	maxLifetimeDestroyCount *prometheus.Desc
	maxIdleDestroyCount     *prometheus.Desc
}

// NewPoolCollector constructs the collector. provider is the
// snapshot source; nil → Collect emits zero metrics safely.
func NewPoolCollector(provider PoolStatProvider) *PoolCollector {
	c := &PoolCollector{provider: provider}
	c.buildCounters()
	c.buildGauges()
	return c
}

// poolDesc is a tiny ctor helper to keep buildCounters/Gauges
// readable (no `nil, nil` boilerplate spamming the call sites).
func poolDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, nil, nil)
}

// buildCounters wires the cumulative-counter Descs.
func (c *PoolCollector) buildCounters() {
	c.acquireCount = poolDesc(
		"elsereno_pool_acquire_count_total",
		"Cumulative successful acquires from the pool.")
	c.acquireDurationSeconds = poolDesc(
		"elsereno_pool_acquire_duration_seconds_total",
		"Cumulative time spent waiting for a connection (sum).")
	c.canceledAcquireCount = poolDesc(
		"elsereno_pool_canceled_acquire_count_total",
		"Cumulative acquires cancelled before completion.")
	c.emptyAcquireCount = poolDesc(
		"elsereno_pool_empty_acquire_count_total",
		"Cumulative acquires that waited for the pool to be non-empty.")
	c.newConnsCount = poolDesc(
		"elsereno_pool_new_conns_count_total",
		"Cumulative new connections created.")
	c.maxLifetimeDestroyCount = poolDesc(
		"elsereno_pool_max_lifetime_destroy_count_total",
		"Cumulative connections destroyed due to MaxConnLifetime.")
	c.maxIdleDestroyCount = poolDesc(
		"elsereno_pool_max_idle_destroy_count_total",
		"Cumulative connections destroyed due to MaxConnIdleTime.")
}

// buildGauges wires the instantaneous-gauge Descs.
func (c *PoolCollector) buildGauges() {
	c.acquiredConns = poolDesc(
		"elsereno_pool_acquired_conns",
		"Connections currently in use by callers.")
	c.constructingConns = poolDesc(
		"elsereno_pool_constructing_conns",
		"Connections currently being constructed.")
	c.idleConns = poolDesc(
		"elsereno_pool_idle_conns",
		"Connections idle in the pool.")
	c.maxConns = poolDesc(
		"elsereno_pool_max_conns",
		"Pool's maximum-conn-count configuration.")
	c.totalConns = poolDesc(
		"elsereno_pool_total_conns",
		"Total connections (idle + acquired + constructing).")
}

// Describe implements prometheus.Collector.
func (c *PoolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.acquireCount
	ch <- c.acquireDurationSeconds
	ch <- c.acquiredConns
	ch <- c.canceledAcquireCount
	ch <- c.constructingConns
	ch <- c.emptyAcquireCount
	ch <- c.idleConns
	ch <- c.maxConns
	ch <- c.totalConns
	ch <- c.newConnsCount
	ch <- c.maxLifetimeDestroyCount
	ch <- c.maxIdleDestroyCount
}

// Collect implements prometheus.Collector. Reads the
// current snapshot + emits one metric per field. Nil
// provider / nil stat → emits zero metrics (no error).
func (c *PoolCollector) Collect(ch chan<- prometheus.Metric) {
	if c.provider == nil {
		return
	}
	s := c.provider.Stat()
	if s == nil {
		return
	}
	emit := func(d *prometheus.Desc, t prometheus.ValueType, v float64) {
		ch <- prometheus.MustNewConstMetric(d, t, v)
	}
	emit(c.acquireCount, prometheus.CounterValue, float64(s.AcquireCount))
	emit(c.acquireDurationSeconds, prometheus.CounterValue, float64(s.AcquireDurationNS)/1e9)
	emit(c.acquiredConns, prometheus.GaugeValue, float64(s.AcquiredConns))
	emit(c.canceledAcquireCount, prometheus.CounterValue, float64(s.CanceledAcquireCount))
	emit(c.constructingConns, prometheus.GaugeValue, float64(s.ConstructingConns))
	emit(c.emptyAcquireCount, prometheus.CounterValue, float64(s.EmptyAcquireCount))
	emit(c.idleConns, prometheus.GaugeValue, float64(s.IdleConns))
	emit(c.maxConns, prometheus.GaugeValue, float64(s.MaxConns))
	emit(c.totalConns, prometheus.GaugeValue, float64(s.TotalConns))
	emit(c.newConnsCount, prometheus.CounterValue, float64(s.NewConnsCount))
	emit(c.maxLifetimeDestroyCount, prometheus.CounterValue, float64(s.MaxLifetimeDestroyCount))
	emit(c.maxIdleDestroyCount, prometheus.CounterValue, float64(s.MaxIdleDestroyCount))
}
