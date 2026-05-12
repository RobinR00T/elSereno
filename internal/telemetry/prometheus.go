package telemetry

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// LabelUnknown is the sanitised value used for labels that fail
// validation. Emitting a fixed value avoids unbounded cardinality.
const LabelUnknown = "unknown"

// iso3166re is the ISO 3166-1 alpha-2 validation regex. The brief
// caps country labels to this shape to stop log-injected garbage from
// exploding label cardinality.
var iso3166re = regexp.MustCompile(`^[A-Z]{2}$`)

// Metrics is the set of Prometheus instruments exposed by ElSereno.
// Instantiate once per process via NewMetrics and hand the pointer to
// consumers; never register twice in the same registry.
type Metrics struct {
	registry *prometheus.Registry

	FindingsTotal       *prometheus.CounterVec
	ScanDurationSeconds *prometheus.HistogramVec
	PersistenceLagSec   prometheus.Gauge
	AuditEntriesTotal   prometheus.Counter
	OutboxInflight      prometheus.Gauge
	// AuditPrunerRunsTotal (v1.91+) counts pruner-tick
	// outcomes labelled by `result` ∈
	// {"acquired", "skipped_lock", "error"}. Operators
	// graphing this can tell if the v1.90 advisory lock is
	// keeping replicas in line.
	AuditPrunerRunsTotal *prometheus.CounterVec
	// AuditPrunerEventsDeletedTotal (v1.91+) counts the
	// cumulative number of audit events deleted by the
	// background pruner. Sum across replicas equals the real
	// throughput; the advisory lock ensures no double-count.
	AuditPrunerEventsDeletedTotal prometheus.Counter
}

// NewMetrics constructs and registers the metric set. A nil registry
// falls back to a private one; production callers should pass a shared
// registry.
func NewMetrics(reg *prometheus.Registry) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &Metrics{registry: reg}
	m.buildCoreInstruments()
	m.buildAuditPrunerInstruments()
	reg.MustRegister(
		m.FindingsTotal,
		m.ScanDurationSeconds,
		m.PersistenceLagSec,
		m.AuditEntriesTotal,
		m.OutboxInflight,
		m.AuditPrunerRunsTotal,
		m.AuditPrunerEventsDeletedTotal,
	)
	return m
}

// buildCoreInstruments fills in the pre-v1.91 metric set
// (findings, scans, persistence, audit, outbox).
func (m *Metrics) buildCoreInstruments() {
	m.FindingsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "elsereno",
			Subsystem: "findings",
			Name:      "total",
			Help:      "Total findings produced, labelled by low-cardinality fields.",
		},
		[]string{"protocol", "severity", "asn", "country"},
	)
	m.ScanDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "elsereno",
			Subsystem: "scan",
			Name:      "duration_seconds",
			Help:      "Wall-clock duration of a single target probe.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"protocol"},
	)
	m.PersistenceLagSec = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "elsereno",
		Subsystem: "persistence",
		Name:      "lag_seconds",
		Help:      "Oldest unflushed finding age in seconds.",
	})
	m.AuditEntriesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "elsereno",
		Subsystem: "audit",
		Name:      "entries_total",
		Help:      "Audit entries written (any event type).",
	})
	m.OutboxInflight = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "elsereno",
		Subsystem: "outbox",
		Name:      "inflight",
		Help:      "Outbox rows waiting for delivery.",
	})
}

// buildAuditPrunerInstruments (v1.91+) fills in the audit-
// pruner counters: outcomes labelled by result + cumulative
// events deleted.
func (m *Metrics) buildAuditPrunerInstruments() {
	m.AuditPrunerRunsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "elsereno",
			Subsystem: "audit_pruner",
			Name:      "runs_total",
			Help:      "Audit-pruner tick outcomes (acquired / skipped_lock / error).",
		},
		[]string{"result"},
	)
	m.AuditPrunerEventsDeletedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "elsereno",
		Subsystem: "audit_pruner",
		Name:      "events_deleted_total",
		Help:      "Cumulative audit events deleted by the background pruner.",
	})
}

// Handler returns an http.Handler that exposes `reg` via the default
// Prometheus format. Callers mount it on /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry exposes the underlying prometheus.Registry for tests and
// for callers that need to add custom collectors.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// SanitiseLabels canonicalises the (protocol, severity, asn, country)
// tuple per the brief's rules. Protocol and severity are lowercased
// and checked against a known set; asn is numeric-only; country is
// ISO 3166-1 alpha-2. Anything else collapses to "unknown".
//
// The function is intentionally pure — callers pass already-derived
// values and receive back the sanitised ones.
func SanitiseLabels(protocol, severity, asn, country string) (string, string, string, string) {
	return sanitiseProtocol(protocol),
		sanitiseSeverity(severity),
		sanitiseASN(asn),
		sanitiseCountry(country)
}

// sanitiseProtocol keeps the set small so that a new plugin must
// explicitly land here. Unknown values become "unknown".
func sanitiseProtocol(p string) string {
	switch p {
	case "modbus", "s7", "enip", "bacnet", "dnp3", "iec104",
		"hartip", "fox", "atg", "xot", "atmodem", "banner":
		return p
	}
	return LabelUnknown
}

func sanitiseSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	}
	return LabelUnknown
}

func sanitiseASN(s string) string {
	if s == "" {
		return LabelUnknown
	}
	if _, err := strconv.ParseUint(s, 10, 32); err != nil {
		return LabelUnknown
	}
	return s
}

func sanitiseCountry(s string) string {
	if !iso3166re.MatchString(s) {
		return LabelUnknown
	}
	return s
}

// ErrMetricsLocked is returned by the accessor if the registry has not
// been initialised yet.
var ErrMetricsLocked = errors.New("telemetry: metrics not initialised")

var (
	metricsOnce    sync.Once
	globalMetrics  *Metrics
	globalRegistry = prometheus.NewRegistry()
)

// Global returns the process-wide Metrics handle, constructing it on
// first call. Tests that need isolation should call NewMetrics
// directly with their own registry.
func Global() *Metrics {
	metricsOnce.Do(func() {
		globalMetrics = NewMetrics(globalRegistry)
	})
	return globalMetrics
}
