// Package telemetry wires structured logging, metrics, and tracing.
//
//   - Logs: zerolog to stderr, RFC 3339 microsecond timestamps
//     (ADR-020), level default "info".
//   - Redaction: zerolog.Hook with specific patterns + entropy
//     heuristic that excludes UUID v1-v5 (PITF-004).
//   - Metrics: Prometheus /metrics with low-cardinality labels
//     (protocol, severity, asn, country; never ip). Labels go through a
//     sanitiser that validates asn numeric and country ISO 3166-1
//     alpha-2.
//   - Tracing: OTel opt-in via OTEL_EXPORTER_OTLP_ENDPOINT.
//   - SafeField(name, value) escapes newlines, carriage returns, and
//     control characters for target-controlled strings.
package telemetry
