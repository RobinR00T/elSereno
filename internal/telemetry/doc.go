// Package telemetry wires structured logging, metrics, and tracing.
//
//   - Logs: zerolog to stderr, RFC 3339 microsecond timestamps
//     (ADR-020), level default "info".
//   - Redaction: the Logger redacts string fields (Str), and
//     RedactWriter redacts every standard-logger line at the sink
//     (keyed secrets, Bearer tokens, bare high-entropy tokens; UUID
//     v1-v5 exempt). entrypoint installs it on the std logger, so a
//     log.Printf anywhere is redacted (PITF-004, PITF-099).
//   - Metrics: Prometheus /metrics with low-cardinality labels
//     (protocol, severity, asn, country; never ip). Labels go through a
//     sanitiser that validates asn numeric and country ISO 3166-1
//     alpha-2.
//   - Tracing: OTel opt-in via OTEL_EXPORTER_OTLP_ENDPOINT.
//   - SafeField(name, value) escapes newlines, carriage returns, and
//     control characters for target-controlled strings.
package telemetry
