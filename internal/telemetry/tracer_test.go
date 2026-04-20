package telemetry_test

import (
	"context"
	"errors"
	"testing"

	"local/elsereno/internal/telemetry"
)

func TestInitTracer_DefaultNoop(t *testing.T) {
	// Unset OTEL_TRACES_EXPORTER → no-op path; shutdown must be a
	// no-op closure we can invoke twice without harm.
	t.Setenv("OTEL_TRACES_EXPORTER", "")
	shutdown, err := telemetry.InitTracer(context.Background(), "elsereno-test", "v0")
	if err != nil {
		t.Fatal(err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
}

func TestInitTracer_Stdout(t *testing.T) {
	t.Setenv("OTEL_TRACES_EXPORTER", "stdout")
	shutdown, err := telemetry.InitTracer(context.Background(), "elsereno-test", "v0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })
	// Emit a span just to exercise the path; stdouttrace is silent
	// under `go test` unless -v.
	_, span := telemetry.Tracer().Start(context.Background(), "self-test")
	span.End()
}

func TestInitTracer_RejectsUnknownExporter(t *testing.T) {
	t.Setenv("OTEL_TRACES_EXPORTER", "blackhole")
	_, err := telemetry.InitTracer(context.Background(), "elsereno-test", "v0")
	if !errors.Is(err, telemetry.ErrUnknownExporter) {
		t.Fatalf("want ErrUnknownExporter, got %v", err)
	}
}

func TestTracer_NoopWhenNotInitialised(t *testing.T) {
	// Even with no Init, Tracer() must never panic and spans must
	// be cheap.
	t.Setenv("OTEL_TRACES_EXPORTER", "")
	tr := telemetry.Tracer()
	_, span := tr.Start(context.Background(), "noop")
	// Default no-op tracer returns an invalid SpanContext; exercising
	// End() without asserting on the span is the contract.
	span.End()
}
