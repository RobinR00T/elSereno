package telemetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// ErrUnknownExporter is returned when OTEL_TRACES_EXPORTER is set to
// an unsupported value.
var ErrUnknownExporter = errors.New("telemetry: OTEL_TRACES_EXPORTER must be one of: none, otlp, stdout")

// TracerName is the instrumentation name returned by Tracer().
const TracerName = "local/elsereno"

// Tracer returns the globally registered OpenTelemetry tracer. When
// InitTracer has not been called (or the exporter is "none"), the
// returned tracer is a no-op — callers can emit spans
// unconditionally without paying any runtime cost.
func Tracer() trace.Tracer {
	return otel.Tracer(TracerName)
}

// InitTracer wires a trace exporter per `OTEL_TRACES_EXPORTER`:
//
//   - unset / "none" — no-op (global no-op tracer stays in place).
//   - "otlp"        — gRPC OTLP to `OTEL_EXPORTER_OTLP_ENDPOINT`
//     (default localhost:4317).
//   - "stdout"      — stdouttrace exporter; useful for operator
//     debugging.
//
// Returned shutdown function MUST be called before process exit so
// buffered spans flush cleanly.
func InitTracer(ctx context.Context, serviceName, version string) (func(context.Context) error, error) {
	exporter := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER")))
	if exporter == "" || exporter == "none" {
		return func(context.Context) error { return nil }, nil
	}

	res, err := buildResource(ctx, serviceName, version)
	if err != nil {
		return nil, err
	}

	var exp sdktrace.SpanExporter
	switch exporter {
	case "otlp":
		e, err := otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(otlpEndpoint()),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("telemetry: otlp: %w", err)
		}
		exp = e
	case "stdout":
		e, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("telemetry: stdout: %w", err)
		}
		exp = e
	default:
		return nil, fmt.Errorf("%w: got %q", ErrUnknownExporter, exporter)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(1.0))),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return tp.Shutdown, nil
}

func buildResource(ctx context.Context, serviceName, version string) (*resource.Resource, error) {
	host, _ := os.Hostname()
	return resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
			semconv.HostName(host),
		),
		resource.WithFromEnv(),
		resource.WithProcess(),
	)
}

func otlpEndpoint() string {
	if v := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); v != "" {
		return strings.TrimPrefix(strings.TrimPrefix(v, "http://"), "https://")
	}
	if v := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); v != "" {
		return strings.TrimPrefix(strings.TrimPrefix(v, "http://"), "https://")
	}
	return "127.0.0.1:4317"
}
