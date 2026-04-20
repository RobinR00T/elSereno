package scanner

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	"local/elsereno/internal/core"
	"local/elsereno/internal/telemetry"
)

// ErrNoTargets is returned by Run when called with an empty slice. It
// is treated as a usage error by the CLI.
var ErrNoTargets = errors.New("scanner: no targets")

// Options controls the scanner's concurrency, rate-limiting, and retry
// behaviour. Zero values fall back to the brief's defaults.
type Options struct {
	// MaxConcurrentTargets caps global in-flight probes. Default 100.
	MaxConcurrentTargets int
	// MaxConcurrentPerHost caps per-address parallelism. Default 1.
	MaxConcurrentPerHost int
	// RatePerSecond is the token-bucket limit applied across all
	// probes. Zero means no rate limit.
	RatePerSecond int
	// MaxRetries bounds retry attempts on transient errors. Zero means
	// retry disabled.
	MaxRetries int
	// BaseBackoff is the initial wait before the first retry. Each
	// subsequent retry doubles the wait. Defaults to 250ms.
	BaseBackoff time.Duration
	// JitterFraction is applied to each retry wait: delay *= (1 + rand
	// in [-jitter, +jitter]). Defaults to 0.25 (±25%).
	JitterFraction float64
}

// Probe is the function the Scanner invokes per target. Plugins will
// typically hand a core.Protocol.Probe bound method.
type Probe func(ctx context.Context, target core.Target) (*core.Finding, error)

// Scanner orchestrates concurrent probes.
type Scanner struct {
	opts Options
}

// New constructs a Scanner with the supplied options. Defaults are
// applied for zero fields.
func New(opts Options) *Scanner {
	if opts.MaxConcurrentTargets <= 0 {
		opts.MaxConcurrentTargets = 100
	}
	if opts.MaxConcurrentPerHost <= 0 {
		opts.MaxConcurrentPerHost = 1
	}
	if opts.BaseBackoff <= 0 {
		opts.BaseBackoff = 250 * time.Millisecond
	}
	if opts.JitterFraction <= 0 {
		opts.JitterFraction = 0.25
	}
	return &Scanner{opts: opts}
}

// Run probes each target (deduped first) and sends findings and errors
// on the returned channels. Both channels are closed when every probe
// has completed. Callers iterate until both channels are closed OR
// until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context, targets []core.Target, probe Probe) (<-chan core.Finding, <-chan error) {
	findings := make(chan core.Finding, 64)
	errs := make(chan error, 64)

	if len(targets) == 0 {
		close(findings)
		go func() { errs <- ErrNoTargets; close(errs) }()
		return findings, errs
	}
	if probe == nil {
		close(findings)
		go func() { errs <- fmt.Errorf("scanner: nil probe"); close(errs) }()
		return findings, errs
	}

	go s.runAll(ctx, Dedupe(targets), probe, findings, errs)
	return findings, errs
}

func (s *Scanner) runAll(ctx context.Context, targets []core.Target, probe Probe, findings chan<- core.Finding, errs chan<- error) {
	defer close(findings)
	defer close(errs)

	global := semaphore.NewWeighted(int64(s.opts.MaxConcurrentTargets))
	perHost := newHostSemaphore(s.opts.MaxConcurrentPerHost)

	var limiter *rate.Limiter
	if s.opts.RatePerSecond > 0 {
		limiter = rate.NewLimiter(rate.Limit(s.opts.RatePerSecond), s.opts.RatePerSecond)
	}

	g, gctx := errgroup.WithContext(ctx)

	for _, t := range targets {
		t := t
		g.Go(func() error {
			if err := global.Acquire(gctx, 1); err != nil {
				return err
			}
			defer global.Release(1)

			if err := perHost.Acquire(gctx, t.Address.String()); err != nil {
				return err
			}
			defer perHost.Release(t.Address.String())

			if limiter != nil {
				if err := limiter.Wait(gctx); err != nil {
					return err
				}
			}

			f, err := s.withRetries(gctx, probe, t)
			if err != nil {
				select {
				case errs <- err:
				case <-gctx.Done():
					return gctx.Err()
				}
				return nil
			}
			if f == nil {
				return nil
			}
			select {
			case findings <- *f:
			case <-gctx.Done():
				return gctx.Err()
			}
			return nil
		})
	}
	_ = g.Wait()
}

// withRetries invokes probe up to MaxRetries+1 times with exponential
// backoff + jitter, unless the context is cancelled. Each attempt is
// wrapped in an OpenTelemetry span so operators running with
// OTEL_TRACES_EXPORTER=otlp (or stdout) see per-target latency +
// retry history without any code change.
func (s *Scanner) withRetries(ctx context.Context, probe Probe, t core.Target) (*core.Finding, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "scanner.probe")
	defer span.End()
	span.SetAttributes(
		attribute.String("target.address", t.Address.String()),
		attribute.Int("target.port", int(t.Port)),
	)

	var lastErr error
	delay := s.opts.BaseBackoff

	for attempt := 0; attempt <= s.opts.MaxRetries; attempt++ {
		f, err := probe(ctx, t)
		if err == nil {
			span.SetAttributes(attribute.Int("scanner.attempts", attempt+1))
			return f, nil
		}
		lastErr = err

		if attempt == s.opts.MaxRetries {
			break
		}
		if !isRetryable(err) {
			break
		}
		wait := jittered(delay, s.opts.JitterFraction)
		select {
		case <-ctx.Done():
			span.SetStatus(codes.Error, "context cancelled")
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		delay *= 2
	}
	span.SetStatus(codes.Error, lastErr.Error())
	return nil, fmt.Errorf("scanner: target %s:%d: %w", t.Address, t.Port, lastErr)
}

// isRetryable treats ErrTimeout and context.DeadlineExceeded as
// retryable; everything else aborts the chain.
func isRetryable(err error) bool {
	return errors.Is(err, core.ErrTimeout) || errors.Is(err, context.DeadlineExceeded)
}

// jittered returns d scaled by a random factor in [1-fraction, 1+fraction].
func jittered(d time.Duration, fraction float64) time.Duration {
	if fraction <= 0 {
		return d
	}
	// math/rand/v2 seeds itself; good enough for jitter (not cryptographic).
	scale := 1.0 + (rand.Float64()*2-1)*fraction // #nosec G404 -- jitter, not security
	if scale < 0 {
		scale = 0
	}
	return time.Duration(float64(d) * scale)
}
