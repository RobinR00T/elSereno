package telemetry

import (
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog.Logger and applies redaction to string fields.
// Use Logger.Str instead of the raw event for any target-controlled or
// secret-adjacent value.
type Logger struct {
	base zerolog.Logger
}

// LoggerOptions controls output, level, and caller info.
type LoggerOptions struct {
	Level  string // "debug", "info", "warn", "error"; defaults to "info"
	Output io.Writer
}

// NewLogger configures zerolog to ElSereno's defaults:
//   - RFC 3339 microsecond timestamps (ADR-020).
//   - stderr by default (conventions.md).
//   - JSON output (no console formatter in production).
func NewLogger(opts LoggerOptions) Logger {
	level := parseLevel(opts.Level)
	out := opts.Output
	if out == nil {
		out = os.Stderr
	}
	zerolog.TimeFieldFormat = "2006-01-02T15:04:05.000000Z07:00"
	zerolog.TimestampFunc = func() time.Time { return time.Now().UTC() }
	zerolog.LevelFieldName = "level"
	return Logger{
		base: zerolog.New(out).
			Level(level).
			With().
			Timestamp().
			Logger(),
	}
}

func parseLevel(s string) zerolog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return zerolog.DebugLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// Event wraps zerolog.Event and redacts string fields on the way in.
type Event struct {
	ev *zerolog.Event
}

// Info starts an info-level event.
func (l Logger) Info() *Event { return &Event{ev: l.base.Info()} }

// Warn starts a warn-level event.
func (l Logger) Warn() *Event { return &Event{ev: l.base.Warn()} }

// Error starts an error-level event.
func (l Logger) Error() *Event { return &Event{ev: l.base.Error()} }

// Debug starts a debug-level event.
func (l Logger) Debug() *Event { return &Event{ev: l.base.Debug()} }

// Str adds a string field, applying Redact before emission.
func (e *Event) Str(key, value string) *Event {
	e.ev.Str(key, Redact(key, value))
	return e
}

// SafeStr is like Str but also sanitises target-controlled control
// characters via SafeField before redaction.
func (e *Event) SafeStr(key, value string) *Event {
	return e.Str(key, SafeField(key, value))
}

// Int adds an int field. Ints are never redacted.
func (e *Event) Int(key string, value int) *Event {
	e.ev.Int(key, value)
	return e
}

// Err adds the standard "error" field.
func (e *Event) Err(err error) *Event {
	e.ev.Err(err)
	return e
}

// Msg finalises the event.
func (e *Event) Msg(s string) { e.ev.Msg(s) }

// Msgf finalises the event with a formatted message. Values
// interpolated into the format string are NOT automatically redacted;
// prefer Str(key, value) + Msg for any target-controlled value.
func (e *Event) Msgf(format string, args ...any) { e.ev.Msgf(format, args...) }
