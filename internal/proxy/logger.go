package proxy

import (
	"context"
	"fmt"
	"io"

	"local/elsereno/internal/render"
)

// LoggingHook emits a one-line summary of every byte chunk to w using
// render.SafeBytes for rendering. It never mutates the bytes it sees.
type LoggingHook struct {
	W io.Writer
}

// PreHook implements Hook.
func (LoggingHook) PreHook(_ context.Context, _ Direction, _ []byte) ([]byte, error) {
	return nil, nil
}

// PostHook implements Hook.
func (h LoggingHook) PostHook(_ context.Context, dir Direction, b []byte) {
	if h.W == nil {
		return
	}
	label := "C>U"
	if dir == UpstreamToClient {
		label = "U>C"
	}
	_, _ = fmt.Fprintf(h.W, "[%s] %d bytes: %s\n", label, len(b), render.SafeBytes(b))
}

// Ensure interface satisfaction at compile time.
var _ Hook = LoggingHook{}
