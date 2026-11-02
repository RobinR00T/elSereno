package netutil

import (
	"context"
	"io"
)

// CloseOnDone closes c as soon as ctx is done (cancelled or past its
// deadline) and returns a function that closes c and stops watching.
// Plugins defer the returned function in place of a plain Close: their
// IO deadline is a fixed time from now, so without it a cancelled scan
// (Ctrl-C, a dashboard job cancel) waited for that deadline on every
// probe in flight. Closing interrupts any blocked Read or Write.
func CloseOnDone(ctx context.Context, c io.Closer) func() {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	return func() {
		stop()
		_ = c.Close()
	}
}
