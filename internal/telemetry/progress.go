package telemetry

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ProgressBar is a minimal terminal progress renderer with ETA. It
// honours the standard environment flag for suppressing ANSI
// colouring (see no-color.org) and falls back to plain-text updates
// when the output is not a TTY.
//
// The intended usage is:
//
//	p := telemetry.NewProgress(os.Stderr, total)
//	for ... {
//	    p.Inc(1)
//	}
//	p.Done()
type ProgressBar struct {
	w           io.Writer
	total       int64
	startedAt   time.Time
	lastDrawnAt time.Time

	mu      sync.Mutex
	done    int64
	noColor bool
	isTTY   bool
}

// NewProgress constructs a ProgressBar that renders to w. total is the
// expected maximum (use 0 for indeterminate).
func NewProgress(w io.Writer, total int64) *ProgressBar {
	p := &ProgressBar{
		w:         w,
		total:     total,
		startedAt: time.Now(),
	}
	p.noColor = os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" //nolint:misspell // CSS/env spec spelling

	if f, ok := w.(*os.File); ok {
		fi, err := f.Stat()
		if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			p.isTTY = true
		}
	}
	return p
}

// Inc advances the counter by n and redraws at most once per 100ms.
func (p *ProgressBar) Inc(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done += n
	now := time.Now()
	if now.Sub(p.lastDrawnAt) < 100*time.Millisecond {
		return
	}
	p.lastDrawnAt = now
	p.drawLocked()
}

// Done finalises the bar with a newline so subsequent output does not
// overwrite it.
func (p *ProgressBar) Done() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.drawLocked()
	_, _ = fmt.Fprintln(p.w)
}

func (p *ProgressBar) drawLocked() {
	elapsed := time.Since(p.startedAt)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(p.done) / elapsed.Seconds()
	}

	var eta string
	if p.total > 0 && rate > 0 && p.done < p.total {
		secs := float64(p.total-p.done) / rate
		eta = time.Duration(secs * float64(time.Second)).Round(time.Second).String()
	}

	if !p.isTTY {
		// Plain line-per-update (good for tail -f / logs).
		if p.total > 0 {
			_, _ = fmt.Fprintf(p.w, "progress %d/%d eta=%s\n", p.done, p.total, eta)
		} else {
			_, _ = fmt.Fprintf(p.w, "progress %d items (rate=%.1f/s)\n", p.done, rate)
		}
		return
	}

	// TTY path: overwrite the line with \r.
	const width = 30
	fillChar := "#"
	empty := "."
	bar := ""
	if p.total > 0 {
		filled := int((float64(p.done) / float64(p.total)) * float64(width))
		if filled > width {
			filled = width
		}
		bar = strings.Repeat(fillChar, filled) + strings.Repeat(empty, width-filled)
	}

	pct := 0
	if p.total > 0 {
		pct = int((float64(p.done) / float64(p.total)) * 100)
	}

	line := fmt.Sprintf("\r[%s] %d/%d (%d%%) eta=%s", bar, p.done, p.total, pct, eta)
	if p.total <= 0 {
		line = fmt.Sprintf("\r%d items (rate=%.1f/s)", p.done, rate)
	}

	if !p.noColor {
		line = "\x1b[36m" + line + "\x1b[0m"
	}
	_, _ = fmt.Fprint(p.w, line)
}
