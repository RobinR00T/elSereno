//go:build !mini

package feeds

import (
	"context"
	"io"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// Stdin streams ndjson:v1 records from an io.Reader (typically
// os.Stdin in production; injected for tests). It's the live
// counterpart to Replay: rather than reading a captured file,
// Stdin consumes a producer's output as it arrives.
//
// Pairs with the batch scan verb's stream form:
//
//	elsereno scan --input targets.txt --output-format ndjson | \
//	  elsereno tui --feed -
//
// or with any external tool that emits ndjson:v1 lines (jq
// pipelines, custom orchestrators, replay captures piped
// through filters, etc.).
//
// Closure semantics: when In returns io.EOF, the feed
// terminates cleanly and the TUI receives a FeedClosedMsg with
// nil error. The TUI keeps running so the operator can review
// the accumulated findings; q quits the program.
type Stdin struct {
	// In is the source. Defaults to os.Stdin if nil. Tests set
	// this to a strings.Reader / bytes.Buffer.
	In io.Reader
	// Rate, if >0, slows playback. Useful when the source is a
	// pre-captured file piped through `cat` and the operator
	// wants demo-paced findings. 0 = unbounded.
	Rate float64
}

// Name implements tui.Feed.
func (Stdin) Name() string { return "feed stdin" }

// Run implements tui.Feed.
func (s Stdin) Run(ctx context.Context, emit func(tea.Msg)) error {
	src := s.In
	if src == nil {
		src = os.Stdin
	}
	return streamNDJSON(ctx, src, emit, paceFromRate(s.Rate))
}
