// Package preview is the dependency-light input dispatcher
// used by the web handler's /api/v1/inputs/preview endpoint
// and by the cmd-side parseInput dispatcher (v1.36+). It
// handles the 3 "no-credentials, no-network" input kinds —
// list:FILE, nmap:FILE, stdin — and returns the parsed
// []core.Target.
//
// Provider kinds (shodan:, censys:, fofa:, zoomeye:,
// onyphe:, internetdb:) are NOT in scope here because they
// pull in credentials + HTTP clients + rate-limit tuning
// that would make this package non-trivial to reuse from
// the dashboard process. The dashboard hands the operator
// a "preview" of static inputs only; full provider-backed
// scans stay on the CLI verb.
package preview

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"local/elsereno/internal/core"
	"local/elsereno/internal/inputs/list"
	"local/elsereno/internal/inputs/nmapxml"
	"local/elsereno/internal/inputs/stdin"
)

// Opts are the parameters Parse needs.
type Opts struct {
	// Kind is the operator-supplied input kind. One of:
	//   stdin
	//   list:<path>
	//   nmap:<path>
	Kind string

	// DefaultPort is the port assigned to entries that omit
	// one (host-only lines in list / stdin). Zero means "no
	// default" (parse error if any host omits its port).
	DefaultPort core.Port

	// Stdin is the io.Reader used when Kind == "stdin".
	// Defaults to os.Stdin when nil; tests inject a
	// strings.Reader / bytes.Buffer.
	Stdin io.Reader
}

// ErrUnsupportedKind is returned when Kind names a provider
// (shodan: / censys: / etc.) or is malformed. Callers can
// surface a friendly "preview only supports list/nmap/stdin"
// error.
type ErrUnsupportedKind struct {
	Kind string
}

func (e ErrUnsupportedKind) Error() string {
	return fmt.Sprintf("preview: unsupported input kind %q (preview supports list:<path> | nmap:<path> | stdin only; provider kinds — shodan/censys/fofa/zoomeye/onyphe/internetdb — must run via the CLI scan verb)", e.Kind)
}

// Parse dispatches on Kind and returns the parsed targets.
// Returns ErrUnsupportedKind for provider / unknown kinds.
func Parse(ctx context.Context, opts Opts) ([]core.Target, error) {
	switch {
	case opts.Kind == "stdin":
		src := opts.Stdin
		if src == nil {
			src = os.Stdin
		}
		return stdin.Parse(ctx, src, list.ParseOptions{DefaultPort: opts.DefaultPort})
	case strings.HasPrefix(opts.Kind, "list:"):
		path := strings.TrimPrefix(opts.Kind, "list:")
		f, err := os.Open(path) // #nosec G304 -- caller-supplied input list path
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return list.Parse(ctx, f, list.ParseOptions{DefaultPort: opts.DefaultPort})
	case strings.HasPrefix(opts.Kind, "nmap:"):
		path := strings.TrimPrefix(opts.Kind, "nmap:")
		f, err := os.Open(path) // #nosec G304 -- caller-supplied XML path
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return nmapxml.Parse(ctx, f)
	}
	return nil, ErrUnsupportedKind{Kind: opts.Kind}
}
