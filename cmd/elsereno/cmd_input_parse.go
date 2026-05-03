package main

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

// inputParseOpts is the input-parsing surface shared between
// the batch `scan` verb and the interactive `tui` verb. Both
// accept the same `--input` kinds + `--default-port` +
// `--api-creds-file` shape; `parseInput` is the single
// dispatcher.
//
// The struct lives in the cmd package (not internal/inputs)
// because the batch + TUI orchestration is the only consumer;
// individual parsers (list / nmapxml / stdin / providers) keep
// their narrow APIs.
type inputParseOpts struct {
	// InputKind is the operator-supplied --input value. One of:
	//   stdin                read from Stdin reader
	//   list:<path>          host:port lines from disk
	//   nmap:<path>          nmap XML
	//   shodan:<query>       shodan API search
	//   censys:<query>       censys API search
	//   fofa:<query>         fofa API search
	//   zoomeye:<query>      zoomeye API search
	//   onyphe:<query>       onyphe API search
	//   internetdb:<ip>      shodan internetdb (no key)
	InputKind string

	// DefaultPort is the port assigned to entries that omit one
	// (host-only lines in `list:` / `stdin`). 0 = no default
	// (parse error if any host omits its port).
	DefaultPort int

	// APICredsFile is a YAML 0600 file with provider credentials.
	// Required for shodan / censys / fofa / zoomeye / onyphe.
	// Ignored for stdin / list / nmap / internetdb.
	APICredsFile string

	// Stdin is the io.Reader used when InputKind == "stdin".
	// Defaults to os.Stdin when nil; tests inject a *bytes.Buffer
	// or strings.Reader.
	Stdin io.Reader
}

// parseInput dispatches on InputKind. Returns the parsed
// targets or an error describing why the input couldn't be
// resolved (file not found, unknown kind, malformed query).
//
// Used by:
//
//	cmd_scan.go        (batch scan; via readTargets shim)
//	cmd_tui.go         (interactive scan launcher; v1.31+)
func parseInput(ctx context.Context, opts inputParseOpts) ([]core.Target, error) {
	if opts.InputKind == "stdin" {
		return parseStdinInput(ctx, opts)
	}
	if strings.HasPrefix(opts.InputKind, "list:") {
		return parseListInput(ctx, opts)
	}
	if strings.HasPrefix(opts.InputKind, "nmap:") {
		return parseNmapInput(ctx, opts.InputKind)
	}
	for _, p := range providerPrefixes {
		if strings.HasPrefix(opts.InputKind, p+":") {
			return readTargetsFromProvider(ctx, p,
				strings.TrimPrefix(opts.InputKind, p+":"), opts.APICredsFile)
		}
	}
	return nil, fmt.Errorf(
		"unknown input kind %q; use list:<path> | nmap:<path> | stdin | shodan:<q> | censys:<q> | fofa:<q> | zoomeye:<q> | onyphe:<q> | internetdb:<ip>",
		opts.InputKind)
}

// providerPrefixes are the API-keyed (or no-key, for
// internetdb) input kinds that go through readTargetsFromProvider.
// Order matches the help-text listing for consistency in error
// messages + docs.
var providerPrefixes = []string{
	"shodan", "censys", "fofa", "zoomeye", "onyphe", "internetdb",
}

func parseStdinInput(ctx context.Context, opts inputParseOpts) ([]core.Target, error) {
	p, err := portForInput(opts.DefaultPort)
	if err != nil {
		return nil, err
	}
	src := opts.Stdin
	if src == nil {
		src = os.Stdin
	}
	return stdin.Parse(ctx, src, list.ParseOptions{DefaultPort: p})
}

func parseListInput(ctx context.Context, opts inputParseOpts) ([]core.Target, error) {
	path := strings.TrimPrefix(opts.InputKind, "list:")
	f, err := os.Open(path) // #nosec G304 -- caller-supplied input list path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	p, err := portForInput(opts.DefaultPort)
	if err != nil {
		return nil, err
	}
	return list.Parse(ctx, f, list.ParseOptions{DefaultPort: p})
}

func parseNmapInput(ctx context.Context, inputKind string) ([]core.Target, error) {
	path := strings.TrimPrefix(inputKind, "nmap:")
	f, err := os.Open(path) // #nosec G304 -- caller-supplied XML path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return nmapxml.Parse(ctx, f)
}
