package list

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"local/elsereno/internal/core"
)

// ErrEmpty is returned when the input reader produces no valid targets.
// Callers decide whether that is fatal.
var ErrEmpty = fmt.Errorf("inputs/list: no targets parsed")

// ParseOptions bounds the parser's behaviour.
type ParseOptions struct {
	// DefaultPort applies when a line omits ":port". When 0, a line
	// without a port is rejected.
	DefaultPort core.Port

	// SkipBlank: ignore empty lines and '#' comments. Default true.
	SkipBlank bool

	// Limit caps the number of targets produced; 0 means unlimited.
	Limit int
}

// Parse reads newline-separated targets from r. Accepted forms:
//
//	1.2.3.4                       (uses DefaultPort; fails if DefaultPort==0)
//	1.2.3.4:502                   (IPv4 with port)
//	[2001:db8::1]:502             (IPv6 with port)
//	2001:db8::1                   (IPv6 without port; uses DefaultPort)
//
// Lines beginning with '#' are treated as comments. CIDRs are not
// expanded here; that's the scanner's job.
func Parse(_ context.Context, r io.Reader, opts ParseOptions) ([]core.Target, error) {
	skipBlank := opts.SkipBlank || !opts.SkipBlank // zero value -> true
	if !opts.SkipBlank {
		skipBlank = true
	}
	out := make([]core.Target, 0, 32)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1<<20) // 1 MiB line cap
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := strings.TrimSpace(scanner.Text())
		if skipBlank && (raw == "" || strings.HasPrefix(raw, "#")) {
			continue
		}
		t, err := parseLine(raw, opts.DefaultPort)
		if err != nil {
			return nil, fmt.Errorf("inputs/list: line %d: %w", lineNum, err)
		}
		out = append(out, t)
		if opts.Limit > 0 && len(out) >= opts.Limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("inputs/list: scan: %w", err)
	}
	if len(out) == 0 {
		return nil, ErrEmpty
	}
	return out, nil
}

// parseLine is the per-line implementation isolated for testing.
func parseLine(raw string, defaultPort core.Port) (core.Target, error) {
	// Bracketed IPv6 with port: [addr]:port
	if strings.HasPrefix(raw, "[") {
		end := strings.Index(raw, "]")
		if end < 0 {
			return core.Target{}, fmt.Errorf("unterminated '[' in %q", raw)
		}
		addr, err := netip.ParseAddr(raw[1:end])
		if err != nil {
			return core.Target{}, fmt.Errorf("parse addr: %w", err)
		}
		rest := raw[end+1:]
		if rest == "" {
			if defaultPort == 0 {
				return core.Target{}, fmt.Errorf("no port and no default for %q", raw)
			}
			return core.Target{Address: addr, Port: defaultPort}, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return core.Target{}, fmt.Errorf("expected ':port' after ']' in %q", raw)
		}
		p, err := parsePort(rest[1:])
		if err != nil {
			return core.Target{}, err
		}
		return core.Target{Address: addr, Port: p}, nil
	}

	// AddrPort form — handles IPv4:port and unbracketed IPv4.
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		port, pErr := core.NewPort(int(ap.Port()))
		if pErr != nil {
			return core.Target{}, pErr
		}
		return core.Target{Address: ap.Addr(), Port: port}, nil
	}

	// Bare address (IPv4 or IPv6 without port).
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return core.Target{}, fmt.Errorf("parse addr: %w", err)
	}
	if defaultPort == 0 {
		return core.Target{}, fmt.Errorf("no port and no default for %q", raw)
	}
	return core.Target{Address: addr, Port: defaultPort}, nil
}

func parsePort(s string) (core.Port, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("parse port %q: %w", s, err)
	}
	return core.NewPort(n)
}
