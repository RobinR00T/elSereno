//go:build offensive

package harvest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// FTPProber attempts login against an FTP control channel (RFC 959).
// Only the login exchange is implemented: 220 banner → USER →
// 331/230 → PASS → 230 success / 530 fail.
type FTPProber struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// NewFTP returns a prober with conservative timeouts.
func NewFTP() *FTPProber {
	return &FTPProber{DialTimeout: 5 * time.Second, IOTimeout: 3 * time.Second}
}

// Name implements Prober.
func (f *FTPProber) Name() string { return "ftp" }

// DefaultPort implements Prober.
func (f *FTPProber) DefaultPort() uint16 { return 21 }

// Probe implements Prober.
func (f *FTPProber) Probe(ctx context.Context, target string, creds []Credential) (*Result, error) {
	for _, c := range creds {
		if c.Username == "" {
			continue
		}
		hit, banner, err := f.attempt(ctx, target, c)
		if err != nil {
			continue
		}
		if hit {
			return &Result{
				Protocol:   f.Name(),
				Target:     target,
				Credential: c,
				Banner:     banner,
				At:         time.Now().UTC().Truncate(time.Microsecond),
			}, nil
		}
	}
	return nil, ErrNoHit
}

func (f *FTPProber) attempt(ctx context.Context, target string, c Credential) (bool, string, error) {
	d := net.Dialer{Timeout: f.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(f.IOTimeout))
	r := bufio.NewReader(conn)
	// Expect 220 banner.
	banner, code, err := readFTPResponse(r)
	if err != nil {
		return false, banner, err
	}
	if code != 220 {
		return false, banner, nil
	}
	// USER.
	if _, err := fmt.Fprintf(conn, "USER %s\r\n", c.Username); err != nil {
		return false, banner, err
	}
	_, code, err = readFTPResponse(r)
	if err != nil {
		return false, banner, err
	}
	// 230 = logged in without password; 331 = need password; any
	// other code = fail.
	if code == 230 {
		return true, banner, nil
	}
	if code != 331 {
		return false, banner, nil
	}
	// PASS.
	if _, err := fmt.Fprintf(conn, "PASS %s\r\n", c.Password); err != nil {
		return false, banner, err
	}
	_, code, err = readFTPResponse(r)
	if err != nil {
		return false, banner, err
	}
	return code == 230, banner, nil
}

// readFTPResponse reads a single (possibly multi-line) FTP response
// and returns the final line text + numeric code. Handles the
// "<code>-<text>" continuation marker per RFC 959 §4.2.
func readFTPResponse(r *bufio.Reader) (string, int, error) {
	var last string
	var code int
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return last, 0, err
		}
		last = strings.TrimRight(line, "\r\n")
		if len(last) < 3 {
			continue
		}
		var c int
		_, err = fmt.Sscanf(last[:3], "%d", &c)
		if err != nil {
			continue
		}
		code = c
		// Continuation marker "NNN-"; final line has "NNN " or "NNN"
		// by itself.
		if len(last) > 3 && last[3] == '-' {
			continue
		}
		break
	}
	return last, code, nil
}
