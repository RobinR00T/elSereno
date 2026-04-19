//go:build offensive

package harvest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// TelnetProber attempts login against a Telnet server (RFC 854). It
// does the bare minimum Telnet option negotiation (refuse every WILL
// with DONT, every DO with WONT) so vendors that insist on echo /
// linemode options don't leave the connection hung.
type TelnetProber struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// NewTelnet returns a Prober with conservative timeouts.
func NewTelnet() *TelnetProber {
	return &TelnetProber{DialTimeout: 5 * time.Second, IOTimeout: 3 * time.Second}
}

// Name implements Prober.
func (t *TelnetProber) Name() string { return "telnet" }

// DefaultPort implements Prober.
func (t *TelnetProber) DefaultPort() uint16 { return 23 }

// Probe implements Prober.
func (t *TelnetProber) Probe(ctx context.Context, target string, creds []Credential) (*Result, error) {
	for _, c := range creds {
		if c.Username == "" && c.Password == "" {
			continue
		}
		hit, banner, err := t.attempt(ctx, target, c)
		if err != nil {
			// dial or protocol error — try next credential.
			continue
		}
		if hit {
			return &Result{
				Protocol:   t.Name(),
				Target:     target,
				Credential: c,
				Banner:     banner,
				At:         time.Now().UTC().Truncate(time.Microsecond),
			}, nil
		}
	}
	return nil, ErrNoHit
}

// attempt dials the target, walks the telnet login state machine
// with the given credential, and returns (hit, banner, err).
func (t *TelnetProber) attempt(ctx context.Context, target string, c Credential) (bool, string, error) {
	d := net.Dialer{Timeout: t.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(t.IOTimeout))

	r := bufio.NewReader(conn)
	var output bytes.Buffer
	state := waitLogin

	deadline := time.Now().Add(t.IOTimeout)
	for time.Now().Before(deadline) {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || err.Error() == "EOF" {
				break
			}
			return false, output.String(), err
		}
		if b == 0xFF {
			if err := negotiateRefuse(r, conn); err != nil {
				return false, output.String(), err
			}
			continue
		}
		output.WriteByte(b)

		done, hit, err := t.advanceState(&state, &output, conn, c, &deadline)
		if err != nil {
			return false, output.String(), err
		}
		if done {
			return hit, output.String(), nil
		}
	}
	return false, output.String(), nil
}

// advanceState walks one byte through the login state machine. It
// returns (done, hit, err): done=true means the attempt terminated
// (either success or an observed fail line), and the caller
// returns. done=false means keep reading.
func (t *TelnetProber) advanceState(
	state *telnetState,
	output *bytes.Buffer,
	conn net.Conn,
	c Credential,
	deadline *time.Time,
) (bool, bool, error) {
	s := output.String()
	switch *state {
	case waitLogin:
		if containsLoginPrompt(s) {
			if _, err := fmt.Fprintf(conn, "%s\r\n", c.Username); err != nil {
				return true, false, err
			}
			output.Reset()
			*state = waitPassword
		}
	case waitPassword:
		if containsPasswordPrompt(s) {
			if _, err := fmt.Fprintf(conn, "%s\r\n", c.Password); err != nil {
				return true, false, err
			}
			output.Reset()
			*state = waitShell
			*deadline = time.Now().Add(t.IOTimeout)
			_ = conn.SetDeadline(*deadline)
		}
	case waitShell:
		if containsShellPrompt(s) {
			return true, true, nil
		}
		if containsLoginFail(s) {
			return true, false, nil
		}
	}
	return false, false, nil
}

// telnetState indexes the login state machine.
type telnetState int

const (
	waitLogin telnetState = iota
	waitPassword
	waitShell
)

// negotiateRefuse reads the 2-byte Telnet option after an IAC and
// writes back a refusal (WILL -> DONT, WONT -> DONT, DO -> WONT,
// DONT -> WONT). A subnegotiation (SB…SE) is drained silently.
func negotiateRefuse(r *bufio.Reader, w net.Conn) error {
	cmd, err := r.ReadByte()
	if err != nil {
		return err
	}
	switch cmd {
	case 0xFB, 0xFC: // WILL / WONT
		opt, err := r.ReadByte()
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{0xFF, 0xFE, opt}) // IAC DONT opt
		return err
	case 0xFD, 0xFE: // DO / DONT
		opt, err := r.ReadByte()
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{0xFF, 0xFC, opt}) // IAC WONT opt
		return err
	case 0xFA: // SB (subnegotiation) - drain until IAC SE
		for {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			if b == 0xFF {
				if _, err := r.ReadByte(); err != nil {
					return err
				}
				return nil
			}
		}
	}
	return nil
}

func containsLoginPrompt(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "login:") || strings.Contains(low, "username:") || strings.Contains(low, "user:")
}

func containsPasswordPrompt(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "password:") || strings.Contains(low, "passwd:")
}

func containsShellPrompt(s string) bool {
	trim := strings.TrimRight(s, " \t\r\n")
	if trim == "" {
		return false
	}
	last := trim[len(trim)-1]
	return last == '$' || last == '#' || last == '>' || last == '%'
}

func containsLoginFail(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "login incorrect") ||
		strings.Contains(low, "authentication failed") ||
		strings.Contains(low, "access denied") ||
		strings.Contains(low, "login failed")
}
