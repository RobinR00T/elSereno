//go:build offensive

// Credential-reuse check. It answers one question an operator cannot
// answer from a port scan: do the credentials that already exist in the
// IT estate (Active Directory service accounts, a shared "admin"
// password) also open an OT device? Credential reuse across the IT/OT
// boundary is the step that turns a foothold in the office network into
// control of the plant; public surveys put it in a large fraction of OT
// networks.
//
// AUTHORIZED USE ONLY. The credentials come from the operator's own
// store (a 0600 file, Vault, a JSON endpoint: see sources.go), never a
// wordlist, and the check only verifies authentication: an accepted SSH
// login is closed immediately with no command run, and every HTTP probe
// is a GET. It is gated behind the `offensive` build tag and an explicit
// --confirm-authorized in the CLI, and every attempt is written to the
// append-only audit log.

package creds

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Protocols the reuse check can exercise.
const (
	ProtoHTTPBasic = "http-basic"
	ProtoSSH       = "ssh"
)

// ReuseResult is the outcome of one credential against one target.
type ReuseResult struct {
	User string `json:"user"`
	// Source is the store the credential came from (e.g. "vault:kv/ad").
	Source string `json:"source"`
	// Fingerprint is a per-run salted SHA-256 prefix of the password: it
	// lets two accepted results be recognised as the same secret within a
	// run and ties a finding to its audit row, and it never reveals the
	// password (the salt is random per run and discarded).
	Fingerprint string `json:"fingerprint"`
	Accepted    bool   `json:"accepted"`
	Detail      string `json:"detail,omitempty"`
}

// ReuseReport is the outcome against one target.
type ReuseReport struct {
	Target   string        `json:"target"`
	Protocol string        `json:"protocol"`
	Baseline string        `json:"baseline,omitempty"` // http-basic only
	Tested   int           `json:"tested"`
	Results  []ReuseResult `json:"results"`
	Accepted []ReuseResult `json:"accepted"`
}

// Auditor records one reuse attempt. The CLI wires it to the append-only
// audit writer; a nil Auditor disables auditing (tests).
type Auditor func(ctx context.Context, target, protocol string, r ReuseResult) error

// ReuseChecker verifies a set of credentials against one target.
type ReuseChecker struct {
	// HTTPClient is used for ProtoHTTPBasic (caller owns TLS + timeout).
	HTTPClient *http.Client
	// SSHTimeout bounds an SSH dial + handshake.
	SSHTimeout time.Duration
	// Audit, when set, is called once per credential tried.
	Audit Auditor

	salt []byte
}

// NewReuseChecker returns a checker with a fresh random fingerprint salt.
func NewReuseChecker() (*ReuseChecker, error) {
	salt := make([]byte, 16)
	if _, err := cryptorand.Read(salt); err != nil {
		return nil, fmt.Errorf("creds: salt: %w", err)
	}
	return &ReuseChecker{SSHTimeout: 8 * time.Second, salt: salt}, nil
}

// fingerprint is the per-run salted password fingerprint.
func (c *ReuseChecker) fingerprint(pass string) string {
	h := sha256.New()
	h.Write(c.salt)
	h.Write([]byte(pass))
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// CheckHTTPBasic tries each credential against url over HTTP Basic. It
// first GETs with no credentials: only a 401/403 baseline means the
// endpoint gates on Basic auth and the credentials can be judged. Every
// request is a GET.
func (c *ReuseChecker) CheckHTTPBasic(ctx context.Context, url string, creds []Credential) (ReuseReport, error) {
	rep := ReuseReport{Target: url, Protocol: ProtoHTTPBasic}
	base, err := getStatus(ctx, c.HTTPClient, url, "", "", false)
	if err != nil {
		return rep, err
	}
	rep.Baseline = fmt.Sprintf("%d", base)
	if !statusRejected(base) {
		return rep, nil // does not gate on Basic auth: nothing to judge
	}
	for _, cr := range creds {
		status, err := getStatus(ctx, c.HTTPClient, url, cr.User, cr.Pass, true)
		if err != nil {
			return rep, err
		}
		res := ReuseResult{
			User: cr.User, Source: cr.Source, Fingerprint: c.fingerprint(cr.Pass),
			Accepted: !statusRejected(status), Detail: fmt.Sprintf("status %d", status),
		}
		c.record(ctx, &rep, res)
	}
	return rep, nil
}

// CheckSSH tries each credential against addr (host:port) over SSH,
// password auth only. A successful handshake is closed at once: no
// session is opened and no command is run. An authentication failure is
// "not accepted"; any other dial/handshake error aborts the target.
func (c *ReuseChecker) CheckSSH(ctx context.Context, addr string, creds []Credential) (ReuseReport, error) {
	rep := ReuseReport{Target: addr, Protocol: ProtoSSH}
	for _, cr := range creds {
		accepted, detail, err := c.sshAttempt(ctx, addr, cr)
		if err != nil {
			return rep, err
		}
		res := ReuseResult{
			User: cr.User, Source: cr.Source, Fingerprint: c.fingerprint(cr.Pass),
			Accepted: accepted, Detail: detail,
		}
		c.record(ctx, &rep, res)
	}
	return rep, nil
}

// sshAttempt performs one password handshake. It returns (accepted,
// detail, err): err is only for conditions that are not an auth verdict
// (connection refused, timeout, no common algorithm).
func (c *ReuseChecker) sshAttempt(ctx context.Context, addr string, cr Credential) (bool, string, error) {
	d := net.Dialer{Timeout: c.SSHTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, "", fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(c.SSHTimeout))
	cfg := &ssh.ClientConfig{
		User:            cr.User,
		Auth:            []ssh.AuthMethod{ssh.Password(cr.Pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- auditing reuse, not trusting the host; no data is sent
		Timeout:         c.SSHTimeout,
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		// Password rejected is an auth verdict, not an error.
		if isAuthFailure(err) {
			return false, "authentication failed", nil
		}
		return false, "", fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	// Authenticated. Close immediately: open no session, run no command.
	go ssh.DiscardRequests(reqs)
	go drainChannels(chans)
	_ = sc.Close()
	return true, "authenticated (closed without a session)", nil
}

func drainChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		_ = ch.Reject(ssh.Prohibited, "elsereno: reuse check opens no channel")
	}
}

// isAuthFailure reports whether an SSH handshake error is a credential
// rejection rather than a transport or algorithm failure.
func isAuthFailure(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain") ||
		strings.Contains(msg, "permission denied")
}

// record appends a result, tallies accepted ones and audits the attempt.
func (c *ReuseChecker) record(ctx context.Context, rep *ReuseReport, res ReuseResult) {
	rep.Tested++
	rep.Results = append(rep.Results, res)
	if res.Accepted {
		rep.Accepted = append(rep.Accepted, res)
	}
	if c.Audit != nil {
		_ = c.Audit(ctx, rep.Target, rep.Protocol, res)
	}
}

// ErrNoCreds is returned by the CLI when no credential source yielded a
// credential.
var ErrNoCreds = errors.New("creds: no credentials loaded from any source")
