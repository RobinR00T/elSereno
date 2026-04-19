//go:build offensive

package harvest

import (
	"context"
	"errors"
	"time"
)

// Credential is a username/password or SNMP community tried against
// a target. Fields are mutually optional — Telnet/FTP/HTTP-Basic use
// Username+Password, SNMPv1/v2c uses Community.
type Credential struct {
	Username  string
	Password  string
	Community string
}

// Empty reports whether this credential is totally blank (useful for
// filtering default-user-list entries).
func (c Credential) Empty() bool {
	return c.Username == "" && c.Password == "" && c.Community == ""
}

// Result is one successful credential discovery.
type Result struct {
	Protocol   string
	Target     string     // host:port
	Credential Credential // the one that worked
	Banner     string     // evidence (truncated by caller)
	At         time.Time
}

// Prober fingerprints a single (target, protocol) and tries the
// supplied credential list until one succeeds, the list runs out, or
// the context is cancelled.
type Prober interface {
	// Name returns the protocol identifier ("telnet", "ftp",
	// "http-basic", "snmp").
	Name() string
	// DefaultPort returns the well-known port for the protocol.
	DefaultPort() uint16
	// Probe tries creds against target (host:port). On first success
	// it returns the Result and stops iterating. Empty list -> nil.
	Probe(ctx context.Context, target string, creds []Credential) (*Result, error)
}

// Errors returned by probers.
var (
	// ErrNoHit — the entire credential list was exhausted without a
	// successful login. Not an error in the "something went wrong"
	// sense; callers decide whether to surface it.
	ErrNoHit = errors.New("harvest: no credential in list succeeded")
	// ErrBadTarget — target string could not be parsed as host:port.
	ErrBadTarget = errors.New("harvest: bad target address")
)

// DefaultCredentials returns a small list of credentials that appear
// on public ICS / OT misconfiguration lists. The list is intentionally
// short — offensive harvest is NOT a brute-force tool; operators
// supply their own wordlist via --creds-file for anything wider.
//
// Sources: OWASP embedded-device default-password database, Kaspersky
// ICS default-credentials publications, vendor documentation that
// ships default accounts (Moxa, Schneider, Siemens, GE, etc.).
func DefaultCredentials() []Credential {
	return []Credential{
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "password"},
		{Username: "admin", Password: ""},
		{Username: "root", Password: "root"},
		{Username: "root", Password: ""},
		{Username: "user", Password: "user"},
		{Username: "operator", Password: "operator"},
		{Username: "guest", Password: "guest"},
		{Username: "engineer", Password: "engineer"},
		{Username: "service", Password: "service"},
		// SNMP defaults.
		{Community: "public"},
		{Community: "private"},
	}
}
