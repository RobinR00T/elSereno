//go:build offensive

// Package creds holds the opt-in, offensive-build default-credential
// checks. They evidence NIST SP 800-82 Rev. 4 Table 13, "Vendor default
// passwords are used ... easy to discover within vendor product manuals"
// (see docs/standards/nist-sp800-82r4.md).
//
// AUTHORIZED USE ONLY. This is a targeted verification of a small,
// PUBLISHED set of vendor default credentials against a device's own web
// UI, for an operator auditing infrastructure they are authorized to test.
// It is not a brute-force or wordlist attack: it only tries documented
// defaults, and only after confirming the endpoint actually requires
// authentication. It is gated behind the `offensive` build tag and an
// explicit authorization acknowledgment in the CLI.
package creds

import (
	"context"
	"net/http"
)

// Credential is one published default credential and where it is documented.
type Credential struct {
	User   string `json:"user"`
	Pass   string `json:"pass"`
	Source string `json:"source"` // where this default is publicly documented
}

// HTTPBasicDefaults is a small, curated set of PUBLISHED default HTTP Basic
// credentials common on ICS/OT and networking device web UIs. It is
// intentionally short and documented, not a wordlist.
var HTTPBasicDefaults = []Credential{
	{"admin", "admin", "generic device default"},
	{"admin", "", "generic device default (blank password)"},
	{"admin", "password", "generic device default"},
	{"admin", "1234", "generic device default"},
	{"root", "root", "generic embedded-Linux default"},
	{"user", "user", "generic device default"},
	{"operator", "operator", "generic HMI default"},
	{"admin", "Siemens", "documented Siemens device default"},
	{"admin", "moxa", "documented Moxa device default"},
}

// CredResult reports the outcome of one credential attempt.
type CredResult struct {
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Source   string `json:"source"`
	Accepted bool   `json:"accepted"`
	Status   int    `json:"status"`
}

// Report is the outcome of a default-credential check against one URL.
type Report struct {
	URL            string       `json:"url"`
	BaselineStatus int          `json:"baseline_status"`
	RequiresAuth   bool         `json:"requires_auth"`
	Tested         int          `json:"tested"`
	Accepted       []CredResult `json:"accepted"`
}

// statusRejected reports whether an HTTP status is an auth rejection.
func statusRejected(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// CheckHTTPBasicDefaults verifies the published HTTP Basic defaults against
// url, using client (the caller owns TLS config and timeouts). It first
// GETs url with no credentials: only if that is an auth rejection (401/403)
// does it try the defaults, so a page that does not gate on Basic auth is
// never misreported as "accepting" credentials. Every request is a GET; it
// never changes state.
func CheckHTTPBasicDefaults(ctx context.Context, client *http.Client, url string) (Report, error) {
	rep := Report{URL: url}

	baseStatus, err := getStatus(ctx, client, url, "", "", false)
	if err != nil {
		return rep, err
	}
	rep.BaselineStatus = baseStatus
	rep.RequiresAuth = statusRejected(baseStatus)
	if !rep.RequiresAuth {
		return rep, nil // endpoint does not gate on Basic auth: nothing to verify
	}

	for _, c := range HTTPBasicDefaults {
		status, err := getStatus(ctx, client, url, c.User, c.Pass, true)
		if err != nil {
			return rep, err
		}
		rep.Tested++
		if !statusRejected(status) {
			rep.Accepted = append(rep.Accepted, CredResult{
				User: c.User, Pass: c.Pass, Source: c.Source, Accepted: true, Status: status,
			})
		}
	}
	return rep, nil
}

// getStatus issues one GET (optionally with Basic auth) and returns the
// status code. Redirects are not followed, so a 3xx to an authenticated
// landing page reads as acceptance rather than a rejection.
func getStatus(ctx context.Context, client *http.Client, url, user, pass string, withAuth bool) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	if withAuth {
		req.SetBasicAuth(user, pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}
