package inputs

import (
	"errors"
	"net/url"
	"strings"
)

// Redacted replaces a credential in an error's URL.
const Redacted = "REDACTED"

// RedactQuery returns err with the values of the named query parameters
// replaced by Redacted in the URL that net/http records in a *url.Error.
// Shodan and FOFA take their credentials in the query string, and every
// transport failure (DNS, refused, timeout, TLS) comes back as
// `Get "<full URL>": ...` and a malformed request URL as
// `parse "<full URL>": ...`, so without this the
// API key reached the terminal, CI logs and anything that stores the
// error text. The first *url.Error in the chain has its URL rewritten in
// place (net/http creates it for this call alone), so the chain and the
// cause are kept: errors.Is(err, context.DeadlineExceeded) and the
// Timeout method still work. Call it on the error net/http returned,
// before wrapping it; when a wrapper already formatted the old text, the
// result is a new error with the rewritten text that unwraps to the
// redacted *url.Error (not to the wrapper, whose text still holds the
// secret). An error without a *url.Error is returned unchanged.
func RedactQuery(err error, params ...string) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	before := ue.Error()
	ue.URL = redactURL(ue.URL, params)
	after := ue.Error()
	if msg := err.Error(); msg != after && strings.Contains(msg, before) {
		return &rewrittenError{msg: strings.ReplaceAll(msg, before, after), err: ue}
	}
	return err
}

// rewrittenError carries the redacted text of an error chain whose
// wrappers formatted the URL before RedactQuery saw it. It unwraps to the
// redacted *url.Error, so errors.Is and As still reach the cause.
type rewrittenError struct {
	msg string
	err error
}

func (e *rewrittenError) Error() string { return e.msg }
func (e *rewrittenError) Unwrap() error { return e.err }

// redactURL replaces the named query values in raw. When raw does not
// parse, everything after the first '?' is dropped instead.
func redactURL(raw string, params []string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexByte(raw, '?'); i >= 0 {
			return raw[:i] + "?" + Redacted
		}
		return raw
	}
	q := u.Query()
	changed := false
	for _, p := range params {
		if q.Has(p) {
			q.Set(p, Redacted)
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}
