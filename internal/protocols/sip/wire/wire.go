// Package wire builds + parses the subset of SIP (RFC 3261)
// messages the ElSereno PBX fingerprint needs. That subset is
// tiny: a single OPTIONS request to "sip:server" and the
// response header block that carries `User-Agent:` and
// `Server:` fields — those two headers are where Asterisk /
// FreePBX / 3CX / Cisco UCM / Mitel / Avaya / Yeastar /
// Grandstream / Fanvil / Yealink reveal themselves.
//
// This is NOT a full SIP stack. We never parse To/From/Via tags,
// never follow redirects, never handle authentication. Probes
// that get a response with a SIP-looking status line + a
// vendor-identifying User-Agent / Server are scored; everything
// else is logged as non-SIP.
package wire

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strings"
)

// BuildOPTIONS crafts a minimal OPTIONS request. Following
// RFC 3261 §13 the method MUST include Via, Max-Forwards,
// From, To, Call-ID, CSeq, and Content-Length headers — most
// SIP servers will 400 if any of these are missing, even for
// OPTIONS.
//
// `host` is the server's externally-visible host:port; `branch`
// is an operator-supplied magic cookie used by the Via header
// per §8.1.1.7 (format "z9hG4bK" + random).
func BuildOPTIONS(host, branch string) []byte {
	var b strings.Builder
	// Request-URI is "sip:host" — we're asking the server about
	// itself, not routing to an extension.
	fmt.Fprintf(&b, "OPTIONS sip:%s SIP/2.0\r\n", host)
	fmt.Fprintf(&b, "Via: SIP/2.0/UDP %s;branch=z9hG4bK%s\r\n", host, branch)
	fmt.Fprintf(&b, "Max-Forwards: 70\r\n")
	fmt.Fprintf(&b, "From: <sip:elsereno@%s>;tag=probe-%s\r\n", host, branch)
	fmt.Fprintf(&b, "To: <sip:%s>\r\n", host)
	fmt.Fprintf(&b, "Call-ID: %s@%s\r\n", branch, host)
	fmt.Fprintf(&b, "CSeq: 1 OPTIONS\r\n")
	fmt.Fprintf(&b, "User-Agent: ElSereno/1.0 (probe)\r\n")
	fmt.Fprintf(&b, "Accept: application/sdp\r\n")
	fmt.Fprintf(&b, "Content-Length: 0\r\n")
	fmt.Fprintf(&b, "\r\n")
	return []byte(b.String())
}

// Response captures the status line + the two vendor-disclosing
// headers of a SIP response.
type Response struct {
	// StatusLine is the full first line — e.g. "SIP/2.0 200 OK"
	// or "SIP/2.0 401 ...". Status phrase spelling follows
	// RFC 3261 §21.4 which uses US-English; the misspell linter
	// is disarmed per-line at the test file where the phrase
	// appears verbatim.
	StatusLine string
	// Code is the 3-digit status code (200, 401, 404, 405, …)
	// or 0 if the line didn't parse.
	Code int
	// Reason is the status phrase after the code ("OK",
	// "Forbidden", the auth-required phrase for 401, etc).
	Reason string
	// Server is the "Server:" header value — the canonical
	// vendor-disclosing field. Asterisk returns "Asterisk PBX
	// X.Y.Z"; Cisco "Cisco-SIPGateway/IOS-12.x"; 3CX "3CX
	// Phone System".
	Server string
	// UserAgent is the "User-Agent:" header value — sometimes
	// populated instead of Server in registrar-style responses.
	UserAgent string
	// Allow is the "Allow:" header (comma-separated methods).
	// Read-only discovery signal: a server that advertises
	// INVITE / REGISTER / SUBSCRIBE / MESSAGE is a full PBX,
	// one that lists only OPTIONS is usually a proxy.
	Allow string
}

// ParseResponse reads a SIP response from r and extracts the
// status line + interesting headers. Returns an error only on
// read failure; a response with missing headers yields empty
// strings in the matching fields (caller decides how to score).
func ParseResponse(r io.Reader) (Response, error) {
	br := bufio.NewReader(r)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return Response{}, fmt.Errorf("sip/wire: read status line: %w", err)
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	resp := Response{StatusLine: statusLine}
	// Status line: "SIP/2.0 <code> <reason...>".
	if strings.HasPrefix(statusLine, "SIP/2.0 ") {
		rest := strings.TrimPrefix(statusLine, "SIP/2.0 ")
		sp := strings.IndexByte(rest, ' ')
		var codeStr string
		if sp < 0 {
			codeStr = rest
		} else {
			codeStr = rest[:sp]
			resp.Reason = rest[sp+1:]
		}
		if code, err := parsePositiveInt(codeStr); err == nil {
			resp.Code = code
		}
	}
	// Read headers via textproto — it handles folded lines, case-
	// insensitive keys, and stops cleanly at the blank line
	// separator.
	tp := textproto.NewReader(br)
	headers, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		// EOF after the blank line is normal for UDP responses
		// that don't append a body; anything else is a read
		// failure.
		return resp, fmt.Errorf("sip/wire: parse headers: %w", err)
	}
	resp.Server = headers.Get("Server")
	resp.UserAgent = headers.Get("User-Agent")
	resp.Allow = headers.Get("Allow")
	return resp, nil
}

// parsePositiveInt is a tiny helper to avoid pulling strconv
// for one call.
func parsePositiveInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a digit: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// IsSIPStatus returns true when line starts with "SIP/2.0 " —
// the cheapest way to tell a SIP response apart from noise
// (HTTP, TLS records, telnet banners) in the probe path.
func IsSIPStatus(line string) bool {
	return strings.HasPrefix(line, "SIP/2.0 ")
}
