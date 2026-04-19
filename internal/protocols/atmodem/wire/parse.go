package wire

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MaxResponseBytes caps the size of a single AT response. Exceeding
// it returns ErrTooLong; the caller decides whether to sever the
// connection or just discard the buffer.
const MaxResponseBytes = 64 * 1024

// ErrTooLong is returned when a response exceeds MaxResponseBytes.
var ErrTooLong = errors.New("atmodem: response exceeds 64 KiB")

// ResultCode is the class of an AT response. The raw textual form is
// preserved on the Response so callers can emit it verbatim.
type ResultCode string

// Canonical terminal result codes. Any other final line is recorded as
// ResultUnknown with the original text.
const (
	ResultOK         ResultCode = "OK"
	ResultError      ResultCode = "ERROR"
	ResultConnect    ResultCode = "CONNECT"
	ResultNoCarrier  ResultCode = "NO CARRIER"
	ResultNoDialtone ResultCode = "NO DIALTONE"
	ResultBusy       ResultCode = "BUSY"
	ResultNoAnswer   ResultCode = "NO ANSWER"
	ResultRing       ResultCode = "RING"
	ResultCMEError   ResultCode = "+CME ERROR"
	ResultCMSError   ResultCode = "+CMS ERROR"
	ResultUnknown    ResultCode = "UNKNOWN"
)

// Response is the decoded AT response.
type Response struct {
	// Lines holds every payload line (not the final result code).
	Lines []string

	// Result is the canonical terminal code.
	Result ResultCode

	// RawResult is the final line verbatim.
	RawResult string

	// ErrorCode is the numeric code for +CME ERROR / +CMS ERROR (0 on
	// any other terminal).
	ErrorCode int
}

// errorResults is the set the exhaustive linter wants declared.
// Declaring it once lets IsError avoid a switch over every
// ResultCode.
var errorResults = map[ResultCode]struct{}{
	ResultError:    {},
	ResultCMEError: {},
	ResultCMSError: {},
}

// IsError reports whether the terminal code is any of ERROR,
// +CME ERROR, or +CMS ERROR.
func (r Response) IsError() bool {
	_, ok := errorResults[r.Result]
	return ok
}

// IsConnect reports whether the modem moved to online/data mode
// (CONNECT). Callers must treat the connection as an opaque data
// pipe thereafter.
func (r Response) IsConnect() bool { return r.Result == ResultConnect }

// Parse decodes AT response bytes. A terminal line is always present
// in well-formed responses; callers that build inputs from the wire
// should feed complete responses at a time.
func Parse(raw []byte) (Response, error) {
	if len(raw) > MaxResponseBytes {
		return Response{}, fmt.Errorf("%w: %d", ErrTooLong, len(raw))
	}
	r := Response{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 4096), MaxResponseBytes)
	// AT uses CR/LF or LF; split on either.
	sc.Split(scanATLines)

	var allLines []string
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		allLines = append(allLines, line)
	}
	if err := sc.Err(); err != nil {
		return Response{}, fmt.Errorf("atmodem: scan: %w", err)
	}

	if len(allLines) == 0 {
		r.Result = ResultUnknown
		return r, nil
	}

	// The terminal is the last non-empty line.
	terminal := allLines[len(allLines)-1]
	r.RawResult = terminal
	r.Result, r.ErrorCode = classifyTerminal(terminal)
	if r.Result != ResultUnknown {
		r.Lines = allLines[:len(allLines)-1]
	} else {
		r.Lines = allLines
	}
	return r, nil
}

// ReadResponse reads bytes from r until a terminal result code line
// is seen, then returns the parsed response.
func ReadResponse(r io.Reader) (Response, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), MaxResponseBytes)
	sc.Split(scanATLines)

	var lines []string
	total := 0
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		total += len(line) + 1
		if total > MaxResponseBytes {
			return Response{}, fmt.Errorf("%w: %d", ErrTooLong, total)
		}
		if line == "" {
			continue
		}
		code, num := classifyTerminal(line)
		if code != ResultUnknown {
			return Response{
				Lines:     lines,
				Result:    code,
				RawResult: line,
				ErrorCode: num,
			}, nil
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return Response{}, fmt.Errorf("atmodem: scan: %w", err)
	}
	return Response{Lines: lines, Result: ResultUnknown}, io.EOF
}

// classifyTerminal recognises the canonical terminal codes and
// extracts the numeric code for +CME ERROR / +CMS ERROR.
func classifyTerminal(line string) (ResultCode, int) {
	switch strings.TrimSpace(line) {
	case "OK":
		return ResultOK, 0
	case "ERROR":
		return ResultError, 0
	case "NO CARRIER":
		return ResultNoCarrier, 0
	case "NO DIALTONE":
		return ResultNoDialtone, 0
	case "BUSY":
		return ResultBusy, 0
	case "NO ANSWER":
		return ResultNoAnswer, 0
	case "RING":
		return ResultRing, 0
	}
	// CONNECT may include a baud rate: "CONNECT 9600" — match prefix.
	if strings.HasPrefix(line, "CONNECT") {
		return ResultConnect, 0
	}
	// +CME ERROR: <n> / +CMS ERROR: <n>
	if num, ok := extractErrorCode(line, "+CME ERROR"); ok {
		return ResultCMEError, num
	}
	if num, ok := extractErrorCode(line, "+CMS ERROR"); ok {
		return ResultCMSError, num
	}
	return ResultUnknown, 0
}

func extractErrorCode(line, prefix string) (int, bool) {
	if !strings.HasPrefix(line, prefix) {
		return 0, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	rest = strings.TrimPrefix(rest, ":")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return 0, true
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		// Some GSM stacks emit textual error names; accept without a
		// number.
		return 0, true
	}
	return n, true
}

// scanATLines is a bufio.SplitFunc that treats both \n and \r\n as
// line terminators without producing spurious empty tokens.
func scanATLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, dropCR(data[:i]), nil
	}
	if atEOF {
		return len(data), dropCR(data), nil
	}
	return 0, nil, nil
}

func dropCR(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\r' {
		return b[:len(b)-1]
	}
	return b
}
