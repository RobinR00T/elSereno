//go:build offensive

package dial

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// v2.37+ — range-spec syntax for wardialing batch.
//
// Operators want to type one expression and have it expand to a
// sequence of numbers. Two forms supported:
//
//	555-0100..555-0199           → 100 numbers in lexical order
//	+34900-XXX-100..+34900-XXX-199
//
// The "common prefix + numeric tail" pattern is dominant in real
// wardials (NANP exchange + 100-block of subscriber numbers, or
// E.164 country-and-area + suffix range). We support exactly that
// case: any non-digit characters in the prefix carry through
// verbatim; only the trailing numeric block expands.
//
// Constraints:
//   - Both endpoints must share an identical non-numeric prefix.
//   - Both endpoints must have a numeric suffix of equal length
//     (preserves leading zeros).
//   - Start ≤ end (lexical = numeric for equal-length suffixes).
//   - Total expansion ≤ MaxRangeSize. Operators wanting more
//     should split into chunks (and the chunked workflow gives
//     them better checkpoint granularity).

// MaxRangeSize caps the number of digits a single range may
// expand to. 10k is enough for "100 blocks of 100" wardials
// while still being review-able as a batch.
const MaxRangeSize = 10_000

// ErrRangeMalformed is the catch-all for bad range syntax.
var ErrRangeMalformed = errors.New("dial: range spec malformed")

// ErrRangePrefixMismatch — endpoints don't share a common non-
// numeric prefix.
var ErrRangePrefixMismatch = errors.New("dial: range endpoints have different prefixes")

// ErrRangeSuffixLength — endpoints' numeric tails are different
// lengths (would not preserve leading-zero alignment).
var ErrRangeSuffixLength = errors.New("dial: range endpoints have suffixes of different lengths")

// ErrRangeReversed — end < start.
var ErrRangeReversed = errors.New("dial: range end is before start")

// ErrRangeTooLarge — expansion would exceed MaxRangeSize.
var ErrRangeTooLarge = errors.New("dial: range expansion exceeds MaxRangeSize")

// rangeRE captures `<start>..<end>`. The `\.\.` separator must
// appear exactly once; trailing whitespace is tolerated.
var rangeRE = regexp.MustCompile(`^(.+?)\.\.(.+)$`)

// trailingDigitsRE peels off the trailing numeric tail.
var trailingDigitsRE = regexp.MustCompile(`^(.*?)(\d+)$`)

// ExpandRange parses a range spec and returns the expanded list
// of numbers (in lexical/numeric order). Empty list with non-nil
// error on parse failure.
//
// Examples:
//
//	"555-0100..555-0199"             → [555-0100, 555-0101, ..., 555-0199]
//	"+34900-100-100..+34900-100-105" → 6 numbers, prefix +34900-100- kept
//	"555-0100..555-0199 " (trailing) → same as the first (whitespace trimmed)
//
// Non-range inputs (no "..") return ErrRangeMalformed.
func ExpandRange(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	m := rangeRE.FindStringSubmatch(spec)
	if m == nil {
		return nil, fmt.Errorf("%w: missing '..'", ErrRangeMalformed)
	}
	startRaw := strings.TrimSpace(m[1])
	endRaw := strings.TrimSpace(m[2])
	startPrefix, startDigits, ok := splitPrefixDigits(startRaw)
	if !ok {
		return nil, fmt.Errorf("%w: start has no numeric tail", ErrRangeMalformed)
	}
	endPrefix, endDigits, ok := splitPrefixDigits(endRaw)
	if !ok {
		return nil, fmt.Errorf("%w: end has no numeric tail", ErrRangeMalformed)
	}
	if startPrefix != endPrefix {
		return nil, fmt.Errorf("%w: %q vs %q", ErrRangePrefixMismatch, startPrefix, endPrefix)
	}
	if len(startDigits) != len(endDigits) {
		return nil, fmt.Errorf("%w: %d vs %d digits", ErrRangeSuffixLength, len(startDigits), len(endDigits))
	}
	startN, err := strconv.Atoi(startDigits)
	if err != nil {
		return nil, fmt.Errorf("%w: start digits parse: %w", ErrRangeMalformed, err)
	}
	endN, err := strconv.Atoi(endDigits)
	if err != nil {
		return nil, fmt.Errorf("%w: end digits parse: %w", ErrRangeMalformed, err)
	}
	if endN < startN {
		return nil, fmt.Errorf("%w: %d < %d", ErrRangeReversed, endN, startN)
	}
	count := endN - startN + 1
	if count > MaxRangeSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrRangeTooLarge, count, MaxRangeSize)
	}
	width := len(startDigits)
	out := make([]string, 0, count)
	for n := startN; n <= endN; n++ {
		out = append(out, fmt.Sprintf("%s%0*d", startPrefix, width, n))
	}
	return out, nil
}

// splitPrefixDigits separates the trailing numeric tail from the
// preceding (possibly empty) prefix. Returns (prefix, digits,
// true) on success; (_, _, false) when the input has no
// trailing digits.
func splitPrefixDigits(s string) (string, string, bool) {
	m := trailingDigitsRE.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// IsRangeSpec reports whether a string looks like a range spec
// (contains exactly one ".."). Used by the CLI to dispatch
// between file-input and range-input modes.
func IsRangeSpec(spec string) bool {
	return strings.Contains(spec, "..")
}
