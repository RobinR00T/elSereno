package scanorch

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CronExpr is a parsed 5-field cron expression. Field order
// matches the standard Unix layout:
//
//	minute  (0-59)
//	hour    (0-23)
//	dom     (1-31)  day of month
//	month   (1-12)
//	dow     (0-6)   day of week (Sunday=0)
//
// Each field is a 64-bit bitmask of allowed values. A bit set
// at position N means "N is a valid trigger value for this
// field". Bitmask form makes the per-minute "is this t a
// match?" check a bitwise AND across the 5 fields.
//
// Supported syntax in each field (asterisk means any value):
// asterisk, N (single numeric), N,M,... (comma list),
// N-M (inclusive range), asterisk/S (step from minimum),
// N-M/S (stepped range).
//
// NOT supported (deferred): @yearly / @daily / @hourly named
// shortcuts; JAN..DEC / SUN..SAT named months/days;
// last-of-month / weekday-of-month etc.
//
// A future cycle can layer the named shortcuts as a
// pre-process pass on the input string before parsing.
type CronExpr struct {
	minute uint64 // bits 0..59
	hour   uint64 // bits 0..23
	dom    uint64 // bits 1..31
	month  uint64 // bits 1..12
	dow    uint64 // bits 0..6
	// raw is the original expression string. Useful for
	// dashboards / logging — we never need to round-trip the
	// bitmasks back to the canonical form.
	raw string
}

// Sentinel errors.
var (
	// ErrCronInvalidField is returned by ParseCron when a
	// field is malformed (non-numeric, range out of bounds,
	// step <= 0, etc).
	ErrCronInvalidField = errors.New("scanorch: cron field invalid")
	// ErrCronWrongFieldCount means the expression has !=5
	// space-separated fields.
	ErrCronWrongFieldCount = errors.New("scanorch: cron expression must have exactly 5 fields")
)

// Per-field min/max ranges.
type fieldRange struct {
	min, max int
}

var cronFields = []fieldRange{
	{0, 59}, // minute
	{0, 23}, // hour
	{1, 31}, // dom
	{1, 12}, // month
	{0, 6},  // dow
}

// ParseCron parses a 5-field cron expression. Returns the
// compiled CronExpr or an error wrapping ErrCronInvalidField /
// ErrCronWrongFieldCount.
func ParseCron(expr string) (CronExpr, error) {
	expr = strings.TrimSpace(expr)
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return CronExpr{}, fmt.Errorf("%w: got %d fields", ErrCronWrongFieldCount, len(parts))
	}
	c := CronExpr{raw: expr}
	for i, part := range parts {
		mask, err := parseCronField(part, cronFields[i])
		if err != nil {
			return CronExpr{}, fmt.Errorf("%w: field %d %q: %w", ErrCronInvalidField, i, part, err)
		}
		switch i {
		case 0:
			c.minute = mask
		case 1:
			c.hour = mask
		case 2:
			c.dom = mask
		case 3:
			c.month = mask
		case 4:
			c.dow = mask
		}
	}
	return c, nil
}

// parseCronField turns one field into a bitmask. Handles the
// supported syntax via a small dispatcher per top-level form.
func parseCronField(field string, r fieldRange) (uint64, error) {
	if field == "" {
		return 0, errors.New("empty")
	}
	// Comma-separated list: parse each chunk + OR them
	// together.
	if strings.Contains(field, ",") {
		var mask uint64
		for _, chunk := range strings.Split(field, ",") {
			submask, err := parseCronField(chunk, r)
			if err != nil {
				return 0, err
			}
			mask |= submask
		}
		return mask, nil
	}
	// Step form: BASE/STEP. BASE is "*" or "N-M".
	base, step, err := splitCronStep(field)
	if err != nil {
		return 0, err
	}
	// Range or single.
	lo, hi, err := parseCronRange(base, r)
	if err != nil {
		return 0, err
	}
	if lo < r.min || hi > r.max {
		return 0, fmt.Errorf("range %d-%d outside [%d, %d]", lo, hi, r.min, r.max)
	}
	var mask uint64
	for v := lo; v <= hi; v += step {
		// #nosec G115 -- v is bounded by [r.min, r.max] which
		// is at most 59 (minute field); the cast to uint is
		// always within int's positive range.
		mask |= 1 << uint(v)
	}
	return mask, nil
}

// splitCronStep separates the BASE/STEP form. Returns the
// base sub-field and the step (default 1).
func splitCronStep(field string) (string, int, error) {
	idx := strings.Index(field, "/")
	if idx < 0 {
		return field, 1, nil
	}
	s, err := strconv.Atoi(field[idx+1:])
	if err != nil {
		return "", 0, fmt.Errorf("step %q: %w", field[idx+1:], err)
	}
	if s <= 0 {
		return "", 0, fmt.Errorf("step %d <= 0", s)
	}
	return field[:idx], s, nil
}

// parseCronRange resolves "*", "N", or "N-M" against the
// field's natural range.
func parseCronRange(base string, r fieldRange) (int, int, error) {
	if base == "*" {
		return r.min, r.max, nil
	}
	if dash := strings.Index(base, "-"); dash >= 0 {
		n, err := strconv.Atoi(base[:dash])
		if err != nil {
			return 0, 0, fmt.Errorf("range start %q: %w", base[:dash], err)
		}
		m, err := strconv.Atoi(base[dash+1:])
		if err != nil {
			return 0, 0, fmt.Errorf("range end %q: %w", base[dash+1:], err)
		}
		if n > m {
			return 0, 0, fmt.Errorf("range %d > %d", n, m)
		}
		return n, m, nil
	}
	n, err := strconv.Atoi(base)
	if err != nil {
		return 0, 0, fmt.Errorf("value %q: %w", base, err)
	}
	return n, n, nil
}

// Match reports whether t matches the cron expression. Used
// internally by Next; exposed for tests.
//
// Day-of-month and day-of-week are OR'd together when both
// are restricted (the standard Unix-cron semantic): if either
// matches, the date matches. When one is "*" the other
// dominates.
func (c CronExpr) Match(t time.Time) bool {
	// All time.Time getters return values bounded by their
	// natural ranges (minute<60, hour<24, day∈[1,31],
	// month∈[1,12], weekday∈[0,6]); the uint cast is always
	// within int's positive range.
	min := uint64(1) << uint(t.Minute())       // #nosec G115 -- bounded
	hour := uint64(1) << uint(t.Hour())        // #nosec G115 -- bounded
	dom := uint64(1) << uint(t.Day())          // #nosec G115 -- bounded
	month := uint64(1) << uint(int(t.Month())) // #nosec G115 -- bounded
	dow := uint64(1) << uint(int(t.Weekday())) // #nosec G115 -- bounded
	if c.minute&min == 0 {
		return false
	}
	if c.hour&hour == 0 {
		return false
	}
	if c.month&month == 0 {
		return false
	}
	// Day matching: OR semantics when both fields are
	// restricted; AND when one is "*" (full mask).
	domAllAny := c.dom == cronFullMask(cronFields[2])
	dowAllAny := c.dow == cronFullMask(cronFields[4])
	switch {
	case domAllAny && dowAllAny:
		return true
	case domAllAny:
		return c.dow&dow != 0
	case dowAllAny:
		return c.dom&dom != 0
	default:
		return c.dom&dom != 0 || c.dow&dow != 0
	}
}

// cronFullMask returns the full bitmask for a field (every
// value in [min, max]).
func cronFullMask(r fieldRange) uint64 {
	var mask uint64
	for v := r.min; v <= r.max; v++ {
		// #nosec G115 -- v is bounded by [r.min, r.max] (max 59).
		mask |= 1 << uint(v)
	}
	return mask
}

// nextScanLimitMinutes caps the Next() walk at one year. A
// schedule that doesn't fire in a year is effectively
// disabled; we'd rather return ErrCronNoMatch than spin
// forever.
const nextScanLimitMinutes = 366 * 24 * 60

// ErrCronNoMatch is returned by Next if no match is found
// within nextScanLimitMinutes of `after`.
var ErrCronNoMatch = errors.New("scanorch: cron expression has no match within 1 year")

// Next returns the smallest t' > after such that t' matches
// the cron expression. Walks minute-by-minute from after+1m,
// truncated to minute precision (sub-second components on
// `after` are dropped).
//
// Returns ErrCronNoMatch if no match is found within 1 year —
// guards against expressions that look valid but never match
// (e.g., "0 0 30 2 *" — Feb 30 doesn't exist).
func (c CronExpr) Next(after time.Time) (time.Time, error) {
	t := after.Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < nextScanLimitMinutes; i++ {
		if c.Match(t) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, ErrCronNoMatch
}

// Raw returns the original expression string. Useful for
// dashboards + audit logs.
func (c CronExpr) Raw() string { return c.raw }
