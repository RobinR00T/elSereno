package scanorch_test

import (
	"errors"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// TestParseCron_Wildcard: "* * * * *" matches every minute.
func TestParseCron_Wildcard(t *testing.T) {
	c, err := scanorch.ParseCron("* * * * *")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	at := time.Date(2026, 5, 8, 14, 23, 0, 0, time.UTC)
	if !c.Match(at) {
		t.Errorf("wildcard should match every minute")
	}
}

// TestParseCron_HourlyTopOfHour: "0 * * * *" matches XX:00.
func TestParseCron_HourlyTopOfHour(t *testing.T) {
	c, _ := scanorch.ParseCron("0 * * * *")
	atZero := time.Date(2026, 5, 8, 14, 0, 0, 0, time.UTC)
	atOne := time.Date(2026, 5, 8, 14, 1, 0, 0, time.UTC)
	if !c.Match(atZero) {
		t.Errorf("0 * * * * should match :00")
	}
	if c.Match(atOne) {
		t.Errorf("0 * * * * should NOT match :01")
	}
}

// TestParseCron_Daily0200: "0 2 * * *" matches 02:00 daily.
func TestParseCron_Daily0200(t *testing.T) {
	c, _ := scanorch.ParseCron("0 2 * * *")
	at := time.Date(2026, 5, 8, 2, 0, 0, 0, time.UTC)
	atOff := time.Date(2026, 5, 8, 3, 0, 0, 0, time.UTC)
	if !c.Match(at) {
		t.Errorf("0 2 * * * should match 02:00")
	}
	if c.Match(atOff) {
		t.Errorf("0 2 * * * should NOT match 03:00")
	}
}

// TestParseCron_CommaList: "0,15,30,45 * * * *" matches every
// quarter hour.
func TestParseCron_CommaList(t *testing.T) {
	c, _ := scanorch.ParseCron("0,15,30,45 * * * *")
	for _, m := range []int{0, 15, 30, 45} {
		at := time.Date(2026, 5, 8, 14, m, 0, 0, time.UTC)
		if !c.Match(at) {
			t.Errorf("should match :%02d", m)
		}
	}
	for _, m := range []int{1, 16, 31, 46} {
		at := time.Date(2026, 5, 8, 14, m, 0, 0, time.UTC)
		if c.Match(at) {
			t.Errorf("should NOT match :%02d", m)
		}
	}
}

// TestParseCron_Range: "0 9-17 * * 1-5" matches business
// hours weekdays.
func TestParseCron_Range(t *testing.T) {
	c, _ := scanorch.ParseCron("0 9-17 * * 1-5")
	// Monday May 4 2026 is a weekday.
	mondayMidday := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	if !c.Match(mondayMidday) {
		t.Errorf("Monday 12:00 should match")
	}
	// Saturday May 9 2026 — should NOT match (dow=6).
	saturdayMidday := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	if c.Match(saturdayMidday) {
		t.Errorf("Saturday 12:00 should NOT match")
	}
	// Monday 08:00 — outside 9-17 range.
	mondayMorning := time.Date(2026, 5, 4, 8, 0, 0, 0, time.UTC)
	if c.Match(mondayMorning) {
		t.Errorf("Monday 08:00 should NOT match (outside 9-17)")
	}
}

// TestParseCron_Step: "*/5 * * * *" matches every 5 minutes.
func TestParseCron_Step(t *testing.T) {
	c, _ := scanorch.ParseCron("*/5 * * * *")
	for _, m := range []int{0, 5, 10, 15, 20, 55} {
		at := time.Date(2026, 5, 8, 14, m, 0, 0, time.UTC)
		if !c.Match(at) {
			t.Errorf(":%02d should match", m)
		}
	}
	for _, m := range []int{1, 2, 7, 11} {
		at := time.Date(2026, 5, 8, 14, m, 0, 0, time.UTC)
		if c.Match(at) {
			t.Errorf(":%02d should NOT match", m)
		}
	}
}

// TestParseCron_DOM_DOW_OrSemantic: when both day fields are
// restricted, EITHER matching is sufficient (Unix cron
// semantic).
func TestParseCron_DOM_DOW_OrSemantic(t *testing.T) {
	// Match every 1st OR every Monday.
	c, _ := scanorch.ParseCron("0 0 1 * 1")
	monday := time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC) // Monday, not the 1st
	first := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)  // 1st, but not Monday
	neither := time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC)
	if !c.Match(monday) {
		t.Errorf("Monday should match (dow=1)")
	}
	if !c.Match(first) {
		t.Errorf("1st should match (dom=1)")
	}
	if c.Match(neither) {
		t.Errorf("non-Monday non-1st should NOT match")
	}
}

// TestParseCron_WrongFieldCount.
func TestParseCron_WrongFieldCount(t *testing.T) {
	for _, expr := range []string{"", "*", "* *", "* * * *", "* * * * * *"} {
		_, err := scanorch.ParseCron(expr)
		if !errors.Is(err, scanorch.ErrCronWrongFieldCount) {
			t.Errorf("%q: err = %v, want ErrCronWrongFieldCount", expr, err)
		}
	}
}

// TestParseCron_InvalidField.
func TestParseCron_InvalidField(t *testing.T) {
	for _, expr := range []string{
		"abc * * * *",  // non-numeric minute
		"60 * * * *",   // out of range
		"* 24 * * *",   // hour out of range
		"* * 0 * *",    // dom < 1
		"* * 32 * *",   // dom > 31
		"* * * 13 *",   // month > 12
		"* * * * 7",    // dow > 6
		"5-2 * * * *",  // backwards range
		"*/0 * * * *",  // step zero
		"*/-1 * * * *", // negative step
	} {
		_, err := scanorch.ParseCron(expr)
		if !errors.Is(err, scanorch.ErrCronInvalidField) {
			t.Errorf("%q: err = %v, want ErrCronInvalidField", expr, err)
		}
	}
}

// TestParseCron_Next: "0 2 * * *" — next fire after midnight
// is 02:00 same day.
func TestParseCron_Next(t *testing.T) {
	c, _ := scanorch.ParseCron("0 2 * * *")
	after := time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)
	got, err := c.Next(after)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := time.Date(2026, 5, 8, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next = %v, want %v", got, want)
	}
}

// TestParseCron_Next_AfterDailyTrigger: at 02:01, next fire
// is tomorrow 02:00.
func TestParseCron_Next_AfterDailyTrigger(t *testing.T) {
	c, _ := scanorch.ParseCron("0 2 * * *")
	after := time.Date(2026, 5, 8, 2, 1, 0, 0, time.UTC)
	got, _ := c.Next(after)
	want := time.Date(2026, 5, 9, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next = %v, want %v", got, want)
	}
}

// TestParseCron_Next_WeekdaysOnly: "0 9 * * 1-5" — after a
// Friday 17:00, next fire is Monday 09:00.
func TestParseCron_Next_WeekdaysOnly(t *testing.T) {
	c, _ := scanorch.ParseCron("0 9 * * 1-5")
	// Friday May 8 2026, 17:00.
	after := time.Date(2026, 5, 8, 17, 0, 0, 0, time.UTC)
	got, _ := c.Next(after)
	// Monday May 11 2026, 09:00.
	want := time.Date(2026, 5, 11, 9, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next = %v, want %v (Monday 09:00)", got, want)
	}
}

// TestParseCron_Next_NoMatch: "0 0 30 2 *" — Feb 30 doesn't
// exist, so Next eventually gives up with ErrCronNoMatch.
func TestParseCron_Next_NoMatch(t *testing.T) {
	c, _ := scanorch.ParseCron("0 0 30 2 *")
	after := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := c.Next(after)
	if !errors.Is(err, scanorch.ErrCronNoMatch) {
		t.Errorf("err = %v, want ErrCronNoMatch", err)
	}
}

// TestParseCron_Raw round-trips the original string.
func TestParseCron_Raw(t *testing.T) {
	expr := "*/5 9-17 * * 1-5"
	c, _ := scanorch.ParseCron(expr)
	if c.Raw() != expr {
		t.Errorf("Raw() = %q, want %q", c.Raw(), expr)
	}
}

// TestParseCron_TruncatesSubMinute: Next() on a t with seconds
// returns a clean minute-aligned time.
func TestParseCron_TruncatesSubMinute(t *testing.T) {
	c, _ := scanorch.ParseCron("* * * * *")
	after := time.Date(2026, 5, 8, 14, 23, 47, 999_000, time.UTC)
	got, _ := c.Next(after)
	want := time.Date(2026, 5, 8, 14, 24, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next = %v, want %v (minute-aligned)", got, want)
	}
}
