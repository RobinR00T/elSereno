package exec_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"local/elsereno/internal/exec"
)

func TestValidateFlagsRejectsMetachars(t *testing.T) {
	cases := []string{
		"-x;rm -rf /",
		"-x|cat",
		"-x&whoami",
		"-x$IFS",
		"-x`id`",
		"-x\nnewline",
		"-x\x00nul",
		"noleading-dash",
		"",
	}
	for _, f := range cases {
		_, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
			Name:         "true",
			Flags:        []string{f},
			AllowedPaths: []string{"/usr/bin", "/bin"},
		})
		if err == nil {
			t.Fatalf("expected error for flag %q", f)
		}
		if !errors.Is(err, exec.ErrInvalidFlag) {
			t.Fatalf("flag %q: got %v, want ErrInvalidFlag", f, err)
		}
	}
}

func TestPositionalsUseDefaultValidator(t *testing.T) {
	_, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
		Name:         "true",
		Positional:   []string{"safe-value", "also;bad"},
		AllowedPaths: []string{"/usr/bin", "/bin"},
	})
	if !errors.Is(err, exec.ErrInvalidPositional) {
		t.Fatalf("got %v, want ErrInvalidPositional", err)
	}
}

func TestDisallowedPath(t *testing.T) {
	// Pick something that exists but lives in an unusual path.
	_, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
		Name:         "go", // resolves to /opt/homebrew/... likely
		AllowedPaths: []string{"/nonexistent"},
	})
	if err == nil {
		t.Fatal("expected ErrDisallowedPath")
	}
	if !errors.Is(err, exec.ErrDisallowedPath) && !strings.Contains(err.Error(), "LookPath") {
		// LookPath failure is also an acceptable terminal state when the
		// binary isn't on PATH at all (CI may differ).
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSeparatorIsAlwaysPresent(t *testing.T) {
	cmd, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
		Name:         "true",
		Flags:        []string{"-q"},
		Positional:   []string{"arg1"},
		AllowedPaths: []string{"/usr/bin", "/bin"},
	})
	if err != nil {
		t.Skipf("skipping: %v (depends on /usr/bin/true being present)", err)
	}
	// cmd.Args = [binary, -q, --, arg1]
	if len(cmd.Args) < 4 {
		t.Fatalf("unexpected argv: %v", cmd.Args)
	}
	found := false
	for _, a := range cmd.Args {
		if a == "--" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("-- separator missing in %v", cmd.Args)
	}
}

// --- --no-allowlist bypass (ADR-039 escape hatch, F5) ---

type captureBypass struct {
	events []exec.BypassEvent
	fail   error
}

func (c *captureBypass) RecordBypass(ev exec.BypassEvent) error {
	if c.fail != nil {
		return c.fail
	}
	c.events = append(c.events, ev)
	return nil
}

func TestBypass_RequiresAuditor(t *testing.T) {
	_, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
		Name:         "sh", // most systems have this somewhere
		AllowAnyPath: true,
	})
	if !errors.Is(err, exec.ErrBypassAuditRequired) {
		t.Fatalf("want ErrBypassAuditRequired, got %v", err)
	}
}

// #nosec G101 -- false positive — test struct literal with no secrets
func TestBypass_RecordsEvent(t *testing.T) {
	cb := &captureBypass{}
	_, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
		Name:          "sh",
		AllowAnyPath:  true,
		BypassReason:  "operator-run test helper",
		Actor:         "test-actor",
		BypassAuditor: cb,
	})
	if err != nil {
		t.Fatalf("SafeCommand: %v", err)
	}
	if len(cb.events) != 1 {
		t.Fatalf("events: %+v", cb.events)
	}
	ev := cb.events[0]
	if ev.Actor != "test-actor" || ev.Reason != "operator-run test helper" {
		t.Fatalf("event fields: %+v", ev)
	}
	if !strings.HasSuffix(ev.Binary, "/sh") {
		t.Fatalf("binary = %q", ev.Binary)
	}
}

func TestBypass_DefaultReasonUnspecified(t *testing.T) {
	cb := &captureBypass{}
	_, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
		Name:          "sh",
		AllowAnyPath:  true,
		BypassAuditor: cb,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cb.events[0].Reason != "unspecified" {
		t.Fatalf("reason = %q", cb.events[0].Reason)
	}
}

func TestBypass_AuditFailureAborts(t *testing.T) {
	cb := &captureBypass{fail: errors.New("chain broken")}
	_, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
		Name:          "sh",
		AllowAnyPath:  true,
		BypassAuditor: cb,
	})
	if err == nil {
		t.Fatal("expected error when auditor fails")
	}
	if !strings.Contains(err.Error(), "chain broken") {
		t.Fatalf("err should wrap auditor error: %v", err)
	}
}

func TestBypass_NormalPathStillAllowlisted(t *testing.T) {
	// Without AllowAnyPath, a binary outside allowed paths must fail
	// with ErrDisallowedPath — bypass is strictly opt-in.
	_, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
		Name:         "sh",
		AllowedPaths: []string{"/does-not-exist"},
	})
	if !errors.Is(err, exec.ErrDisallowedPath) {
		t.Fatalf("want ErrDisallowedPath, got %v", err)
	}
}
