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
