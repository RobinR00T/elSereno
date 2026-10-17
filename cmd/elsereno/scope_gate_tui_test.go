//go:build !mini

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"local/elsereno/internal/core"
)

func tuiInputFeedErr(t *testing.T, input, scopePath string) error {
	t.Helper()
	_, err := buildInteractiveFeed(context.Background(), input, 0, "", scopePath)
	return err
}

func tuiAbsent() bool { return false }

// TestScope_TUIInputExitCodes: tui --input keeps the exit code of each
// scope refusal (until the audit of PITF-095 every one came out as 64).
func TestScope_TUIInputExitCodes(t *testing.T) {
	dir, outOfRange := scopeTestEnv(t, outOfRangeScope)
	list := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(list, []byte("127.0.0.1:502\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		scope string
		want  core.ExitCode
	}{
		{outOfRange, core.ExitNoInput},
		{write("broken.yaml", "version: 1\nrangez: []\n"), core.ExitConfig},
		{write("nobanner.yaml", "version: 1\nprotocols:\n  allow: [modbus]\n"), core.ExitNoPerm},
	}
	for _, c := range cases {
		if got := exitCode(runRoot(t, "tui", "--input", "list:"+list, "--scope", c.scope)); got != c.want {
			t.Errorf("tui --input with %s: exit %d, want %d", filepath.Base(c.scope), got, c.want)
		}
	}
}
