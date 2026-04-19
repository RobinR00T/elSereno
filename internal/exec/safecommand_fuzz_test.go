package exec_test

import (
	"context"
	"strings"
	"testing"

	"local/elsereno/internal/exec"
)

// FuzzFlagValidationRejectsShellMeta: any flag containing a shell
// metacharacter, newline, carriage return, nul, or backtick must be
// rejected. Any flag not starting with '-' must also be rejected.
func FuzzFlagValidationRejectsShellMeta(f *testing.F) {
	f.Add("-q")
	f.Add("--config=/etc/foo")
	f.Add("-p502")
	f.Add("-x;rm -rf /")
	f.Add("noleading")
	f.Add("")
	f.Fuzz(func(t *testing.T, flag string) {
		_, err := exec.SafeCommand(context.Background(), exec.CommandSpec{
			Name:         "true",
			Flags:        []string{flag},
			AllowedPaths: []string{"/usr/bin", "/bin"},
		})
		hasMeta := strings.ContainsAny(flag, ";|&$`\n\r\x00")
		badPrefix := !strings.HasPrefix(flag, "-") || flag == ""
		if hasMeta || badPrefix {
			if err == nil {
				t.Fatalf("expected rejection of %q", flag)
			}
		}
	})
}
