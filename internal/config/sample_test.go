package config_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"local/elsereno/internal/config"
)

// exampleLine matches a commented YAML line of the sample: "# key:",
// "#   key: value" or "#   - item".
var exampleLine = regexp.MustCompile(`^#( *[a-z_]+:( |$)| +- )`)

// TestPackagedSample_Loads: the sample the package installs as
// /etc/elsereno/elsereno.yaml loads as shipped and with every example
// uncommented. Until 2026-10-17 it showed keys that do not exist
// (web.listen, web.tls, database.url, audit.*, scanner.base_backoff),
// each an exit 78 once uncommented (audit of PITF-096).
func TestPackagedSample_Loads(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "packaging", "configs", "elsereno.yaml.sample"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	examples := 0
	for _, l := range strings.Split(string(raw), "\n") {
		if exampleLine.MatchString(l) {
			lines = append(lines, strings.TrimPrefix(l, "# "))
			examples++
		}
	}
	if examples < 10 {
		t.Fatalf("only %d example lines found; the pattern no longer matches the sample", examples)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"shipped.yaml": string(raw), "uncommented.yaml": strings.Join(lines, "\n") + "\n"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := config.NewLoader(config.LookupOrder{Explicit: p}).Load(context.Background()); err != nil {
			t.Errorf("%s does not load: %v\n%s", name, err, body)
		}
	}
}
