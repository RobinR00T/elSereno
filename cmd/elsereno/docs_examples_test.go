//go:build !mini

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestDocsExamples_UseRealCommandsAndFlags: every `elsereno ...` command
// in the user docs (fenced code blocks of the Markdown files, every line
// of the cheat sheet) must name commands that exist, are not "planned"
// stubs, and flags the command accepts. Until 2026-10-17 the docs held
// 44 that did not: `scan --input-file`, `creds store --name`, `backup
// create --output`, `gen-man --output` (a stub), `audit show`, and
// more; an operator copying them got "unknown flag" (PITF-091). Commands
// that exist only in the offensive build are checked by the offensive
// run of this test (CI runs `go test -tags offensive ./...`).
//
// Not checked: CHANGELOG, ROADMAP, TODO-vNext and .context/ (history and
// plans), and commands whose path goes through a placeholder such as
// `write <proto> send`.
func TestDocsExamples_UseRealCommandsAndFlags(t *testing.T) {
	root := newRootCmd()
	repo := filepath.Join("..", "..")
	var files []string
	for _, pattern := range []string{"*.md", "docs/*.md", "docs/*/*.md", "docs/manual/*.txt", "man/src/*/*.md"} {
		m, err := filepath.Glob(filepath.Join(repo, pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	skip := map[string]bool{"CHANGELOG.md": true, "ROADMAP.md": true, "TODO-vNext.md": true}

	checked := 0
	for _, f := range files {
		rel, _ := filepath.Rel(repo, f)
		if skip[rel] {
			continue
		}
		for _, ex := range docExamples(t, f) {
			checked++
			for _, problem := range checkExample(root, ex.cmd) {
				t.Errorf("%s:%d: %s: %s", rel, ex.line, strings.TrimSpace(ex.cmd), problem)
			}
		}
	}
	if checked < 250 {
		t.Fatalf("only %d examples found; the extractor is broken", checked)
	}
}

type docExample struct {
	line int
	cmd  string
}

var (
	// The binary as a command: bare, by path (./bin/elsereno) or by its
	// release name (elsereno-offensive, elsereno-mini).
	exampleStart = regexp.MustCompile(`(?:^|[\s$|(;&])(?:[.~\w/-]*/)?elsereno(?:-offensive|-mini)?(\s+[a-z][\w-]*)+`)
	// A command ends at a pipe, a list operator, a redirect or a comment.
	exampleEnd = regexp.MustCompile(`\s(?:\||&&|;|>|2>|#)`)
	longFlag   = regexp.MustCompile(`(?:^|\s)--([a-z][a-z0-9-]*)`)
)

// docExamples returns the `elsereno ...` commands of a file: inside
// fenced code blocks for Markdown, on any line for plain text, with
// backslash continuations joined.
func docExamples(t *testing.T, path string) []docExample {
	t.Helper()
	fh, err := os.Open(path) // #nosec G304 -- repo docs listed by Glob
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	var lines []string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	markdown := strings.HasSuffix(path, ".md")
	var out []docExample
	inFence := false
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			inFence = !inFence
			continue
		}
		if markdown && !inFence {
			continue
		}
		loc := exampleStart.FindStringIndex(l)
		if loc == nil || !commandPosition(l[:loc[0]]) {
			continue // no command, or a mention in prose, a comment or a diagram
		}
		start, cmd := i, l[loc[0]:]
		for strings.HasSuffix(strings.TrimRight(cmd, " "), `\`) && i+1 < len(lines) {
			i++
			cmd = strings.TrimSuffix(strings.TrimRight(cmd, " "), `\`) + " " + lines[i]
		}
		if end := exampleEnd.FindStringIndex(cmd); end != nil {
			cmd = cmd[:end[0]]
		}
		out = append(out, docExample{line: start + 1, cmd: cmd})
	}
	return out
}

// commandPosition reports whether text before a match leaves it where a
// shell would run it: at the start of the line, after a prompt, sudo, a
// pipe or list operator, or an opening parenthesis.
func commandPosition(before string) bool {
	b := strings.TrimSpace(before)
	if b == "" {
		return true
	}
	for _, suffix := range []string{"$", "|", "&&", ";", "(", "sudo", "!", "time"} {
		if strings.HasSuffix(b, suffix) {
			return true
		}
	}
	return false
}

// offensiveOnly lists the top-level commands that exist only in the
// offensive build; `proxy` has subcommands only there.
var offensiveOnly = map[string]bool{
	"creds-check": true, "dial": true, "exploit": true, "harvest": true, "sandbox": true, "write": true,
}

// checkExample resolves the command path of one example and reports
// what does not exist: an unknown subcommand, a "planned" stub, or a
// flag the command does not accept.
func checkExample(root *cobra.Command, example string) []string {
	words := strings.Fields(example)[1:] // drop the binary token (elsereno, ./bin/elsereno, elsereno-offensive)
	if len(words) == 0 {
		return nil
	}
	if !offensiveBuild && (offensiveOnly[words[0]] || (words[0] == "proxy" && len(words) > 1 && !strings.HasPrefix(words[1], "-"))) {
		return nil
	}
	if findSub(root, words[0]) == nil {
		return []string{"unknown command " + words[0]}
	}
	cmd := root
	for _, w := range words {
		if strings.HasPrefix(w, "-") {
			break
		}
		if strings.HasPrefix(w, "<") || strings.HasPrefix(w, "{") {
			return nil // placeholder: the path cannot be resolved
		}
		next := findSub(cmd, w)
		if next == nil {
			if cmd.HasSubCommands() && !cmd.Runnable() {
				return []string{"unknown subcommand " + w + " of " + cmd.CommandPath()}
			}
			break // a positional argument
		}
		cmd = next
	}
	if cmd == root {
		return nil
	}
	var problems []string
	if cmd.Annotations[stubAnnotation] != "" {
		problems = append(problems, cmd.CommandPath()+" does nothing yet ("+cmd.Annotations[stubAnnotation]+")")
	}
	for _, m := range longFlag.FindAllStringSubmatch(example, -1) {
		name := m[1]
		if name == "help" {
			continue
		}
		if cmd.Flags().Lookup(name) == nil && cmd.InheritedFlags().Lookup(name) == nil {
			problems = append(problems, "unknown flag --"+name+" for "+cmd.CommandPath())
		}
	}
	return problems
}

func findSub(c *cobra.Command, name string) *cobra.Command {
	for _, sub := range c.Commands() {
		if sub.Name() == name || sub.HasAlias(name) {
			return sub
		}
	}
	return nil
}
