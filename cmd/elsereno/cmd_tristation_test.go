package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTriStationModeFlags(t *testing.T) {
	for _, args := range [][]string{{}, {"--active", "--passive"}, {"--passive"}} {
		cmd := newTriStationCmd()
		cmd.SetArgs(args)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil {
			t.Errorf("%v: want usage error", args)
		}
	}
}

func TestTriStationPassiveRejectsGarbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.pcap")
	if err := os.WriteFile(p, []byte("not a capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newTriStationCmd()
	cmd.SetArgs([]string{"--passive", "--file", p})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "x.pcap") {
		t.Fatalf("err = %v", err)
	}
}
