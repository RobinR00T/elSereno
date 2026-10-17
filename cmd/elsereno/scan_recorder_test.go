//go:build !mini

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanorch"
)

// fakeRecorder keeps what the runner hands it.
type fakeRecorder struct {
	mu        sync.Mutex
	started   int
	findings  []core.Target
	status    string
	counts    map[string]int
	recordErr error
	startErr  error
}

func (f *fakeRecorder) Start(context.Context, scanorch.Job) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started++
	if f.startErr != nil {
		return "", f.startErr
	}
	return "run-1", nil
}

func (f *fakeRecorder) Record(_ context.Context, runID string, _ core.Finding, t core.Target) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if runID != "run-1" {
		return errors.New("wrong run id")
	}
	if f.recordErr != nil {
		return f.recordErr
	}
	f.findings = append(f.findings, t)
	return nil
}

func (f *fakeRecorder) Finish(_ context.Context, _ string, status string, counts map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.counts = status, counts
}

// listTargets starts n loopback listeners that accept and close, and
// writes them to a list file.
func listTargets(t *testing.T, n int) string {
	t.Helper()
	var lines []byte
	for i := 0; i < n; i++ {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		lines = append(lines, []byte(ln.Addr().String()+"\n")...)
	}
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, lines, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestScanRunner_RecordsFindings: a dashboard scan's findings reach the
// recorder with the target each was probed on, and the run is closed
// with its status and severity counts. Until 2026-10-17 the runner only
// counted them (PITF-094).
func TestScanRunner_RecordsFindings(t *testing.T) {
	list := listTargets(t, 2)
	rec := &fakeRecorder{}
	r := &defaultScanRunner{recorder: rec}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stats, _, err := r.Run(ctx, scanorch.Job{ID: "j", Input: "list:" + list, Plugins: []string{"banner"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.started != 1 || len(rec.findings) != stats.FindingsCount || stats.FindingsCount != 2 {
		t.Fatalf("started %d, recorded %d, counted %d; want 1, 2, 2", rec.started, len(rec.findings), stats.FindingsCount)
	}
	for _, tg := range rec.findings {
		if !tg.Address.IsLoopback() || tg.Port == 0 {
			t.Errorf("finding recorded without its target: %+v", tg)
		}
	}
	if rec.status != "completed" {
		t.Errorf("run closed as %q, want completed", rec.status)
	}
	total := 0
	for _, n := range rec.counts {
		total += n
	}
	if total != 2 {
		t.Errorf("severity counts %v add up to %d, want 2", rec.counts, total)
	}
}

// TestScanRunner_StopsWhenFindingsCannotBeKept: the first failed write
// fails the job and closes the run as error, as the CLI stops on a
// write error: probing on while nothing can be kept is wasted traffic.
func TestScanRunner_StopsWhenFindingsCannotBeKept(t *testing.T) {
	list := listTargets(t, 1)
	rec := &fakeRecorder{recordErr: errors.New("disk full")}
	r := &defaultScanRunner{recorder: rec}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _, err := r.Run(ctx, scanorch.Job{ID: "j", Input: "list:" + list, Plugins: []string{"banner"}}, nil)
	if err == nil {
		t.Fatal("Run succeeded although no finding could be recorded")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.status != "error" {
		t.Errorf("run closed as %q, want error", rec.status)
	}
}
