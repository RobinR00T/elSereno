//go:build !mini

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"local/elsereno/internal/tui/feeds"
)

// TestPickFeed_ReplayPropagatesRate — v1.43 pin. The
// --rate flag plumbs through to the feed's Rate field so
// the streamNDJSON pacer slows playback as advertised.
func TestPickFeed_ReplayPropagatesRate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.ndjson")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, feed, err := pickFeed(context.Background(), pickFeedArgs{
		replayPath: path,
		rate:       50,
	})
	if err != nil {
		t.Fatalf("pickFeed: %v", err)
	}
	r, ok := feed.(feeds.Replay)
	if !ok {
		t.Fatalf("got %T, want feeds.Replay", feed)
	}
	if r.Rate != 50 {
		t.Errorf("Rate = %v, want 50", r.Rate)
	}
	if r.Path != path {
		t.Errorf("Path = %q, want %q", r.Path, path)
	}
}

// TestPickFeed_StdinPropagatesRate — same shape for the
// --feed - path.
func TestPickFeed_StdinPropagatesRate(t *testing.T) {
	_, feed, err := pickFeed(context.Background(), pickFeedArgs{
		feedFlag: "-",
		rate:     20,
	})
	if err != nil {
		t.Fatalf("pickFeed: %v", err)
	}
	s, ok := feed.(feeds.Stdin)
	if !ok {
		t.Fatalf("got %T, want feeds.Stdin", feed)
	}
	if s.Rate != 20 {
		t.Errorf("Rate = %v, want 20", s.Rate)
	}
}

// TestPickFeed_RateZeroIsUnlimited — default 0 leaves the
// pacer disabled (back-compat with pre-v1.43 behaviour).
func TestPickFeed_RateZeroIsUnlimited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.ndjson")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, feed, err := pickFeed(context.Background(), pickFeedArgs{replayPath: path})
	if err != nil {
		t.Fatalf("pickFeed: %v", err)
	}
	r, ok := feed.(feeds.Replay)
	if !ok {
		t.Fatalf("got %T, want feeds.Replay", feed)
	}
	if r.Rate != 0 {
		t.Errorf("Rate = %v, want 0 (unbounded)", r.Rate)
	}
}
