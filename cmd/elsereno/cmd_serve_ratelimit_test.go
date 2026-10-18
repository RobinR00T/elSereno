//go:build !mini

package main

import (
	"testing"

	"local/elsereno/internal/config"
)

// TestRateLimitBanner: serve states the caps it enforces, and a zero cap
// reads "off" (PITF-100).
func TestRateLimitBanner(t *testing.T) {
	cases := []struct {
		ip, tok int
		want    string
	}{
		{100, 300, "elsereno serve: rate limits per IP 100/min (loopback exempt), per token 300/min"},
		{0, 300, "elsereno serve: rate limits per IP off, per token 300/min"},
		{0, 0, "elsereno serve: rate limits per IP off, per token off"},
	}
	for _, c := range cases {
		got := rateLimitBanner(config.WebConfig{RateLimitPerMinIP: c.ip, RateLimitPerMinToken: c.tok})
		if got != c.want {
			t.Errorf("rateLimitBanner(%d, %d) = %q, want %q", c.ip, c.tok, got, c.want)
		}
	}
	if got := rateLimitBanner(config.Defaults().Web); got != cases[0].want {
		t.Errorf("defaults: %q, want %q", got, cases[0].want)
	}
}
