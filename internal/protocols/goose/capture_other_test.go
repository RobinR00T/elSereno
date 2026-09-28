//go:build !linux

package goose

import (
	"errors"
	"testing"
)

func TestOpenLiveCaptureUnsupported(t *testing.T) {
	_, err := OpenLiveCapture("eth0")
	if !errors.Is(err, ErrCaptureUnsupported) {
		t.Fatalf("off Linux OpenLiveCapture must return ErrCaptureUnsupported, got %v", err)
	}
}
