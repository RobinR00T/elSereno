package goose

import "errors"

// ErrCaptureUnsupported is returned by OpenLiveCapture on platforms
// without raw L2 capture. Only Linux (AF_PACKET) is supported today;
// everywhere else the offline `goose monitor --file` path is the way in.
var ErrCaptureUnsupported = errors.New("goose: live L2 capture requires Linux (raw AF_PACKET socket + CAP_NET_RAW)")

// FrameReader yields raw Ethernet frames from a live L2 source. It is
// receive-only: the monitor never transmits. Close releases the socket.
//
// The concrete implementation is platform-specific (see
// capture_linux.go); OpenLiveCapture is the constructor.
type FrameReader interface {
	// Read returns the next Ethernet frame. On a poll timeout it returns
	// (nil, nil) so the caller can check for cancellation and retry; a
	// non-nil error is terminal.
	Read() ([]byte, error)
	Close() error
}
