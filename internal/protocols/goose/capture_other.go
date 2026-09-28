//go:build !linux

package goose

// OpenLiveCapture is unsupported off Linux: raw L2 capture needs an
// AF_PACKET socket. Use `goose monitor --file` with a tcpdump/tshark
// capture instead.
func OpenLiveCapture(_ string) (FrameReader, error) {
	return nil, ErrCaptureUnsupported
}
