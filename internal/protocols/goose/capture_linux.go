//go:build linux

package goose

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// ethPAll is ETH_P_ALL: capture every EtherType off the wire. GOOSE/SV
// frames are then filtered by Dissect (which returns ErrNotSubstation
// for anything else), so a mixed segment is handled without a kernel
// BPF filter.
const ethPAll = 0x0003

// htons converts a uint16 to network byte order (AF_PACKET wants the
// protocol in big-endian both in Socket() and in the bind address).
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// maxCaptureFrame bounds a single read. Jumbo frames aside, GOOSE/SV
// frames are well under a standard 1500-byte MTU; 65536 is generous.
const maxCaptureFrame = 65536

// liveCapture is a read-only AF_PACKET raw socket bound to one interface.
type liveCapture struct {
	fd    int
	iface string
}

// OpenLiveCapture opens a receive-only AF_PACKET raw socket bound to
// iface. It requires CAP_NET_RAW (run as root or grant the capability).
// The socket is never written to: this is passive monitoring only.
func OpenLiveCapture(iface string) (FrameReader, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("goose: interface %q: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("goose: open AF_PACKET socket (need CAP_NET_RAW): %w", err)
	}
	sll := &unix.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifi.Index}
	if err := unix.Bind(fd, sll); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("goose: bind %q: %w", iface, err)
	}
	// 1s receive timeout: Read returns (nil,nil) each idle second so the
	// caller can honour context cancellation between frames.
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("goose: set recv timeout: %w", err)
	}
	return &liveCapture{fd: fd, iface: iface}, nil
}

// Read returns the next frame, or (nil, nil) on the 1s poll timeout.
func (c *liveCapture) Read() ([]byte, error) {
	buf := make([]byte, maxCaptureFrame)
	n, _, err := unix.Recvfrom(c.fd, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
			return nil, nil // idle poll tick, not an error
		}
		return nil, err
	}
	if n < 0 {
		return nil, nil
	}
	return buf[:n], nil
}

// Close releases the socket.
func (c *liveCapture) Close() error { return unix.Close(c.fd) }
