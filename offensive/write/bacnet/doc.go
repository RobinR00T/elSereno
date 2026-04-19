//go:build offensive

// Package bacnet implements BACnet/IP WriteProperty (confirmed
// service 0x0F) behind the offensive build tag and the triple-confirm
// wrapper. BACnet/IP is UDP; the returned bytes are a single BVLC
// datagram the caller sends via net.WriteTo.
package bacnet
