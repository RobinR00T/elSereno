//go:build offensive

// Package enip implements EtherNet/IP (CIP) writes — SendRRData
// carrying a CIP Set Attribute Single (service 0x10) against a
// chosen instance — gated by the offensive build tag and the
// triple-confirm wrapper.
package enip
