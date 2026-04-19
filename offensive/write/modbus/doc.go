//go:build offensive

// Package modbus implements Modbus/TCP writes (FC 5/6/15/16) gated by
// the offensive build tag and the triple-confirm wrapper. Reads stay
// in internal/protocols/modbus/; this package only adds mutations.
package modbus
