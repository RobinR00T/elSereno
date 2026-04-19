//go:build offensive

// Package s7 implements S7comm writes (WriteVar 0x05, PLC Stop 0x29,
// PLC Control 0x28 hot/cold/warm restart) gated by the offensive
// build tag and the triple-confirm wrapper. Reads stay in
// internal/protocols/s7/; this package only adds mutations.
package s7
