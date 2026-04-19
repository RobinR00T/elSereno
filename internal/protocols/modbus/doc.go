// Package modbus implements the ElSereno plugin for Modbus/TCP.
//
// Default build is read-only: the probe sends FC 1 (Read Coils addr=0
// count=1) as the minimal legal Modbus read, then opportunistically
// fires FC 43 sub-code 14 (Read Device Identification) to collect
// vendor/product/revision strings when the device supports it.
//
// The proxy handler enforces the read-only policy at the wire layer:
// any PDU whose FunctionCode classifies as CategoryWrite is replaced
// with an IllegalFunction exception (FC | 0x80, exception code 0x01)
// before reaching the upstream device. FC 43 sub-codes other than 14
// are likewise rejected. Diagnostic (FC 8) is treated as
// CategoryUnknown today and passes through until F5 adds per-sub-code
// gating.
//
// Port: 502/tcp.
package modbus
