// Command modbus-sim is a minimal Modbus/TCP PLC simulator. It
// implements the read-only FCs (1, 2, 3, 4) against an in-memory
// bank and rejects writes, so integration tests can exercise the
// plugin and the proxy framework deterministically.
package main
