// Package mbustcp implements the ElSereno plugin for M-Bus
// (Meter Bus) over TCP per EN 13757-3 + EN 13757-4. The default
// build is read-only: a single REQ_UD2 short frame is sent to
// the broadcast primary address (0xFE) and the resulting RSP_UD
// long frame is parsed for the meter's manufacturer code +
// medium byte + version. No SND_UD writes are performed.
package mbustcp
