// Package xot implements the ElSereno plugin for XOT (X.25 over TCP,
// RFC 1613). The default build ships the read-only surface: probe a
// target and classify the response (Clear Indication cause/diag,
// Restart Indication, or Call Accepted). The REPL and proxy are
// skeletons over the wire/ parser; protocol-specific dial semantics
// live behind the offensive build tag in F5.
//
// Port: 1998/tcp.
package xot
