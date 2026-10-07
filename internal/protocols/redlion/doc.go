// Package redlion implements the ElSereno plugin for Red Lion
// Crimson v3 (CR3) on TCP/789. The default build is read-only: the
// plugin reads the manufacturer register (and then the model
// register) with the two frames of cr3-fingerprint.nse, and
// classifies a CR3 string response, falling back to canonical Red
// Lion banner substrings (Red Lion / Crimson 3 / FlexEdge / Graphite
// / DA-50N / G3 / Sixnet). No write or control frame is issued.
// Until 2026-10-07 it waited for a connect banner and sent three zero
// bytes instead (PITF-079).
package redlion
