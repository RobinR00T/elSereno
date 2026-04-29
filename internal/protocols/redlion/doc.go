// Package redlion implements the ElSereno plugin for Red Lion
// Crimson / RLN (Red Lion Net) on TCP/789. The default build is
// read-only: the plugin connects, optionally reads an
// unsolicited banner, falls back to a 3-byte zero hello, and
// classifies the response by canonical Red Lion banner
// substrings (Red Lion / Crimson 3 / FlexEdge / Graphite /
// DA-50N / G3 / Sixnet). No service-request frames are issued.
package redlion
