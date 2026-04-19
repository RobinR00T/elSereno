//go:build offensive

// Package confirm is the single authorisation choke-point for every
// mutating operation in the offensive build. Writes, exploits,
// credential harvest, and dial all route through Authorize (ADR-039).
package confirm
