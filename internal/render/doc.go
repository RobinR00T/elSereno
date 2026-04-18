// Package render sanitises target-controlled bytes for safe presentation
// in terminals, logs, and web templates.
//
// Callers that render a banner, a modem response, or any other bytes
// that originate from a scanned host MUST pass them through SafeBytes
// before writing to a user-visible sink (conventions.md).
package render
