//go:build !mini

// Package tui implements `elsereno tui` — the interactive
// terminal UI for the ElSereno scanner. Built on
// charmbracelet/bubbletea + bubbles + lipgloss.
//
// The TUI exists as a complement to (not a replacement for) the
// existing batch CLI verbs. Operators who want pipeline /
// scriptable workflows continue using `elsereno scan --output
// ndjson | jq …`; the TUI is for interactive sessions where
// you want to watch findings stream in, navigate the triage
// buckets, and accept writes from a single screen.
//
// Four modes are supported, all sharing the same Model / View /
// Update implementation:
//
//   - **interactive**: `elsereno tui`. The TUI drives a fresh
//     scan from inside (lanzas con `s`, observas progreso +
//     findings + triage en vivo).
//   - **replay**: `elsereno tui --replay FILE.ndjson`. Reads a
//     pre-recorded NDJSON file (the same format `elsereno scan
//     --output-format ndjson` writes) + presents it through the
//     full UI for post-batch review.
//   - **feed**: `elsereno tui --feed -`. Consumes NDJSON from
//     stdin live; pairs naturally with `elsereno scan ...
//     --output-format ndjson | elsereno tui --feed -`.
//   - **watch**: `elsereno tui --watch http://host:8787/api/v1/stream
//     --bearer TOKEN`. Read-only consumer of the dashboard's SSE
//     broadcaster — useful for SOC operators watching from a
//     secondary terminal while another runs scans.
//
// All four modes use the same bubbletea Model. Switching is a
// startup decision; once the TUI is running it doesn't matter
// which feed populated the state.
//
// Build tag: `//go:build !mini`. The mini variant excludes the
// TUI + its bubbletea / bubbles / lipgloss / termenv
// dependencies (~5-8 MB binary saving).
package tui
