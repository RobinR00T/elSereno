// Package atmodem implements the ElSereno plugin for AT-over-TCP
// modems (Hayes, GSM, and EN 81-28 lift interphones).
//
// Default build is read-only: probe (AT, ATI, AT+CGMI) + fingerprint
// classification + an REPL that refuses dial/SMS/write commands.
// The proxy handler blocks ATD*, ATA, AT+CMGS, AT+CMGW, AT+CMSS,
// AT+CMGD, AT+CFUN, AT+CPWROFF, and the '+++' escape sequence
// (conventions.md). Offensive dial + SMS + phonebook-dump + at-raw
// arrive in F5 behind `-tags offensive` with --dial-allowed + triple
// confirm + hard-coded ≤3-digit block (PITF-016, LEGAL.md).
//
// Probed ports (brief section 7 F2b): 23, 7, 2001-2032, 3001,
// 4001-4009, 9999, 10001-10004/tcp.
package atmodem
