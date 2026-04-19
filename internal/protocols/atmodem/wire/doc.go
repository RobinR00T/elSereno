// Package wire parses AT-modem responses into a small state machine.
//
// AT responses are line-oriented with a handful of terminal result
// codes: OK, ERROR, CONNECT, NO CARRIER, NO DIALTONE, BUSY, NO ANSWER,
// RING, and the GSM extended errors +CME ERROR: <n> / +CMS ERROR: <n>.
// Any other line is a payload line (informational / echo / +COMMAND).
//
// The parser treats CR/LF permissively (either is a line separator),
// drops command echoes when requested, and caps total response size
// so an adversary cannot blow memory (MaxResponseBytes).
package wire
