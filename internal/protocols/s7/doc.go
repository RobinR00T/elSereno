// Package s7 implements the ElSereno plugin for S7comm (Siemens S7
// PLCs over TPKT/COTP on port 102).
//
// The default-build probe sends a TPKT-framed COTP Connection
// Request and classifies the response: a COTP Connection Confirm
// means "this port speaks TPKT/COTP" (almost always S7 on
// port 102). Full S7 Setup Communication + read operations land
// alongside the generic REPL framework.
package s7
