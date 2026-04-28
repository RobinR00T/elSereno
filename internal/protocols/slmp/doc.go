// Package slmp implements the ElSereno plugin for MELSEC SLMP
// (SeamLess Message Protocol) on TCP/5007. The default build is
// read-only: a single READ CPU MODEL NAME 3E-frame request
// (command 0x0101, subcommand 0x0000) is sent and the 16-byte
// ASCII CPU model name + 2-byte CPU type code (CJ-, Q-, L-, R-,
// or F-series) are folded into the finding hash. No memory-area
// reads or writes are performed.
package slmp
