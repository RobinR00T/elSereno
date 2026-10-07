// Package gesrtp implements the ElSereno plugin for GE-SRTP (GE
// Service Request Transfer Protocol) on TCP/18245. The default
// build is read-only: a 56-byte all-zero CONNECTION INIT mailbox is
// sent and the reply classified by its type byte (0x01 = init
// accepted); on a positive init one 0x21 Read PLC Long Status
// follows and its 0x03 operation reply is scanned for a model and a
// firmware version. No memory-area or program-block access and no
// writes.
package gesrtp
