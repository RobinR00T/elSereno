// Package gesrtp implements the ElSereno plugin for GE-SRTP (GE
// Service Request Transfer Protocol) on TCP/18245. The default
// build is read-only: a single 56-byte CONNECTION INIT mailbox
// is sent and the response classified by the SRTP type byte
// (0x03 = response). No memory-area reads, program-block reads,
// or service-request writes are performed.
package gesrtp
