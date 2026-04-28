// Package finsudp implements the ElSereno plugin for Omron FINS
// (Factory Interface Network Service) on UDP/9600. The default
// build is read-only: a single CONTROLLER DATA READ request
// (MRC=0x05, SRC=0x01) is sent and the controller model
// (CJ/CS/CP/NJ/NX) is folded into the finding hash. No memory-area
// reads or writes are performed.
package finsudp
