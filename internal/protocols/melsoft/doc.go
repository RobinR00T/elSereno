// Package melsoft implements the ElSereno plugin for the Mitsubishi
// Electric MELSOFT communication protocol on TCP/5007. The default
// build is read-only: a single fixed "get CPU info" request is sent and
// the 16-byte ASCII CPU model name from the 0xD7-marked response is
// folded into the finding hash. No memory-device reads or writes are
// performed.
//
// MELSOFT is what GX Works2 / GX Works3 speak to a MELSEC CPU over
// Ethernet; it is distinct from SLMP (MC 3E), which uses a 0x50/0xD0
// subheader and is what the `slmp` plugin probes. On a QnUCPU built-in
// Ethernet port, TCP/5007 is the system's "MELSOFT communication port
// (TCP/IP)" (Mitsubishi SH(NA)-080811ENG, Appendix 2, which also lists
// 5006/UDP and 5008, the "MELSOFT direct connection port"); iQ-R lists the
// same numbers (secondary: the pymelsec README table). E71 Ethernet modules
// use TCP/5002 for MELSOFT instead (LJ71E71 manual, Appendix 2).
package melsoft
