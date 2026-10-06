// Package melsoft implements the ElSereno plugin for the Mitsubishi
// Electric MELSOFT direct-connection protocol on TCP/5007. The default
// build is read-only: a single fixed "get CPU info" request is sent and
// the 16-byte ASCII CPU model name from the 0xD7-marked response is
// folded into the finding hash. No memory-device reads or writes are
// performed.
//
// MELSOFT is what GX Works2 / GX Works3 speak to a MELSEC CPU over
// Ethernet; it is distinct from SLMP (MC 3E), which uses a 0x50/0xD0
// subheader and is what the `slmp` plugin probes. A MELSEC CPU's built-in
// Ethernet port answers MELSOFT on TCP/5007 (melsecq-discover NSE, a real
// Q03UDECPU capture and secondary sources; not yet confirmed against the
// built-in-Ethernet manual). E71 Ethernet modules use TCP/5002 for MELSOFT
// (E71 manual, Appendix 2).
package melsoft
