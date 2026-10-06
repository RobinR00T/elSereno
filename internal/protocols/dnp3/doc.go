// Package dnp3 implements the ElSereno plugin for DNP3 (IEEE 1815)
// on port 20000. The probe sends link-layer Request Link Status frames
// to destination addresses 0..100 (as nmap's dnp3-info.nse) and
// classifies whether the reply is a DNP3 link frame with a valid
// header CRC. Until 2026-10-07 it sent a header with a zero CRC,
// which every real outstation discards (PITF-073).
package dnp3
