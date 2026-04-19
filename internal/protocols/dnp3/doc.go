// Package dnp3 implements the ElSereno plugin for DNP3 (IEEE 1815)
// on port 20000. The probe sends a minimal Read Class 0 link frame
// and classifies whether the reply starts with 0x05 0x64.
package dnp3
