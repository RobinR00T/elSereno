package wire

// Transport function header (IEEE 1815-2012 Clause 8): the first octet
// of every user-data frame's data. An application fragment longer than
// one frame travels as several segments: FIR marks the first, FIN the
// last, and SEQ counts them modulo 64. A single-frame request carries
// both FIR and FIN.
const (
	TransportFIN     uint8 = 0x80
	TransportFIR     uint8 = 0x40
	TransportSeqMask uint8 = 0x3F
)
