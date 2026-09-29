package wire

import "fmt"

// u16 reads a little-endian uint16 through the bounds-checked cursor.
func (c *cur) u16() uint16 {
	lo := uint16(c.u8())
	hi := uint16(c.u8())
	return lo | hi<<8
}

// NodeIDText renders raw NodeId bytes (any encoding) in the canonical
// "ns=…;i=…" / "…;s=…" / "…;g=…" / "…;b=…" text form (Part 6 §5.3.1.10),
// used as a stable key for the walk's visited-set and for human output.
// A namespace of 0 is omitted (the common case). Returns "?" on malformed
// input; it is display/keying only, never fed back onto the wire.
func NodeIDText(raw []byte) string {
	c := &cur{b: raw}
	enc := NodeIDEncoding(c.u8() & 0x0F)
	switch enc {
	case NodeIDTwoByte:
		id := c.u8()
		if c.fail() {
			return "?"
		}
		return fmt.Sprintf("i=%d", id)
	case NodeIDFourByte:
		ns := uint16(c.u8())
		id := c.u16()
		if c.fail() {
			return "?"
		}
		return numericNodeID(ns, uint32(id))
	case NodeIDNumeric:
		ns := c.u16()
		id := c.u32()
		if c.fail() {
			return "?"
		}
		return numericNodeID(ns, id)
	case NodeIDString:
		ns := c.u16()
		s := c.str()
		if c.fail() {
			return "?"
		}
		return fmt.Sprintf("ns=%d;s=%s", ns, s)
	case NodeIDGuid:
		ns := c.u16()
		g := c.readN(16)
		if c.fail() {
			return "?"
		}
		return fmt.Sprintf("ns=%d;g=%X", ns, g)
	case NodeIDByteString:
		ns := c.u16()
		b := c.readByteStringBytes()
		if c.fail() {
			return "?"
		}
		return fmt.Sprintf("ns=%d;b=%X", ns, b)
	default:
		return "?"
	}
}

// numericNodeID formats a numeric NodeId, omitting a zero namespace.
func numericNodeID(ns uint16, id uint32) string {
	if ns == 0 {
		return fmt.Sprintf("i=%d", id)
	}
	return fmt.Sprintf("ns=%d;i=%d", ns, id)
}

// readN returns the next n bytes (bounds-checked), or nil on truncation.
func (c *cur) readN(n int) []byte {
	if !c.need(n) {
		return nil
	}
	out := c.b[c.off : c.off+n]
	c.off += n
	return out
}

// readByteStringBytes reads a UA ByteString and returns its bytes.
func (c *cur) readByteStringBytes() []byte {
	n := c.i32()
	if c.fail() || n <= 0 {
		return nil
	}
	return c.readN(int(n))
}
