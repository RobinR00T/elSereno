package netutil

import "bytes"

// IsEcho reports whether reply is (a prefix of) the probe that was sent.
//
// A reflecting service (TCP/UDP echo, tarpits, some honeypots) answers a
// probe with the probe itself. When a plugin's response signature can also be
// found in its own request (a magic shared by both directions, the same
// leading opcode, a command code the reply repeats), that reflection would
// otherwise be classified as a confirmed device (PITF-071). A genuine reply
// carries its own header, direction bits or length, so it is never a prefix
// of the probe it answers. Matching a prefix, not just equality, also
// catches an echo cut short by a read boundary. An empty reply is not an
// echo (that is "no reply", which callers already handle).
func IsEcho(sent, reply []byte) bool {
	return len(reply) > 0 && bytes.HasPrefix(sent, reply)
}
