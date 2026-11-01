// Package pcapfile reads packet captures (classic libpcap and pcapng)
// from scratch and extracts UDP datagrams from them, for the offline
// (passive) decoders. It understands the Ethernet (with 802.1Q tags), raw
// IP and BSD loopback link types and IPv4/IPv6 without extension headers;
// anything else is skipped, never guessed. Every length is checked before
// slicing: a capture file is untrusted input.
package pcapfile
