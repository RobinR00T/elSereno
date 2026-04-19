// Package enip implements the ElSereno plugin for EtherNet/IP CIP on
// port 44818. The default-build probe sends a ListIdentity
// (command 0x0063) request — no session needed — and parses the
// reply into a VendorID + DeviceType + ProductCode + Revision +
// ProductName tuple.
package enip
