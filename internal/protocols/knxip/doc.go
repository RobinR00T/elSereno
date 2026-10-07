// Package knxip implements the ElSereno plugin for KNXnet/IP on
// UDP/3671. The default build is read-only: a single
// DESCRIPTION_REQUEST (service type 0x0203) is sent and the
// DESCRIPTION_RESPONSE's 30-byte ASCII Friendly Name and KNX Medium
// are folded into the finding hash when the name is non-empty (the
// Individual Address is parsed, not hashed). No
// CONNECT/TUNNELLING/DEVICE_CONFIGURATION services are issued.
package knxip
