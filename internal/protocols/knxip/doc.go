// Package knxip implements the ElSereno plugin for KNXnet/IP on
// UDP/3671. The default build is read-only: a single
// DESCRIPTION_REQUEST (service type 0x0203) is sent and the
// 30-byte ASCII Friendly Name + KNX Medium + KNX Individual
// Address are folded into the finding hash. No
// CONNECT/TUNNELLING/DEVICE_CONFIGURATION services are issued.
package knxip
