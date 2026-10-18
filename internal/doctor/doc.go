// Package doctor documents the preflight checks of `elsereno doctor`.
// The checks live in cmd/elsereno/cmd_doctor.go and are six, none of
// them external:
//
//   - Go runtime version and platform.
//   - Raw-socket privilege (CAP_NET_RAW on Linux, root on macOS): a
//     skip when missing, since probes use ordinary sockets.
//   - nmap on PATH: optional, elsereno never runs it.
//   - IPv6 availability and free disk.
//
// Not built: Postgres connectivity and TLS, DNS/IDN smoke tests,
// provider endpoints (Shodan, Censys), NTP drift, memguard mlock and
// vault status.
package doctor
