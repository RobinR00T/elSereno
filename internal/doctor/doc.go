// Package doctor implements cross-platform preflight checks:
//
//   - Go runtime version.
//   - Postgres connectivity and TLS per ADR-021 (.pgpass/PGSERVICEFILE
//     detected).
//   - nmap installed and version >= 7.80.
//   - Privileged scan per platform: CAP_NET_RAW on Linux, root on
//     macOS; suggestions when missing.
//   - DNS + IDN smoke tests.
//   - Credential endpoints for Shodan (/api-info) and Censys
//     (/api/v1/account) when set.
//   - NTP drift when doctor.ntp_server is configured.
//   - memguard mlock allocation test (warning on macOS fallback).
//   - Vault status (not-initialised / initialised-locked / unlocked).
//   - Disk >= 1 GiB and IPv6 availability.
package doctor
