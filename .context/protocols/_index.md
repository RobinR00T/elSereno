---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 800
---

# Protocols index

| Protocol | Default port(s) | Phase | Status | File |
|----------|-----------------|------:|--------|------|
| XOT (X.25 over TCP) | 1998/tcp | F2 | implemented | [xot.md](xot.md) |
| AT modem (Hayes/GSM/EN 81-28) | 23, 7, 2001-2032, 3001, 4001-4009, 9999, 10001-10004/tcp | F2 | implemented | [atmodem.md](atmodem.md) |
| Modbus/TCP | 502/tcp | F3 | implemented | [modbus.md](modbus.md) |
| S7comm | 102/tcp | F4 | implemented | [s7.md](s7.md) |
| EtherNet/IP (CIP) | 44818/tcp | F4 | implemented | [enip.md](enip.md) |
| BACnet/IP | 47808/udp | F4 | implemented | [bacnet.md](bacnet.md) |
| DNP3 | 20000/tcp | F4 | implemented | [dnp3.md](dnp3.md) |
| IEC 60870-5-104 | 2404/tcp | F4 | implemented | [iec104.md](iec104.md) |
| HART-IP | 5094/tcp+udp | F4 | implemented | [hartip.md](hartip.md) |
| Niagara Fox | 1911, 4911/tcp | F4 | implemented | [fox.md](fox.md) |
| ATG Veeder-Root | 10001/tcp | F4 | implemented | [atg.md](atg.md) |
| banner/dictionary | many | F1 + F4 | implemented | [banner.md](banner.md) |

## Summary
- **12 plugins** registered in the default build (read-only).
- Every plugin ships: from-scratch wire parser (with `FuzzXxx`
  targets), Probe method emitting a scored Finding, pass-through
  ProxyHandler, REPL stub (wires with the generic REPL framework in
  F4 chunk 2).
- **Write-gating proxy matrices** live in `modbus` and `atmodem`
  today; the remaining seven plugins hook into F5's per-service
  triple-confirm wrapper.
- **Offensive operations** (writes, exploits, harvest, dial) are
  F5-gated behind `-tags offensive`.
- Deep protocol semantics (full XOT PAD, GSM SMS read, S7 block
  read, CIP Forward Open, BACnet readProperty, DNP3 application
  layer, IEC-104 ASDU, HART command 0, Fox BIFs, ATG I30000) land
  alongside the REPL framework.

## Integration simulators
- `simulators/xot/`, `simulators/atmodem/`, `simulators/modbus/` —
  deterministic Go responders used by unit + integration tests.
- `simulators/docker-compose.test.yml` includes a Conpot container
  that emulates Modbus, S7, EtherNet/IP, BACnet, HART-IP, IEC-104,
  Niagara Fox, and Veeder-Root ATG on separate loopback ports.
