---
phase: F3
status: closed
date: 2026-04-19
token-budget: 1200
---

# Phase F3 snapshot — Proxy framework + Modbus read-only

**Closed on 2026-04-19.** `make ci` green end-to-end. The proxy
framework is live; Modbus is the first plugin to plug into it and
serves as the template for the F4 ICS plugins.

## Shipped

### Proxy framework (`internal/proxy`)
- `framework.go`: TCP-only Server with Accept loop, upstream
  dial, IdleTimeout-driven deadline, MaxConns cap, graceful
  ctx-cancel shutdown. `hookedRW` wraps each side of the connection
  so `Hook.PreHook` / `PostHook` see every byte chunk.
- `logger.go`: `LoggingHook` logs a line per chunk using
  `render.SafeBytes` (PITF logs never escape ANSI/control bytes).
- `Hook` interface with optional rewrite semantics — PreHook can
  return a replacement buffer. `NoopHook` is the pass-through used
  by plugins that do not need observation.
- Tests: end-to-end accept+dial+echo test against a local echo
  server; LoggingHook smoke test that verifies byte-chunk records
  reach the configured writer.

### Modbus plugin (`internal/protocols/modbus`)
- `wire/` from-scratch parser.
  - `mbap.go`: MBAP (7 bytes), PDU (max 253), Frame Read/Write,
    minimal Read Coils and Read Device Identification request
    builders, exception-bit handling, DeviceIDObjects decoder for
    FC 43/14.
  - `codes.go`: FunctionCode constants covering the spec subset
    + `Classify(fc)` -> Read/Write/Diagnostic/MEI/Unknown category.
  - Fuzz targets: FuzzParseMBAP, FuzzReadFrameRoundTrip,
    FuzzDeviceIDObjects.
- `modbus.go`: Plugin with Probe (FC 1 minimal + opportunistic FC
  43/14 vendor strings) and ProxyHandler. The proxy parses each
  client frame and replies with IllegalFunction for every
  CategoryWrite FC, MEI sub-code != 14, or Unknown FC — the
  upstream device never sees a write when fronted by the proxy.
- Tests: probe against a local PLC simulator (FC 1 accepted, FC 1
  exception, FC 43/14 vendor/product strings); proxy FC-by-FC
  adversarial suite that drives every CategoryWrite FC through the
  proxy and asserts the upstream receives 0 bytes while the client
  receives an IllegalFunction.

### Modbus simulator (`simulators/modbus`)
- Go-based responder implementing FC 1/2/3/4 against an in-memory
  bank and FC 43/14 with ElSereno/modbus-sim/v1 identification.
  Rejects every other FC with IllegalFunction so tests cannot
  accidentally mutate the simulator even if the product code
  regresses.
- Operators who want a full PLC can use pymodbus (installed via
  `pipx install 'pymodbus[repl]'` during the F3 prep) — the doc
  points at it.

### Chaos helpers (`test/chaos`)
- Behind `-tags chaos`. `RandomDropReader`, `LatencyReader`,
  `FlipBitsWriter`, `EarlyCloser`. Deterministic under a seeded
  PRNG so CI reproduces failures. The F4 proxy work will drive
  these through the F3 framework + protocol plugins.

### Plugin registration
- `cmd/elsereno/plugins.go` registers banner + xot + atmodem +
  modbus in the default build. `elsereno plugins list` reports
  all four.

### Integration test
- `test/integration/modbus_integration_test.go` (build tag
  `integration`): end-to-end through the proxy framework —
  upstream listener records what it sees, client sends FC 5
  Write Single Coil through the proxy, asserts upstream received
  0 bytes and the client received IllegalFunction.

## Non-trivial decisions made

- **Diagnostic (FC 8) passes through by default**. Some sub-codes
  (Restart Communications) are destructive; F5 adds per-sub-code
  gating. Documented in `.context/protocols/modbus.md` so it is
  not a silent behaviour.
- **MEI default-deny except sub-code 14**. FC 43 with the Read
  Device Identification sub-code passes; everything else is
  blocked. Keeps the safe default tight.
- **`modbus-sim` Go binary over pymodbus for CI**. pymodbus is
  excellent but a runtime-install dependency for CI nodes; the Go
  sim is deterministic, no external deps, and refuses writes on
  principle so the blue side of every test is never accidentally
  mutable.
- **Proxy framework minimal by design**. Hooks see opaque byte
  chunks (framework does not parse). Plugins wrap protocol-aware
  parsers on top (Modbus does it inline in `forwardFiltered`).

## New pitfalls captured

None. The work surfaced the usual gosec/exhaustive/noctx friction —
addressed inline.

## Debt accepted (moved to F4+)

- Full protocol REPL (call / read_coils / write_single_coil with
  triple confirm) — the generic REPL framework lands in F4 and the
  Modbus commands bind there. Write commands go behind
  `-tags offensive` in F5.
- UDP-only protocols (e.g. BACnet/IP) arrive with a UDP proxy
  variant; F4 adds it alongside the BACnet plugin.
- pymodbus-backed integration path. The Go simulator is the CI
  default; operators can point the integration test at a pymodbus
  simulator manually (export DATABASE_URL to opt in).

## What moves to F4

- Remaining ICS plugins (S7, ENIP/CIP, BACnet/IP, DNP3, IEC-104,
  HART-IP, Niagara Fox, ATG Veeder-Root, banner+dictionary fingerprint).
- Dashboard MVP (HTMX + Alpine + Tailwind over the HTTP server
  scaffolded in F1).
- TUI (bubbletea).
- `/api/v1` + OpenAPI.
- Generic REPL framework — XOT / atmodem / modbus commands bind
  there.
- Conpot simulator under `simulators/docker-compose.test.yml` for
  wider ICS coverage in integration tests.
