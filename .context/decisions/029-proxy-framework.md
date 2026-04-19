---
id: 029
title: Proxy framework — TCP listener with per-frame hook chain
status: accepted
date: 2026-04-19
phase: F3
---

# ADR-029: Proxy framework — TCP listener with per-frame hook chain

## Context
Several F2/F3/F4 protocols (XOT pass-through, Modbus read-only, the
S7/BACnet/DNP3 plugins to come) need a minimal interception proxy:
accept a client, dial an upstream, and forward bytes both ways with
per-frame visibility. Writing one listener per plugin duplicates
accept logic, deadline management, and graceful shutdown.

## Decision
`internal/proxy` owns:
- The listener + accept loop + per-connection lifetime.
- Upstream dial with a configurable DialTimeout.
- An IdleTimeout-driven deadline that both sides share and that the
  framework bumps after every hook invocation.
- A `Hook` interface with `PreHook(dir, []byte) ([]byte, error)` and
  `PostHook(dir, []byte)`. Plugins opt into observation / mutation
  without reimplementing the boilerplate.

Plugins own:
- The `core.ProxyHandler.Handle(ctx, client, upstream io.ReadWriter)`
  implementation. The framework hands them already-wrapped
  ReadWriters; the handler reads/writes like any `io.Copy`-style
  forwarder and the hook chain runs transparently.

Rendering discipline: hooks that log MUST route target-controlled
bytes through `internal/render.SafeBytes`. The framework ships a
`LoggingHook` that does this by default.

The UDP variant arrives when the first UDP-only protocol needs it
(no F3 plugin does).

## Consequences
### Positive
- Plugins shrink to the protocol logic; the test surface for
  accept/deadline/idle/panic-recovery is owned by one package with
  shared tests.
- Hooks are symmetric: the same type observes both directions, which
  matches how operators read SafeBytes-rendered transcripts.
- The framework never parses bytes; the Hook interface passes opaque
  slices so plugins can wrap protocol-aware parsers on top.

### Negative / trade-offs
- The `Hook` surface is minimal on purpose. Plugins that want
  per-frame observability (rather than per-chunk) buffer bytes
  themselves. We keep that as a plugin concern so the framework
  stays protocol-agnostic.
- `hookedRW.Read` allocates a scratch buffer when a hook rewrites
  longer than the caller asked for; rare but worth knowing.

## Alternatives considered
- **Embed the proxy inside every plugin**: duplicates work, and the
  F4 plugins would re-invent the same Accept + dial + idle logic.
- **Use `net.ListenConfig` + inline `io.Copy`**: what we had in F2
  for XOT and atmodem — fine for two plugins, fragile at 9.

## References
- `internal/proxy/framework.go` and `logger.go`.
- `.context/protocols/modbus.md` — the first plugin that sits on top.
