---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 1200
---

# Testing strategy

## Layers

| Layer | Build constraint | Scope |
|-------|------------------|-------|
| Unit | (none) | Pure Go; no network; no Postgres. |
| Fuzz | (none) — `go test -fuzz` | Binary parsers and canonicalisers. |
| Integration | `//go:build integration` | Postgres via `docker-compose`; Linux-only unless justified. |
| E2E | `//go:build e2e` | Full CLI flows against simulators. |
| Chaos | `//go:build chaos` | Fault injection helpers in `test/chaos/`. |

## Style

- Table-driven with `t.Run` per case.
- `testify` for asserts; `google/go-cmp` for deep diffs.
- `gopter` for property-based tests on state machines and codecs.
- Golden files under `testdata/` with an `-update` flag.
- `t.Skip` based on `runtime.GOOS` for Linux-only tests on darwin runners
  (raw sockets, seccomp).
- `funlen` is relaxed in `_test.go` to `120/80`.

## Coverage thresholds

| Package family | Minimum |
|----------------|--------:|
| `internal/protocols/*` | 90 % |
| `internal/core`, `internal/audit` | 85 % |
| Other `internal/*` and adapters | 80 % |

Enforced in CI. Local `make test-cover` prints the per-function report.

## Fuzz

- Every binary-format parser and every canonicaliser (JCS) MUST have a
  `FuzzXxx` function under the package.
- `scripts/run-fuzz.sh` discovers all `Fuzz*` functions in `*_test.go`
  and runs each for `$DURATION` (default 30 s). Invoked by `make test-fuzz`
  and by the nightly CI job at 30 min per target.

## Network policy

- Unit tests MUST NOT touch the network. Integration tests may, and MUST
  run only under `-tags integration` against simulators in
  `simulators/docker-compose.test.yml`.
- No real third-party IPs, hostnames, credentials, or banners in any
  testdata or commit.
