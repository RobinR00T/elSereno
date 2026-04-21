---
phase: v1.1-in-flight
status: v1.0.1 released; all v1.1 feature chunks landed on main (4b DB half carries over to v1.2); ready for close-and-tag
last-updated: 2026-04-21
token-budget: 300
---

# Current state

**Phase**: v1.1 implementation in flight on `main`
(RobinR00T/elSereno, private).

**Shipped releases**:
- **v1.0.0** (2026-04-20) — 12 assets, GPG-signed tag
  ACE3B86BACACE7D6, missing SLSA `.intoto.jsonl`.
- **v1.0.1** (2026-04-21) — release-polish: cosign bundle
  (verified end-to-end with `cosign verify-blob --bundle
  checksums.txt.bundle` → OK), pandoc 3.9.0.2 pin, SLSA
  v2.1.0 generator (final step still hits upstream bug
  exit-27; wrapped non-blocking in release.yml).

**v1.1 chunks landed on `main`**:
- **Chunk 1** ✅ Per-plugin offensive `WriteGatedHandler`.
  Full wire-level Handle for modbus/s7/enip; session-auth
  primitives (AllowlistHash + SessionMutation) for
  bacnet/dnp3/iec104/hartip/atg/fox. Closes ADR-040 offensive
  side; default-build write-ban preserved intact.
- **Chunk 2** ✅ File-backed audit writer at
  `internal/audit/writer.go` (FileWriter + VerifyFile) +
  `offensive/confirm/adapter.go` mapping
  `confirm.AuditEvent` onto the existing `audit_log`
  event_type enum. JSONL at `~/.elsereno/audit.jsonl` mode
  0600. Chain-resumable across process restarts.
- **Chunk 3** ✅ Network delivery wiring:
  `cmd/elsereno/offensive_runtime.go` (vault + writer + actor
  helper), `write modbus send` (real Execute call with
  triple-confirm + audit), `exploit run` (tcp/udp dial +
  audit), `audit verify-file` walks the JSONL chain.
- **Chunk 4a** ✅ SSE `/api/v1/stream` +
  `internal/web/stream` Broadcaster (fan-out, slow-sub
  dropped), audit.Observer hook + cross-process
  `TailAudit` file tailer, dashboard live-feed panel
  (EventSource, CSP-nonce script), OpenAPI spec entry.
  `serve` spins up the tailer so offensive verbs running
  in separate processes light up the feed.
- **Chunk 5** ✅ `dockers_v2` block in `.goreleaser.yml`
  (multi-arch amd64/arm64, `sbom: true` CycloneDX
  attestation, provenance via --attest flag, cosign keyless
  `docker_signs` on the manifest). `release.yml` adds
  buildx + QEMU setup steps. `Dockerfile` + `Dockerfile.sqlite`
  pin Go 1.25.4 (alpine3.22 / bookworm) matching go.mod.
- **Chunk 6** ✅ seccomp-bpf sandbox: per-profile denylist BPF
  programs (exploit/harvest/dial) compiled in
  `offensive/sandbox/bpf_linux.go`, installed via
  `seccomp(SET_MODE_FILTER, TSYNC)`. Syscall tables for x86_64
  + aarch64. New `audit.EventOffSandbox` + migration 00002.
  `offensiveRuntime.ApplySandbox` wires the load before every
  offensive network I/O (write/exploit/harvest). Integration
  tests verify ptrace + socket return EPERM on native Linux.
- **Chunk 7** ✅ OPC UA plugin on port 4840. `internal/protocols/
  opcua/wire/` parses UA-TCP Part 6 Hello/Acknowledge/Error
  frames; `opcua.go` probes + classifies (ua-ack / ua-err /
  non-ua-bytes / no-response). Default ProxyHandler refuses
  with a UA-native ERR frame. `simulators/opcua/` ships the CI
  test peer. Write gating deferred to v1.2 (full SecureChannel/
  Session/Write surface is out of scope for v1.1).
- **Chunk 8** ✅ Wardialing batch. `offensive/dial/batch.go`
  classifies a list of numbers against the ADR-041 dial guard
  and appends one `offensive_dial` audit entry per decision.
  New `elsereno dial batch` CLI verb (stdin or --numbers-file)
  installs the seccomp `dial` sandbox before classification.
  Former single-number check preserved as `elsereno dial
  validate`. Default disposition = "preview" (audit-only dry-
  run); actual modem / VoIP delivery is a v1.2 carry-over.

**Pending v1.1 chunks**:
- **Chunk 4b** (carry-over to v1.2) — findings / triage /
  runs DB tables + panels reading from DB. Landing with
  the DB-backed audit Writer.
- **Chunk 7** — OPC UA plugin (port 4840) as next ICS
  protocol.
- **Chunk 8** — Wardialing batch (`elsereno dial batch --scope
  …`) reusing ADR-041 dial-guard.
- **v1.1 close** — snapshot + STATE + CHANGELOG + TODO + tag
  + release smoke.

**Bootstrap PAT** (`elsereno` fine-grained) still live. User
wants it live until end of v1.1; revoke manually at
https://github.com/settings/personal-access-tokens when done.

**Repo**: `RobinR00T/elSereno`, **private**. Pending operator
decision to flip to public.

**Live services** (preview-start):
- dashboard 127.0.0.1:8787
- dev-db (pg 16) 127.0.0.1:5433
- dev-adminer 127.0.0.1:8080
- test-simulators 127.0.0.1:5434
- banner-sim 127.0.0.1:9999

## Known release carry-overs (post-1.1)
- DB-backed audit writer (FileWriter ships v1.1; DB writer
  v1.2).
- Full wire-level WriteGatedHandler for bacnet/dnp3/iec104/
  hartip/atg/fox (session primitives in v1.1; full handler
  v1.2).
- SLSA `.intoto.jsonl` assets on the release (known upstream
  bug; tracked for v1.2).
- Scorecard / CodeQL / OSV full suite runs only after repo
  flips to public (GHAS-gate).

## Open questions
- Flip repo to public after v1.1? (unlocks Scorecard,
  CodeQL, OSV).
