---
phase: F7
status: closed
last-updated: 2026-04-20
token-budget: 300
---

# Current state

**Phase**: F7 — Hardening + 1.0.
**Last closed**: **F7 on 2026-04-20**. `make release-gate` green on a
  clean tree. See `.context/snapshots/f7-hardening-1.0.md`.
**In progress**: nothing. Project is feature-complete for
  **v1.0.0**; tag + signed release is an operator task documented
  in `RELEASING.md`.
**Next**: **v1.0.0 signed release** — operator runs
  `make release-gate`, pushes the tag, the release workflow
  emits cosign-signed archives + `.intoto.jsonl` SLSA provenance
  + CycloneDX SBOM + GHCR image. Post-1.0 carry-overs listed in
  the F7 snapshot.
**Blockers**: none.

## Post-1.0 carry-overs
- seccomp-bpf BPF filter instruction sequences per profile.
- Offensive CLI network delivery (currently dry-run) + DB-
  backed audit writer.
- SSE live feed on `/api/v1/stream`; findings/triage/runs DB
  panels + tables.
- Gremlins mutation testing CI job (optional enhancement).
- `BENCH_STRICT=1` flip after baseline accumulates ≥ 9 samples.
- GitHub Security tab ingestion in `/admin/security`.

## Open questions
(none)
