---
phase: F7
status: closed
last-updated: 2026-04-20
token-budget: 1500
---

# Snapshot — F7: Hardening + 1.0

Closed **2026-04-20**. Ships every control the project needs for
the v1.0 signed release: dockers_v2, nightly fuzz matrix,
regression benchmarks with benchstat, OpenTelemetry tracing,
STRIDE threat-model docs per surface, supply-chain automation
(scorecard + SLSA L3 + dep-review + osv-scanner + licenses-audit),
encrypted backup + CLI verbs, pentest self-audit panel at
`/admin/security`, and a `make release-gate` local green-light.

## Chunks

### Chunk 1 — dockers_v2 + nightly fuzz matrix (`390189c`)
- `.goreleaser.yml` migrated from `dockers:` → `dockers_v2:`.
  Eliminates the last deprecation warning from the release
  workflow.
- `.github/workflows/nightly.yml` adds a per-target fuzz matrix:
  every `Fuzz*` test in `internal/**/*_test.go` runs for 30 min
  per target on schedule; corpus entries archived as artefacts.

### Chunk 2 — regression benchmarks + benchstat CI (`a0397ce`)
- Benchmarks for the scanner, audit chain, vault derivation,
  and wire parsers live under `*_test.go` with `BenchmarkXxx`.
- `scripts/bench-baseline.sh` captures the committed baseline at
  `benchmarks/baseline.txt`.
- `.github/workflows/benchmarks.yml` runs `benchstat` on PR
  head vs base; comments the delta on the PR; strict mode
  (`BENCH_STRICT=1`) turns a ≥ 10 % regression into a failure.

### Chunk 3 — OpenTelemetry tracing scaffold (`c8abe7c`)
- `internal/telemetry/tracer.go` initialises a tracer from the
  env: `OTEL_TRACES_EXPORTER={none,stdout,otlp}` with sensible
  defaults. `none` is the safe default.
- Scanner's retry/attempt loop attaches a span with
  `scanner.target`, `scanner.port`, `scanner.attempt`, `scanner.
  plugin` attributes. First real consumer; more surfaces follow
  post-1.0.

### Chunk 4 — STRIDE threat-model per surface
- `.context/threat-model/README.md` indexes the surface docs
  with STRIDE legend + residual-risk policy.
- Six surface docs: `vault-audit`, `web`, `scanner-proxy`,
  `exec-scope`, `offensive`, `telemetry-canary`. Each walks the
  six STRIDE letters + lists the code path + ADR that enforces
  the control + a residual-risk section.

### Chunk 5 — supply-chain automation
- `.github/workflows/supply-chain.yml`: OpenSSF Scorecard
  (nightly + PR), SLSA provenance verify (tag only),
  dependency-review (PR), osv-scanner (always),
  licenses-audit (artefact upload).
- `.github/dependency-review-config.yml`: deny AGPL / GPL /
  LGPL / SSPL / Commons-Clause / Elastic-2.0; fail-on-severity
  high.
- `.github/workflows/release.yml` upgraded: goreleaser emits
  real SHA-256 hashes; slsa-provenance job signs them +
  uploads the `.intoto.jsonl` assets directly to the release.
- `.goreleaser.yml` release.footer prints the cosign +
  slsa-verifier recipes for every tag.
- `SUPPLY-CHAIN.md` (new, root): SLSA L3 mapping, dependency
  policy, SBOM diff recipe, scorecard target ≥ 8.0, secrets
  rotation table, incident response pointers.

### Chunk 6 — encrypted backup (`internal/backup`)
- AES-256-GCM envelope: `magic(4) || version(1) || salt(16) ||
  nonce(12) || ciphertext(+tag)`.
- Two-stage HKDF-SHA256 key derivation: master → intermediate
  (info="elsereno/backup/v1") → data key (salt=envelope_salt).
  Per-archive salt bound into AEAD AAD so salt-swap attacks
  fail closed.
- 10 unit tests cover round-trip, bit-flip tamper, salt-swap
  tamper, wrong-key, bad magic, unsupported version,
  truncated input, IND-CPA distinctness, empty files.

### Chunk 7 — pentest panel + backup CLI (`/admin/security`)
- New `Security()` handler at `/admin/security`: table of 11
  in-process controls with status pills + code path + ADR
  reference. Offensive build tag lights a WARN pill when
  offensive plugins register.
- Links to all 6 threat-model docs and a summary of every
  external sec-suite job with pointers to the workflow.
- Dashboard nav bar links the self-audit page.
- `elsereno backup {create,restore,inspect}` CLI verbs wire
  the chunk-6 package. All three honour
  `--vault-passphrase-file` for non-interactive use. O_EXCL
  on create refuses to stomp an existing backup.

### Chunk 8 — release-gate (`scripts/release-gate.sh`)
- 11 local checks: working-tree clean, tests + lint × 2 build
  variants, context-check, docs presence (10 files + 12
  protocol pages + threat-model tree), goreleaser snapshot
  build, govulncheck, gitleaks, benchmarks baseline.
- Coloured output, exit 0/1, `[skip]` tolerated for locally-
  missing tools (CI covers them).
- `make release-gate` target in `.PHONY`.
- `RELEASING.md` gains a 1.0 gate section listing 7
  additional preconditions (residual-risk resolution, STRIDE
  coverage, scorecard ≥ 8.0, benchmarks regression, docs
  freshness, security panel green, release-gate exit 0).

## Metrics

- 8 feature commits on main + 1 close commit.
- ~2 400 LOC added (threat-model docs + sinks + backup +
  pentest panel + release-gate).
- 6 threat-model docs covering every critical surface.
- 11 controls tracked in the security self-audit panel.
- 10 unit tests on the backup crypto envelope.
- `make release-gate` green on a clean working tree.
- Dashboard stack (5 preview servers) still live at end of
  phase.

## Carry-overs to post-1.0 (v1.1+)

- BPF syscall-filter bytecode per profile (F5 chunk 5 shipped
  NO_NEW_PRIVS + profile scaffolding; the filter sequences land
  when the first offensive subprocess needs them).
- Network delivery for `elsereno write|exploit|harvest|dial`
  (today they are dry-run + triple-confirm token minting).
  Needs the DB-backed audit writer.
- SSE live feed at `/api/v1/stream` + findings/triage/runs DB
  panels for the dashboard.
- Gremlins mutation testing CI job (scorecard covers the
  measurement; Gremlins is an optional enhancement).
- BENCH_STRICT=1 flip once the baseline accumulates 9+ samples
  from the GH Actions runner.
- GitHub Security tab ingestion into `/admin/security` so the
  panel shows external sec-suite results alongside in-process
  controls.
