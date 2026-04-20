---
phase: F6
status: closed
last-updated: 2026-04-20
token-budget: 1500
---

# Snapshot — F6: Reporting + release

Closed **2026-04-20**. Ships the full reporting surface
(HTML polish + 5 SIEM/ticketing/webhook sinks + OpenAPI autogen),
the operator-facing CLI verbs that expose the F5 offensive
libraries, the non-interactive vault unlock path, the polished
dashboard, and the release runbook ready for a signed 0.1.0 tag.

## New output sinks

### `internal/outputs/cef` — ArcSight CEF 0.1
One line per Finding: `CEF:0|ElSereno|elsereno|<ver>|<proto>|<op>|
<sev 1..10>|<sorted extensions>`. Severity maps 0..100 score →
CEF 1..10. Header / extension escape rules implemented.

### `internal/outputs/syslog` — RFC 5424
`<PRI>1 <ts> <host> <app> - <msgid> [elsereno@32473 <sorted SD>]
<msg>`. Facility local1 (17); severity mapping
critical=2 / high=3 / medium=4 / low=6 / info=7 / unknown=5.

### `internal/outputs/jira` — JIRA Cloud REST v3
POST /rest/api/3/issue with HTTP Basic email:api_token. ADF
description, severity → priority (Highest..Lowest), labels for
severity / protocol / run id plus operator-supplied LabelsExtra.

### `internal/outputs/githubissues` — GitHub REST
POST /repos/{owner}/{repo}/issues with Bearer PAT + the
2022-11-28 API pin. Markdown body with factor table, GHES
BaseURL override.

### `internal/outputs/webhook` — generic webhook
POST JSON envelope `{schema:"webhook:v1", …}` with optional
HMAC-SHA256 in X-Elsereno-Signature, plus ExtraHeaders for
custom auth (Slack, Teams, etc.).

## HTML report polish (F6 chunk 2)

- CSS custom properties with prefers-color-scheme: dark.
- Severity distribution grid with coloured left-border cards.
- Top-5 scoring factors histogram (CSS-only bars).
- Per-protocol sections with count + max + avg heading and
  within-section findings sorted by descending score.
- Tabular-numeric font for score columns.
- Self-contained — no external fetches.

## OpenAPI autogen (F6 chunk 6)

- `internal/web/openapi.Spec(buildVersion) Document` is the
  single source of truth. `Marshal` renders deterministic
  OpenAPI 3.1 YAML.
- `GET /api/v1/openapi.yaml` serves the live spec straight from
  code — the binary never goes out of sync.
- `elsereno api openapi [-o <path>]` dumps to stdout or file for
  the release snapshot.
- `docs/openapi.yaml` regenerated; every handler in
  `internal/web/handlers/api.go` appears in the spec (verified
  by test).

## Dashboard polish (F6 chunk 8)

- 2-column grid (collapses below 900 px) with navigation chips,
  default vs offensive plugin tables (offensive only when built
  with `-tags offensive`), scoring sidebar, severity
  thresholds, vault hint, build summary.
- Dark-mode palette matches the HTML report.
- Auto-refresh `<meta http-equiv="refresh" content="30">`
  pending the SSE feed in the next phase.

## Offensive CLI wiring (F6 chunk 5)

All four F5 offensive libraries are now operator-usable:

- `elsereno exploit list|show|dry-run` walks the registry.
- `elsereno dial --number <E.164> [--scope scope.yaml]` runs
  the three-gate validator in isolation.
- `elsereno write modbus --target … --op …` prints the PDU
  bytes + payload hash (network delivery with triple-confirm
  lands in F7).
- `elsereno harvest {telnet,ftp,http-basic,snmp} --target …`
  runs the prober with DefaultCredentials.

Default-build stub keeps the binary identical when compiled
without `-tags offensive`.

## --vault-passphrase-file (F6 chunk 7)

`--vault-passphrase-file <path>` on `vault init`, `vault unlock`,
`serve`. Validation:
- `os.Lstat` rejects symlinks / pipes / devices with
  ErrPassphraseFileNotRegular.
- Mode check `perm &^ 0o600 != 0` rejects group/other-readable
  files with ErrPassphraseFileMode.
- Empty file rejected.
- Trailing CRLF stripped.

Unblocks CI, preview runners, and any non-TTY startup path
without weakening the interactive-prompt default. ADR-026 /
PITF-016 compliant.

## Per-protocol docs (F6 chunk 4)

`docs/protocols/README.md` + 12 per-plugin pages
(atg / atmodem / bacnet / banner / dnp3 / enip / fox / hartip /
iec104 / modbus / s7 / xot). Operator-facing: probe bytes,
proxy default policy, writes-behind-offensive-build, scope +
impact class, public references.

## Release prep (F6 chunk 9)

`.goreleaser.yml` migrated `archives.builds` → `archives.ids`
(goreleaser v2 rename). Dry-run verified:

```
goreleaser build --snapshot --clean \
    --id elsereno-default --id elsereno-offensive
```

→ 8 binaries (darwin + linux × amd64 + arm64 × default +
offensive). Both variants smoke-tested: `version`, `plugins
list`, `exploit list` all work on the built binaries.

SBOM generated via syft (CycloneDX 1.6, 48 components).
Checksums (SHA-256) collected for all 8 artefacts.

`RELEASING.md` ships as the operator runbook: prerequisites,
pre-release checklist, dry-run recipe, SBOM, cosign keyless
signing + receiver verification, tagging, rollback.

## Carry-overs to F7

- `dockers:` → `dockers_v2:` migration (deprecation notice
  only; current config still builds).
- `elsereno write|exploit|harvest|dial` network delivery
  wiring (currently dry-run only; needs the DB-backed audit
  writer to emit the `offensive_allowed` event per ADR-039).
- seccomp-bpf BPF filter instruction sequences (F5 ships
  profile scaffolding + NO_NEW_PRIVS; the filters land with
  the first offensive subprocess integration).
- SSE live feed at `/api/v1/stream` backing the dashboard's
  placeholder panels.
- Findings / triage / runs DB tables + dashboard panels.

## Metrics

- 9 feature commits on main (chunks 1..9) + 1 close commit.
- 5 new sink packages + 1 CLI verb (`api`) + 4 offensive CLI
  verbs + the `--vault-passphrase-file` flag + 13 markdown
  docs (12 protocols + README + RELEASING.md).
- ~2 200 LOC added, ~450 LOC deleted.
- `make ci` green on both build variants.
