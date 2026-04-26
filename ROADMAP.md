# ElSereno — Roadmap

State as of **2026-04-26**. **v1.14.0 cycle closed** on `main`
(4 chunks); tag + GitHub release pending. **v1.13.0 remains
the latest GitHub release** until v1.14.0 is cut.

The shipped lineup (each tag GPG-signed with key
`ACE3B86BACACE7D6`, free-tier local-build flow since v1.8): v1.0
→ v1.1 → v1.2 → v1.3 → v1.4 → v1.5 → v1.6 → v1.7 → v1.8 → v1.9
→ v1.10 → v1.11 → v1.12 → v1.13 → **v1.14 (cycle closed, tag
pending)**. Each release has a per-cycle snapshot under
`.context/snapshots/`.

For the live state see `.context/STATE.md`. For per-cycle deep
dives see `.context/snapshots/v1.<N>.0-*.md`. This file keeps
the long-running roadmap so the delta between **shipped** and
**proposed** stays visible.

## Shipped highlights (post-v1.1)

- **v1.2** — DB panels (findings / runs / triage), SLSA via
  Attestations API, Modbus offensive write-gate (per-FC + unit
  + address-range), OPC UA write-gate (service-TypeID).
- **v1.3** — PBX discovery: SIP / IAX2 / pbxhttp probes + 15
  PBX vendor fingerprints.
- **v1.4** — Offensive PBX write-gates (sip / iax2 / pbxhttp),
  BACnet UDP relay (per-service-choice), TR-069/CWMP probe.
- **v1.5** — `elsereno proxy listen` CLI verb (one command for
  all 6 write-gated plugins).
- **v1.6** — `--allow-file` YAML loader + OPC UA per-NodeId
  allowlist (numeric encodings).
- **v1.7** — `--emit-allow-file` YAML emitter (round-trip).
- **v1.8** — FOFA + ZoomEye input clients (5 providers total).
  First **free-tier** release (cosign+SLSA pivot to free-tier
  GPG-signed tag + SHA-256 + CycloneDX SBOM).
- **v1.9** — CLI wire-up for the input providers, ONYPHE
  (5th provider), SIP INVITE prefix gate (toll-fraud).
- **v1.10** — SIP REGISTER AOR allowlist (registration-hijack).
- **v1.11** — CWMP/TR-069 offensive proxy (per-SOAP-RPC). 7
  offensive write-gated proxies in the default build.
- **v1.12** — gates tightening + input pagination. Per-object /
  per-path scoping across all 7 gates; pagination across the 5
  paid input providers; Shodan InternetDB joins as the 6th
  no-key provider.
- **v1.13** — BACnet completion + CWMP polish. **Closes every
  BACnet mutating service** (svc 7/8/9/10/11/15/16/17/20/27)
  with wire-level per-target-or-state allowlists. Plus CWMP
  firmware pre-flight verifier, RPC case-warning, over-TLS
  recipe; InternetDB bulk lookup; triage `utility` bucket.
  13 chunks.
- **v1.14** — IPv6 cross-cutting. New `internal/netutil`
  package + `canonicaliseTarget` at CLI parse boundaries +
  `scan --input internetdb:` dispatcher fix +
  bracket-stripping ergonomics + scope/dedupe IPv6 contract
  tests. 4 chunks. Tag pending operator.

## v1.13 cycle closed on `main` (tag pending)

13 chunks; operator decides when to cut. See
`.context/snapshots/v1.13.0-bacnet-completion-and-cwmp-polish.md`
for the full breakdown.

- **C** `c581a62` — TODO/TODO-vNext/man1 doc hygiene.
- **1** `781ee50` — InternetDB bulk lookup.
- **2** `781ee50` — CWMP firmware pre-flight verifier.
- **3** `38dedff` — BACnet WPM (svc 16) per-object gate.
- **4** `861aa8d` — CWMP RPC-name case-warning.
- **5** `861aa8d` — CWMP-over-TLS operator recipe (docs).
- **6** `20f6215` — Triage `utility` bucket.
- **7** `934c4f7` — BACnet DeleteObject (svc 11) per-target.
- **8** `3f570e3` — BACnet CreateObject (svc 10) per-type.
- **9** `b51f488` — BACnet ReinitializeDevice (svc 20)
  per-state.
- **10** `14a7451` — BACnet DeviceCommunicationControl (svc
  17) per-state.
- **11** `6a10a70` — BACnet LifeSafetyOperation (svc 27)
  per-operation (fire-alarm safety guard).
- **12** `830ce02` — BACnet AtomicWriteFile (svc 7)
  per-File-instance.
- **13** `5952c55` — BACnet Add/RemoveListElement (svc 8/9)
  per-(object, property) — closes all 9 BACnet mutating
  services.

Supporting: `b611f5c` swapped 18 `//nolint:gosec` → native
`// #nosec G<NNN>` so `make sec` exits 0.

## v1.14 cycle closed on `main` (tag pending)

4 chunks; operator decides when to cut. See
`.context/snapshots/v1.14.0-ipv6-cross-cutting.md` for the
full breakdown.

- **1** `8824885` — IPv6 foundation: `internal/netutil`
  package (IsLoopbackHostPort + CanonicalHostPort +
  ParseAddrPort).
- **2** `0de0923` — Target canonicalisation across proxy
  listen + every dry-run command (sip / iax2 / pbxhttp /
  modbus / opcua / cwmp + BACnet runner).
- **3** `e0cae6f` — `scan --input internetdb:` IPv6 fixes
  (missing dispatcher case from v1.13 chunk 1 + bracket-
  stripping ergonomics).
- **4** `59e7d76` — IPv6 coverage tests for scope + dedupe
  paths (audit-only — infrastructure was already correct;
  contract pinned).

## v1.15+ proposed backlog

- **CWMP TransferComplete-side SHA-256 verification** —
  v1.12 chunk 10 stores the SHA-256 as audit metadata; v1.14
  parses the CPE → ACS TransferComplete envelope and compares
  against the allowlist. Audit on mismatch (firmware corrupted
  or supply-chain swap).
- **BACnet per-instance Create + per-object LSO** scoping
  refinements — v1.13 closed all 9 services at the natural
  granularity, but per-instance CreateObject + per-object
  LifeSafetyOperation are possible v1.14+ tightenings if
  operators ask.
- **12 legacy ICS protocols** (PROFINET DCP / GOOSE / SV,
  CoDeSys, Omron FINS, MELSEC SLMP, Red Lion, GE-SRTP, IEC
  61850 MMS, KNX, M-Bus TCP, OPC UA HTTPS, DLMS/COSEM, +1).
- Bigger-picture deferrals: SIGHUP reload of proxy listen
  allowlist, `discover --auto <CIDR>`, TUI front-end, record-&-
  replay proxy sessions, Windows support, multi-user OIDC +
  roles, STIX 2.1 export.

---

## Historical deferral list (v1.1 era)

The notes below preserve the original v1.1-era checklist for
provenance. Most line items have shipped in v1.2–v1.12; what
remains is mirrored above in "v1.13+ proposed backlog".

## v1.1 shipped (closed — see `.context/snapshots/v1.1-sse-sandbox-opcua-wardial.md`)

- [x] **Chunk 1** — Per-plugin offensive `WriteGatedHandler`
  (ADR-040 close). Full wire-level Handle for
  modbus/s7/enip + session-auth primitives for
  bacnet/dnp3/iec104/hartip/atg/fox.
- [x] **Chunk 2** — File-backed audit writer
  (`internal/audit/FileWriter`) + `offensive/confirm/adapter`.
  Chain-resumable JSONL at `~/.elsereno/audit.jsonl` 0600.
- [x] **Chunk 3** — Network delivery: `write modbus send`,
  `exploit run` (tcp/udp), `audit verify-file`,
  `offensive_runtime` CLI helper.
- [x] **Chunk 4a** — SSE `/api/v1/stream` +
  `internal/web/stream` Broadcaster + dashboard live-feed panel
  + cross-process `TailAudit`.
- [ ] **Chunk 4b** — findings/triage/runs DB tables + panels
  reading from DB (CARRY-OVER: lands with v1.2 DB-backed
  audit Writer).
- [x] **Chunk 5** — GHCR docker image via `dockers_v2` —
  multi-arch amd64/arm64, `sbom: true`, cosign-keyless
  manifest sign, buildx/qemu action setup in release.yml.
- [x] **Chunk 6** — seccomp-bpf sandbox per profile
  (exploit/harvest/dial). BPF denylist + TSYNC + migration
  00002 for `offensive_sandbox` audit entries.
- [x] **Chunk 7** — OPC UA plugin on port 4840. UA-TCP Part 6
  Hello/Ack/Err probe + simulator. Write gating deferred to v1.2.
- [x] **Chunk 8** — `elsereno dial batch --numbers-file
  <path>` wardialing mode. Audit entry per decision. Real
  PSTN/VoIP delivery deferred to v1.2.
- [x] **v1.1 close** — snapshot flipped to closed +
  retrospective, top-level CHANGELOG.md gains [1.1.0] entry,
  signed tag `v1.1.0` on commit `0238f15`.

## v1.1 push-time tasks (pending operator action)

- [ ] `git push origin main && git push origin v1.1.0`
  (requires PAT re-export in the operator's shell).
- [ ] Verify release-workflow output: `cosign verify-blob
  --bundle checksums.txt.bundle …` against the v1.1.0 assets.
- [ ] Verify GHCR manifest: `cosign verify
  ghcr.io/robinr00t/elsereno:v1.1.0 …` + `cosign download
  sbom ghcr.io/robinr00t/elsereno:v1.1.0`.
- [ ] Revoke the bootstrap PAT at
  https://github.com/settings/personal-access-tokens (operator
  asked to keep it live until end of v1.1).

## Legend

- 🔴 — **v1.0.1 release-surface** fixes, queued on main.
- 🟠 — **v1.1 carry-overs** already tracked in snapshots / ADRs.
- 🟡 — **v1.2 expansions** — natural next step, still within the
  brief's scope.
- 🟢 — **vNext proposals** — new features not in the original
  brief but high-leverage.
- ⚪ — **research / speculative** — needs a design doc before
  implementation.

---

## 🔴 v1.0.1 — release-surface polish (queued)

- **cosign bundle publishing**
  (`checksums.txt.bundle` shipped alongside `.sig` so operators
  can run `cosign verify-blob --bundle checksums.txt.bundle`
  without fetching the signing cert out-of-band). Configured in
  `.goreleaser.yml`; validates on next tag push.
- **SLSA provenance generator v2.1.0**. v2.0.0 had a finaliser
  bug that emitted exit 27 after a successful upload. v1.0.0
  shipped without `.intoto.jsonl` assets because of it.
- **Pandoc 3.9.0.2 pin** from the upstream `.deb` instead of
  distro apt-get. Byte-reproducible man-page generation lets us
  re-enable the strict "man pages in sync" release-gate step.
- **README badges + signed-install snippet**. Release shield,
  CI shield, licence, Go version, SLSA-3 badge. Quick-install
  recipe with `curl + shasum -c` + optional cosign verify.

Tag re-cut blocked on a local `make release-gate` pass + a clean
CI run on `main`. Zero source-level changes between 1.0.0 and
1.0.1.

---

## 🟠 v1.1 carry-overs (already tracked)

### Offensive build — network delivery

Dry-run CLI verbs are in `main` since F5 chunk 5 but don't emit
real traffic yet. The mutating I/O half of `elsereno
write|exploit|harvest|dial` lands when the DB-backed audit writer
ships (so every `offensive_allowed` event lands on a tamper-
evident chain row, not just stdout).

**Work to land**:
1. `internal/audit.Writer` (pgx-backed, single-goroutine
   INSERT). Carry-over from F1.
2. `offensive/confirm.AuditorWriter` adapter.
3. Network send wrapper for every existing Build — reuse
   `offensive/write/modbus.Execute()` pattern for S7 / ENIP /
   BACnet / exploits / dial.
4. `elsereno audit verify --tail 100` operator verb so the
   audit chain can be checked post-run.

### Per-plugin offensive proxy mode

Each of the 8 plugins that currently ships a default-build
write-ban handler gets a `WriteGatedHandler` under
`-tags offensive` that, instead of refusing, routes mutating
frames through `offensive/confirm.Authorize`. ADR-040 already
declares the contract.

**Work to land**: 8 × 50 LOC per plugin (Modbus / S7 / ENIP /
DNP3 / IEC-104 / HART-IP / ATG / BACnet), 8 matching
integration tests.

### seccomp-bpf filter bytecode

F5 chunk 5 ships the scaffolding (`offensive/sandbox.Load` with
profile enum + `PR_SET_NO_NEW_PRIVS`); the actual BPF filter
instruction sequences per profile (exploit / harvest / dial) land
when the first offensive subprocess needs them.

Library: `github.com/elastic/go-seccomp-bpf` — already pinned in
ADR-042.

### SSE `/api/v1/stream` + DB-backed dashboard panels

Dashboard at `/` currently meta-refreshes every 30 s; the
findings / triage / runs panels show placeholders. The SSE
stream + the DB tables (findings, triage, runs) come together:

- `internal/web/handlers/stream.go` — server-sent events wired
  to the pgx `LISTEN/NOTIFY` channel.
- Migration 00002: findings / triage / runs tables per the
  scanner's existing types.
- Dashboard's placeholder section becomes a live feed with
  per-protocol colours and severity chips.

### GHCR docker image

Disabled in v1.0.0 (buildx driver issue + wrong slug). Fixes:
- `dockers_v2` block with `ghcr.io/robinr00t/elsereno`.
- Release workflow adds a `docker/setup-buildx-action@v3` step
  so `--attest=type=sbom` works.
- OCI annotations populated from goreleaser's templates.

### Advanced-Security-aware workflows on public repos

Scorecard, CodeQL analyze, and osv-scanner-action are gated on
`github.event.repository.visibility == 'public'` because they
upload SARIF to the Security tab (requires GHAS — free only on
public repos). When the repo flips to public the workflows
activate automatically; no code change needed.

### BENCH_STRICT flip

Benchmarks CI comments the delta today. Post-1.0, once the
baseline accumulates ≥ 6 samples from the hosted runner, flip
`BENCH_STRICT=1` so a ≥ 10 % regression becomes a PR-blocking
failure.

---

## 🟡 v1.2 expansions

### Per-protocol offensive tests + fuzz

Every offensive `write/<proto>/Build` function needs a dedicated
fuzz target. Today only the default-build wire parsers have
them; offensive write builders are unit-tested but not fuzzed.

### Outbox → webhook delivery

F5 chunk 5 shipped `internal/canary/canary.go` (direct POST).
The outbox (`internal/outbox`) already has retry + dead-letter
semantics but the canary sender still posts inline. Move the
webhook dispatch behind the outbox so a webhook outage doesn't
cascade into scanner slowdown.

### gen-man roundtrip via cobra

`scripts/gen-manpages.sh` currently skips `man1` because the
binary doesn't expose a `gen-man` subcommand. Add it using
`github.com/spf13/cobra/doc` so `elsereno gen-man --output
man/man1` emits one page per CLI verb. Then the man pages are
fully reproducible from `go build`.

### Audit export verbs

`elsereno audit export --format {cef,syslog,ndjson} --since
<time>` — read from the chain, emit through the F6 sinks. Pair
with `elsereno audit verify --since <time>` for forensic
workflows.

### Gremlins mutation testing

F7 chunk 4 scored Gremlins as "deferred post-1.0; scorecard
covers the measurement". Bring it in as a nightly job under a
separate workflow (`mutation.yml`); the scorecard job and the
Gremlins job complement each other.

### TUI (bubbletea) for offensive flows

Brief §16 mentioned a bubbletea TUI as F4 chunk 2 carry-over.
Never landed. A minimal `elsereno tui` that:
- Shows live findings during a scan.
- Lets the operator drill into a finding, see factor
  breakdown, trigger an `explain` run.
- Exposes the offensive triple-confirm flow as a step-by-step
  wizard (dry-run → review token → paste token → confirm).

---

## 🟢 vNext proposals (high leverage)

### 1. Wardialing batch mode

Brief documented "wardialing batch con scope file" as vNext.
With the dial-guard from ADR-041 already hardened, batch mode
is a matter of:
- `elsereno dial batch --scope scope.yaml --from 34912000000
  --to 34919999999 --max-per-minute 1`
- Reuses `offensive/dial.Validate` per number.
- Rate limiter per CID prefix so nobody gets mass-hit in a
  short window.

Legal caveat: the operator signs an additional batch-
acknowledgement written into the audit chain with an explicit
"I am the end-to-end responsible" claim.

### 2. STIX 2.1 export

Brief mentioned; never scoped. Findings → STIX Indicator +
Observed-Data with an `elsereno-audit` TLP:AMBER bundle. Makes
ElSereno feed into MISP, OpenCTI, ThreatBus.

### 3. Record & replay for sessions

Proxy framework already has the Hook interface. Add a
`RecordHook` that serialises every frame + timing + direction
to a compressed file, and a `ReplayRunner` that re-drives the
proxy from that file. Useful for:
- Regression suites on protocol bug fixes.
- Evidence for incident response (" the PLC replied this exact
  byte sequence ").
- Offline fuzz corpus generation.

### 4. OIDC + roles

Single-operator assumption is the biggest limitation. Add:
- OIDC login via any provider (Auth0, Keycloak, Microsoft
  Entra). `gorilla/sessions` backend.
- Roles: `viewer`, `operator`, `admin`. Operator can run
  scans; admin can issue offensive flows + rotate vault keys.
- Per-operator audit attribution.

### 5. L2 PROFINET / GOOSE / SV (gopacket)

Brief mentioned. Requires `CAP_NET_RAW` + raw sockets (we have
the doctor check). Build on top of `github.com/google/gopacket`
so ElSereno can fingerprint PROFINET DCP announcements and
monitor IEC 61850 GOOSE / SV multicast without ever sending a
frame (pure passive).

### 6. Additional protocols (already in brief)

- **OPC UA** (port 4840) — the modern ICS protocol; important
  for Industry-4.0 deployments.
- **CoDeSys** (port 1200/11740) — many European PLC brands.
- **Omron FINS** (port 9600/UDP).
- **MELSEC SLMP** (Mitsubishi).
- **PCWorx / ProConOS** (Phoenix Contact, some Siemens).
- **Red Lion Crimson** (port 789).
- **GE-SRTP** (port 18245).
- **IEC 61850 MMS** (port 102 — coexists with S7!).
- **KNX** (port 3671/UDP).
- **M-Bus** (port 10001/TCP — legacy).

Each needs its own `internal/protocols/<proto>/` with a
from-scratch wire parser + fuzz target + write-ban proxy per
the F4 template.

### 7. Multiple additional input sources

- **ONYPHE** (EU alternative to Shodan).
- **Fofa** (cn).
- **Zoomeye**.
- **Shodan InternetDB** (free tier, no API key).
- **BinaryEdge**.
- Merge sources with scope-level deduplication.

---

## ⚪ Research / speculative

### A. Deep-learning-based protocol fingerprint

Today every plugin has a hand-crafted wire parser. A lightweight
ML classifier trained on the corpus of captured banners could
help in the "unknown banner" case, falling back to a learned
classifier when the substring rules miss.

Risk: false positives on legitimate admin panels. Design doc
needed before implementation.

### B. Active-Directory-style finding chain

Today findings are independent rows. Some operators want to
visualise "Device A at 10.0.0.1 exposes Modbus, which points at
Device B via TCPdump evidence at 10.0.0.2…". A graph-backed
view where edges are SNMP/ARP/ICMP relationships. Neo4j or
AGE on Postgres.

### C. Canary-mode offensive dry-run

Before hitting a real target, run the payload against the
`simulators/` honeypot (Conpot). ElSereno can tell the operator
"your WriteVar frame, when applied to a S7-1200 Conpot image,
caused a write to memory at DB1.DBB0 and produced this audit
trace" — a canary that catches regressions in the operator's
intent vs. the actual bytes.

### D. Mobile companion app

A read-only phone app that shows the dashboard + triggers an
audit verify after the operator leaves the site. Uses the live
`/api/v1/*` endpoints + server-side push for alerts.

---

## Not in scope (documented NON-GOALS)

Still apply from `NON-GOALS.md`:
- Cloud-only SaaS deployment.
- Windows server support.
- Auto-exploitation cascade (ElSereno always requires explicit
  operator confirmation per mutation).
- Offensive flows without legal scope (`scope.yaml` required).

---

## Priority matrix for the next 90 days

| Priority | Item | Category | Rough effort |
|----------|------|----------|--------------|
| P0 | Cut v1.0.1 | 🔴 | 1 hr |
| P0 | Repo flip to public | operator | 5 min |
| P1 | DB-backed audit writer + network delivery wiring | 🟠 v1.1 | ~4 days |
| P1 | Per-plugin offensive WriteGatedHandler (×8) | 🟠 v1.1 | ~2 days |
| P1 | SSE feed + findings/triage DB panels | 🟠 v1.1 | ~3 days |
| P2 | GHCR image + buildx | 🟠 v1.1 | 1 day |
| P2 | seccomp BPF filter bytecode | 🟠 v1.1 | ~2 days |
| P2 | OPC UA plugin (most-asked next protocol) | 🟢 vNext | ~3 days |
| P2 | Wardialing batch | 🟢 vNext | ~2 days |
| P3 | Gremlins mutation | 🟡 v1.2 | 1 day |
| P3 | STIX 2.1 export | 🟢 vNext | ~3 days |
| P3 | OIDC + roles | 🟢 vNext | ~1 week |
| P4 | TUI bubbletea | 🟡 v1.2 | ~1 week |
| P4 | Record & replay | 🟢 vNext | ~3 days |
| P4 | L2 PROFINET / GOOSE / SV | 🟢 vNext | ~2 weeks |

Best order: **P0 (release-polish + public flip) → P1 (offensive
delivery + dashboard live) → P2 (image + sandbox + OPC UA)**.
That produces a v1.1 that feels like the brief's promise fully
realised.

The P3/P4 band is operator-driven — prioritise whichever pops
up first as a real pentest need.
