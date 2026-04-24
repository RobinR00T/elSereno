# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.11.0] — 2026-04-24

### Added

- **CWMP offensive proxy** — `offensive/write/cwmp`. Completes
  the TR-069 story. v1.4 chunk 5 shipped the fingerprint (17
  plugins, 15 ACS vendors); this ships the matching offensive
  gate. Use case: operator sits between an ACS and a fleet of
  CPEs during change windows and allowlists the SOAP RPCs
  they're authorising.
- **`AllowedRPC{Name string}`** opt-in type. Names are case-
  sensitive per TR-069 §A.4.
- **`AllowlistHash(target, allowed)`** + **`SessionMutation`**
  — standard ADR-040 shape.
- **`canonicaliseRPC`** helper — strips namespace prefix
  (`cwmp:` / `cwmp-1-0:` / `cwmp-1-2:`) and whitespace; case
  preserved.
- **`alwaysSafeRPCs` set (14 entries)** — `GetParameter{Names,
  Values,Attributes}` + Response variants, `GetRPCMethods`,
  `Inform{,Response}`, `TransferComplete{,Response}`,
  `AutonomousTransferComplete`, `Kicked{,Response}`, `Fault`.
  These always pass.
- **`elsereno write cwmp dry-run --rpc <Name>`** CLI,
  repeatable.
- **`elsereno proxy listen --rpc <Name> --plugin cwmp`** CLI.
- **YAML `rpcs:` field** in `proxyAllowFile` — round-trips
  through emit → load.

### Changed

- Write-capable RPCs (SetParameterValues, Reboot, Download,
  FactoryReset, AddObject, DeleteObject, Upload,
  ScheduleInform, ScheduleDownload, ChangeDUState,
  CancelTransfer, SetParameterAttributes) now require explicit
  allowlist. Empty allowlist → all write-capable RPCs refused;
  always-safe RPCs still pass.
- Refusal emits HTTP 200 OK + CWMP SOAP Fault body with
  FaultCode 9001 "Request denied" (TR-069 Annex A spec-
  conformant) + `X-Elsereno-Gate-Reason` header. ACS code
  parses the rejection as an app-level error rather than a
  transport glitch.
- Non-POST (GET/HEAD/OPTIONS) requests bypass the SOAP parser
  entirely — TR-069 proper is POST-only; non-POST is for ACS
  status / health endpoints.
- 7 offensive write-gated proxies in the default build (was
  6). List: modbus, opcua, sip, iax2, pbxhttp, bacnet, cwmp.

### Deferred to v1.12+

- Per-parameter-path allowlist for `SetParameterValues`.
- Firmware-URL allowlist for `Download` (URL + SHA-256 pin).
- RPC-name case-warning in dry-run (flag unknown names).
- Batch-RPC deferred-response routing.
- CWMP-over-TLS (`:7548`) — already works transparently as
  long as the proxy terminates TLS locally, but deserves an
  explicit operator recipe.
- SIGHUP reload (still needs redesign).

## [1.10.0] — 2026-04-24

### Added

- **SIP REGISTER AOR allowlist** — anti-registration-hijack
  twin of v1.9 chunk 5's INVITE prefix gate. Where the INVITE
  prefix controls WHERE calls can go (toll-fraud mitigation),
  this gate controls WHO can register a binding (registration-
  hijack mitigation). Closes the second of the two main PBX-
  abuse vectors.
- **`AllowedAOR{AOR string}`** opt-in type on
  `offensive/write/sip.WriteGatedHandler.AllowedAORs`. Exact-
  match (not prefix): stolen creds for `alice@pbx` shouldn't
  also let an attacker register `admin@pbx`.
- **`AllowlistHashWithAORs(target, methods, prefixes, aors)`**
  — new hash that mixes all three allowlist dimensions.
  Backwards-compat: empty aors → v1.9 hash; empty aors AND
  empty prefixes → v1.4 hash. 0xFE separator for the AORs
  block (distinct from 0xFF prefix separator and ASCII method
  bytes).
- **`SessionMutationWithAORs`** factory; `Authorise()` now
  calls this variant.
- **`canonicaliseAOR`** helper — strips angle brackets, URI
  parameters, `sip:`/`sips:`/`tel:` scheme; lowercases host;
  preserves user-part case per RFC 3261 §19.1.1.
- **`elsereno write sip dry-run --aor <AoR>`** CLI flag,
  repeatable.
- **`elsereno proxy listen --aor <AoR>`** CLI flag,
  repeatable.
- **YAML `aors:` field** in `proxyAllowFile` — round-trips
  through emit → load back to `proxyListenOpts.aors`.

### Changed

- `buildAllowFileSIP` signature extended from 3-arg to 4-arg
  `(target, methods, toPrefixes, aors)`. All 3 existing test
  callers updated.
- `forwardOne` path adds a parallel `REGISTER + AOR list`
  branch to the existing `INVITE + prefix list` branch.
  Failed `registerAORAllowed` emits 403 + `X-Elsereno-Gate-
  Reason: AOR not in session allowlist (REGISTER hijack
  guard)`.

### Deferred to v1.11+

- CWMP offensive proxy (SOAP RPC allowlist).
- BACnet per-object allowlist (ASN.1 BER).
- OPC UA String / Guid / ByteString NodeID encodings.
- OPC UA multi-node per WriteRequest.
- OPC UA CallRequest per-object allowlist.
- Modbus structured `writes:` YAML (unit + FC + addr range).
- SIGHUP reload of proxy listen allowlist.

## [1.9.0] — 2026-04-24

Five chunks that close carry-overs, complete the attack-surface
input story, and add a concrete toll-fraud mitigation.

### Added

- **OPC UA NodeID YAML round-trip.** The `--allow-file` emitter
  + loader now persist per-NodeId allowlist entries as
  structured `node_ids:` entries. Closes the v1.6 → v1.8 gap
  where the per-NodeId gate had CLI support but the YAML
  round-trip silently dropped NodeIDs.
- **`elsereno write modbus proxy-dry-run`** — session-level
  dry-run for the Modbus write-gate. Closes the write-surface
  asymmetry (now all 6 gated plugins — sip/iax2/pbxhttp/opcua/
  bacnet/modbus — have proxy-session dry-runs).
- **`elsereno scan --input <provider>:<query>`** — CLI wire-up
  for the 4 attack-surface input clients (shodan, censys, fofa,
  zoomeye). Credentials via `--api-creds-file <path.yaml>` with
  0600 permission enforcement and strict unknown-field
  rejection.
- **`internal/inputs/onyphe`** — 5th provider. ONYPHE (onyphe.io)
  uses OQL query syntax embedded in the URL path + `bearer`
  auth header. Wired into `scan --input onyphe:<q>`.
- **SIP INVITE To-URI prefix allowlist.** New opt-in field
  `WriteGatedHandler.AllowedToURIPrefixes` on the SIP
  write-gate. When non-empty, INVITE passes only when the To:
  header's URI user-part starts with one of the operator-
  supplied prefixes. Canonical use-case: allow INVITE but only
  to whitelisted destinations (e.g. "+34", "+44") while
  rejecting "+900" premium-rate prefixes that are favourite
  toll-fraud vectors. Other methods (REGISTER, MESSAGE, …)
  unaffected.

### Changed

- `proxyAllowFile` YAML schema gains two v1.9 fields:
  `node_ids:` (list of `{namespace, identifier}`) for opcua +
  `to_prefixes:` (string list) for sip. Both `omitempty` so
  v1.4-v1.8 emitted files stay backwards-compatible.
- `buildSIPHandler` + `buildOPCUAHandler` now pass the new
  optional fields (`AllowedToURIPrefixes`, `AllowedNodeIDs`)
  through to the write-gate.
- SIP + OPC UA `AllowlistHash` gain `WithPrefixes` /
  `WithNodeIDs` companions that degrade to the v1.4 / v1.6
  hash when the new dimension is empty — existing operator
  tokens remain valid.

### Deferred to v1.10+

- SIP REGISTER AOR allowlist (sister to chunk 5's INVITE prefix
  list; blocks registration hijack).
- Modbus per-(unit, fc, addr-range) structured YAML (closes
  chunk 2's `--unit`/`--address-*` + `--emit-allow-file`
  incompatibility).
- OPC UA multi-WriteValue allowlist (v1.6 + v1.9 chunk 1 check
  the first WriteValue only).
- OPC UA String/Guid/ByteString NodeID encodings (chunk 1 is
  numeric-only).
- OPC UA CallRequest per-object allowlist.
- BACnet per-object allowlist (ASN.1 BER parsing).
- CWMP offensive proxy (SOAP RPC allowlist — fingerprint shipped
  in v1.4).

## [1.8.0] — 2026-04-23

### Added

- **`internal/inputs/fofa`** — FOFA (fofa.info) attack-surface
  input client, operator-requested. Requires both `email` +
  `apiKey` (unlike Shodan's single key). `Search` base64-
  encodes the query per FOFA's `qbase64` convention, requests
  `fields=host,ip,port` for a stable row shape, maps rows to
  `core.Target{Address, Port}`. `ErrNoCredentials` +
  `ErrAPIError` typed sentinels.
- **`internal/inputs/zoomeye`** — ZoomEye (zoomeye.org)
  attack-surface input client, operator-requested. Single API
  key delivered via `API-KEY` HTTP header so credentials
  don't leak through URL logs. 1-based paging. `ErrNoAPIKey`
  sentinel.

### Notes

- Both clients are **library-level only**, matching the
  existing Shodan + Censys precedent. Neither is wired into
  the `scan --input <kind>` dispatch yet — that's a v1.9
  design decision (extend `--input fofa:<query>` vs a new
  `elsereno search` verb vs vault-integration via
  `elsereno creds store <provider>`).

### Deferred to v1.9+

- CLI wire-up for FOFA + ZoomEye (see design options above).
- ONYPHE input client (also in `TODO-vNext.md`).
- Modbus proxy-session dry-run (v1.7 carry-over).
- BACnet per-object allowlist.
- SIP To-URI E.164 prefix allowlist for INVITE.
- REGISTER AOR allowlist.
- CWMP offensive proxy.
- SIGHUP reload of proxy listen allowlist.

## [1.7.0] — 2026-04-23

### Added

- **`elsereno write <plugin> dry-run --emit-allow-file PATH`** —
  writes the canonical YAML allow-file that pairs with v1.6
  `proxy listen --allow-file`. Path `-` writes to stdout; any
  other path is created/truncated with 0600 permissions.
  Round-trip: the file emitted plugs directly into `proxy
  listen --allow-file` without further editing.
- **`elsereno write opcua dry-run`** — OPC UA proxy-session
  token minting. Supports `--service <TypeID>` + optional
  `--node-id ns=N;i=M` (repeatable) for the v1.6 per-NodeId
  gate. PayloadHash is computed via `SessionMutationWithNodeIDs`
  when NodeIDs are present.
- **`elsereno write bacnet dry-run`** — BACnet/IP proxy-session
  token minting. Takes `--service-choice <N>` (0-255) for the
  v1.4 chunk 6 confirmed-service allowlist.
- Shared helpers for operator UX: `parseNodeIDFlag("ns=N;i=M")`,
  `canonUintList`, `canonNodeIDs`, `canonUints`.
- **TODO**: FOFA (fofa.info) + ZoomEye (zoomeye.org) input
  integrations are tracked in `TODO-vNext.md` for a future
  cycle. Operator-requested 2026-04-23.

### Changed

- `proxyAllowFile` struct gained `,omitempty` YAML tags on
  per-plugin fields so dry-run-emitted YAML only contains the
  fields relevant to the selected plugin.
- The write command surface is now symmetric across the five
  proxy-session-capable plugins (sip / iax2 / pbxhttp / opcua
  / bacnet). Modbus proxy-session dry-run is a v1.8 carry-over
  because the existing `write modbus` CLI shape is per-request
  (not per-session).

### Deferred to v1.8+

- Modbus proxy-session dry-run.
- Per-NodeId persistence in the YAML allow-file (v1.7 emitter
  only serialises `services:` for opcua; `node_ids:` wire-up
  pending).
- Runtime reload of the proxy listen allowlist (SIGHUP).
- BACnet per-object allowlist (ASN.1 BER parsing).
- SIP To-URI E.164 prefix allowlist for INVITE.
- REGISTER AOR allowlist.
- CWMP offensive proxy (SOAP RPC allowlist).
- FOFA / ZoomEye input integrations.

## [1.6.0] — 2026-04-23

### Added

- **`elsereno proxy listen --allow-file <path.yaml>`** — load
  plugin + target + per-plugin allowlist from a YAML file
  instead of long command-line flag sets. Unknown fields are
  rejected (`yaml.NewDecoder.KnownFields(true)`) so typos like
  `method:` (should be `methods:`) fail noisily. Schema per
  plugin: `methods` (sip), `subclasses` (iax2), `allow`
  (pbxhttp), `functions` (modbus), `services` (opcua),
  `service_choices` (bacnet).
- **OPC UA per-NodeId allowlist** (`offensive/write/opcua`) —
  optional second-stage gate that authorises WriteRequest MSGs
  only when the first WriteValue's NodeId matches an operator-
  supplied list of `{Namespace, Identifier}` pairs. The v1.2
  service-TypeID allowlist still fires first; the NodeID check
  is strictly a *tightening*. Supports TwoByte / FourByte /
  Numeric NodeId encodings; rarer encodings (String / Guid /
  ByteString) cause fail-closed refusal when per-node gating
  is active.
- **`internal/protocols/opcua/wire.WriteRequestFirstNode`**
  parser — walks past the UA RequestHeader + NodesToWrite
  array prefix to extract the first NodeId.
- **`AllowlistHashWithNodeIDs`** and **`SessionMutationWithNodeIDs`**
  on `offensive/write/opcua` — new factories that mix NodeIDs
  into the session PayloadHash.

### Changed

- OPC UA `WriteGatedHandler.Authorise()` now calls
  `SessionMutationWithNodeIDs` instead of the v1.2
  `SessionMutation`. For operators who don't set
  `AllowedNodeIDs`, this is a no-op: the hash degrades to
  the v1.2 `AllowlistHash(target, services)` and existing
  confirm-tokens remain valid.

### Deferred to v1.7+

- OPC UA String / Guid / ByteString NodeId matching.
- OPC UA multi-node-per-WriteRequest allowlist (today only
  the first WriteValue is checked).
- OPC UA CallRequest per-object allowlist.
- BACnet per-object allowlist (ASN.1 BER parsing).
- SIP To-URI E.164 prefix allowlist for INVITE.
- REGISTER AOR allowlist.
- CWMP offensive proxy.
- Runtime reload of the proxy listen allowlist (SIGHUP).
- `elsereno write <plugin> dry-run --emit-allow-file`.

## [1.5.0] — 2026-04-23

### Added

- **`elsereno proxy listen`** (offensive build) — runs any of
  the six v1.4 write-gated handlers inline against a local
  TCP listener. The operator workflow is finally end-to-end:
  mint a confirm-token with `elsereno write <plugin> dry-run
  --vault-passphrase-file …`, then run `elsereno proxy listen
  --plugin <plugin> --target h:p --listen L:P <allowlist
  flags> --accept-writes --confirm-target h:p --confirm-token
  <hex> --vault-passphrase-file /path` to serve a gated
  session until SIGINT / SIGTERM. Supported plugins:
  - `--plugin sip --method INVITE …`
  - `--plugin iax2 --subclass NEW …`
  - `--plugin pbxhttp --allow POST:/admin/config.php …`
  - `--plugin modbus --function 6 …`
  - `--plugin opcua --service 673 …`
  - `--plugin bacnet --service-choice 15 …`
- **First end-to-end integration test** of the gated proxy
  stack: fake SIP origin + `proxy.Server` + gated handler +
  real client — asserts that allowlisted methods reach the
  origin while refused methods get a canonical 405 without
  ever leaving the proxy.

### Changed

- The `proxy` command (previously a planned-stub returning
  EX_TEMPFAIL 75) now exposes real subcommands in the
  offensive build. Default-build behaviour is unchanged: the
  command still returns the stub's "planned" message.

### Deferred to v1.6+

- OPC UA per-NodeId allowlist.
- BACnet per-object allowlist (ASN.1 BER parsing).
- SIP To-URI E.164 prefix allowlist for INVITE.
- REGISTER AOR allowlist.
- CWMP offensive proxy.
- `--allow-file` for YAML / JSON allowlist files.
- Runtime reload (SIGHUP).

## [1.4.0] — 2026-04-23

### Added

- **Offensive SIP write-gate** (`offensive/write/sip`, build-
  tag `offensive`). Replaces the default deny-all SIP proxy
  with a method-allowlist that lets operators use ElSereno as
  a gated SIP relay. Always-safe methods (OPTIONS / ACK / BYE
  / CANCEL / PRACK) always pass; gated methods (INVITE,
  REGISTER, MESSAGE, SUBSCRIBE, NOTIFY, REFER, PUBLISH,
  UPDATE, INFO) require explicit allowlist. Refusal is a
  canonical `SIP/2.0 405 Method Not Allowed` with an Allow:
  header.
- **Offensive pbxhttp write-gate** (`offensive/write/pbxhttp`).
  (method, path) allowlist for HTTP admin UIs. GET/HEAD/OPTIONS
  always pass; CONNECT always refused. Refusal decision tree:
  405 if the method isn't in the allowlist; 403 if the method
  matches but the path doesn't.
- **Offensive iax2 write-gate** (`offensive/write/iax2`). UDP
  per-datagram IAX2 subclass allowlist. Mini-frames (audio)
  and non-IAX media frames always pass. Gated subclasses:
  NEW (call setup), REGREQ (registration), AUTHREP, ACCEPT.
  Refusal is a HANGUP full-frame — the universal IAX call-
  teardown signal.
- **Offensive BACnet write-gate** (`offensive/write/bacnet`).
  UDP per-datagram BACnet confirmed-service allowlist. Closes
  the v1.2 carry-over where BACnet's Handle loop was stuck at
  session-primitives because the generic TCP proxy framework
  didn't apply. Always-passes unconfirmed-requests, acks /
  errors / rejects / aborts, and confirmed-reads; gates
  WriteProperty / WritePropertyMultiple / AtomicWriteFile /
  AddListElement / RemoveListElement / CreateObject /
  DeleteObject / ReinitializeDevice / DeviceCommunicationControl
  / LifeSafetyOperation. Refusal is a BVLC-wrapped Abort-PDU
  with ASHRAE 135 §20.1.9 reason 5 (security-error).
- **CLI dry-run for all three PBX gated proxies.** New
  subcommands `elsereno write sip dry-run`, `write iax2
  dry-run`, `write pbxhttp dry-run`. Each prints the
  SessionMutation PayloadHash + canonicalised allowlist; with
  `--vault-passphrase-file`, also mints the expected confirm-
  token the operator pastes into the eventual `proxy listen`
  verb.
- **`cwmp` plugin** — TR-069 / CWMP ACS fingerprint on port
  7547/tcp. Identifies 15 ACS implementations including
  GenieACS, FreeACS, Axiros (AXACS / AX-MDM), Nokia Altiplano,
  Huawei FusionHome, Broadcom BroadWorks, Cisco Prime, ADB,
  Friendly TR-069 Simulator, interaCMS, Netopia, create-net,
  plus generic open-ACS and TR-069 markers. VendorRisk tiers
  80-90 (exposed ACS is always a finding — the 2016 Deutsche
  Telekom / Mirai port-7547 outage is the cautionary reference).
- **`internal/protocols/bacnet/wire/service.go`** — ASHRAE 135
  APDU classification helpers used by the BACnet write-gate.
  APDUType enum, ConfirmedService enum (Table 20-7),
  IsMutatingConfirmedService predicate, BuildAbortPDU helper.

### Changed

- Plugin count in the default build: **16 → 17** (+cwmp).
- Offensive write-gated proxies: **2 → 5** (+ sip, iax2,
  pbxhttp, bacnet alongside the existing modbus and opcua).
- The v1.2 BACnet carry-over is resolved: BACnet no longer
  ships with only session primitives; it has a full wire-level
  UDP gate.

### Deferred to v1.5

- `proxy listen` CLI verb: promote the existing stub to
  actually run the gated handlers inline against a real
  listener.
- OPC UA per-NodeId allowlist (tighter gate than the service-
  TypeID-level of v1.2).
- BACnet per-object allowlist (ASN.1 BER parsing).
- SIP To-URI E.164 prefix allowlist for INVITE (toll-
  destination blocking).
- REGISTER AOR allowlist.
- CWMP offensive proxy (SOAP RPC allowlist).
- HTTP paths beyond `/` for pbxhttp fingerprint (vendor-
  specific `/admin/config.php`, `/webclient/`, `/ccmadmin/`).
- VoIP-SIP dial backend subprocess.
- `dial batch --backend` CLI wiring.
- Audit daemon for cross-process JSONL.
- seccomp arg-level filtering.

## [1.3.0] — 2026-04-22

### Added

- **PBX discovery cycle.** Three new protocol plugins collectively
  identify 15 PBX brands across the canonical PBX attack surfaces,
  bringing the default build to **16 protocol plugins**.
- **`pbxhttp`** plugin — HTTP(S) PBX admin-page fingerprint on
  443 (also 80 / 8080 / 8088 / 5001 / 8443 via Scheme override).
  Single GET to `/` with a browser-like User-Agent; classifies
  response Server / HTML `<title>` / body against a priority-
  ordered 15-vendor matcher (FreePBX, PBXact, 3CX, Yeastar,
  Cisco UCM, Avaya, Mitel, Grandstream, Fanvil, Yealink, Asterisk
  HTTP Manager, Switchvox, Elastix, FreeSWITCH, plus unknown
  PBX-likely heuristic). `protocol_risk` tiers 70–90 by vendor
  class (attack-ripe / enterprise / SOHO / gateway / unknown).
  Self-signed cert tolerance (`InsecureSkipVerify=true` default)
  for fingerprinting use-case; gosec waiver documented in code.
- **`iax2`** plugin — Asterisk's native binary UDP protocol on
  port 4569. Minimal RFC 5456 full-frame parser (12-byte header;
  FrameType + IAXSubclass enums). Probe sends a random-call
  number NEW, classifies reply by subclass: ACCEPT / AUTHREQ /
  REJECT / HANGUP / PING / PONG / REG\* all confirm IAX2 →
  `protocol_risk=90`. ACCEPT triggers a polite HANGUP so the
  remote dialogue table doesn't grow. Mini-frame-length-
  mismatch guard prevents HTTP bytes (0x48 = 'H' has high bit 0
  → looks like a mini-frame) from falsely confirming IAX2.
- **`sip`** plugin — SIP OPTIONS probe on 5060 UDP+TCP with a
  15-vendor matcher: Asterisk, FreePBX, 3CX, Cisco UCM, Cisco
  SIP Gateway, Mitel (+ ShoreTel), Avaya (+ IP Office), Yeastar,
  Grandstream, Fanvil, Yealink, Kamailio, OpenSIPS, FreeSWITCH,
  SER. DenyAll proxy emits a canonical `SIP/2.0 403 Forbidden`
  with `Server: ElSereno proxy (read-only)`.

### Changed

- Plugin count in the default build: **13 → 16**. Plugin list
  now includes `iax2`, `sip`, `pbxhttp` alongside the existing
  atg / atmodem / bacnet / banner / dnp3 / enip / fox / hartip /
  iec104 / modbus / opcua / s7 / xot.

### Deferred to v1.4

- Offensive write-gated proxies for SIP / IAX2 / pbxhttp (the
  default variants deny all; INVITE / HANGUP / admin-API
  allowlist variants are v1.4).
- TR-069/CWMP fingerprint on 7547/tcp.
- VoIP-SIP dial backend subprocess (`elsereno-dial-voip-sip`).
- HTTP paths beyond `/` for pbxhttp (`/admin/config.php`,
  `/webclient/`, `/ccmadmin/`, etc. for vendor-specific recall).

## [1.2.0] — 2026-04-22

### Added

- **DB-backed dashboard panels**: new `findings`, `triage`, and
  `runs` panels on the overview page, plus `/api/v1/findings`,
  `/api/v1/runs`, `/api/v1/triage` endpoints. Fetch on page
  load + re-fetch on SSE signals (500 ms debounce). Without
  `DATABASE_URL` the endpoints return 503 and the panels
  render a clear "backend unavailable" message.
- **`internal/audit.DBWriter`** persists the audit chain to
  Postgres, preserving the same chain invariant as FileWriter.
  Reserves BIGSERIAL IDs via `nextval` before INSERT so the
  JCS hash is computed once.
- **`audit.MultiWriter`** + `FileMirror` + `DBMirror` —
  fan-out from one primary chain owner to N mirrors. Primary
  error halts fan-out; mirror error surfaces without
  reverting the primary insert.
- **`audit.SyncFromFile(ctx, path, target, existingIDs)`** —
  bootstrap a fresh DB from an existing JSONL chain. Validates
  every prev_hash + entry_hash, skips IDs already in target,
  idempotent + tamper-detecting.
- **OPC UA write gating** (`offensive/write/opcua/`): service-
  layer allowlist on Write (TypeID 673) and Call (704)
  requests. Refusal is a UA ServiceFault with StatusCode
  BadUserAccessDenied (0x80100000) — parseable by real UA
  clients.
- **Full wire-level Handle loops** for DNP3, IEC-104, HART-IP,
  ATG Veeder-Root, and Fox. Each gate refuses disallowed
  operations with a protocol-native error frame
  (DNP3 IIN2 FUNC_NOT_SUPP, IEC-104 I-format COT=47,
  HART response code 0x40, Veeder-Root NAK 9999FF1B,
  Fox `fox a 0 -1 fox denied\n`).
- **Dial backend interface** (`offensive/dial/backend/`):
  `Backend{Name, Deliver, Close}` + `Disposition` enum.
  Two backends ship: `Mock` (CI-safe scriptable) and
  `ATModem` (Hayes AT over any io.ReadWriter).
- **`/admin/security` CSP-nonce fix**: inline styles on the
  security self-audit page now honour the per-request CSP
  nonce (same treatment the overview page got in v1.1).
- **`/readyz` real DB ping** when a pool is wired, 503 on DB
  failure, adds `uptime_s` field.
- **Operator manual pack**: `docs/manual/elsereno-manual.md`
  (400+ lines, all 13 protocols, Shodan/Censys/nmap input
  recipes, scoring, offensive verbs, detection signatures,
  troubleshooting) + `docs/manual/cheatsheet.txt` (terminal-
  ready) + `docs/manual/elsereno-manual.docx` (pandoc-rendered
  with TOC). Plus `AUTHORS` + `TODO-vNext.md` (operator-
  requested forward-looking TODO with PBX discovery called
  out).
- **`scripts/dev-db.sh`** helper: up / down / reset / status /
  env verbs; writes `~/.elsereno/dev-db.env` (0600) with the
  DATABASE_URL export line.

### Changed

- **SLSA L3 provenance** now minted via GitHub's native
  `actions/attest-build-provenance@v2` (SLSA v1.0 predicate,
  Sigstore keyless, transparency log). Replaces
  `slsa-framework/slsa-github-generator` reusable workflow
  (exit-27 bug in v2.0.0 + v2.1.0, never fixed upstream).
  Verify with `gh attestation verify <artifact> --repo` or
  `cosign verify-attestation --type slsaprovenance1 …`.
- `handlers.APIV1()` now takes an `APIV1Deps{Broadcaster,
  Querier}` bundle. Missing deps downgrade individual
  endpoints to 503 without breaking the router.
- `.claude/settings.json` permissions allowlist expanded by
  35 patterns (docker compose / buildx, cosign verify-only,
  goreleaser snapshot, git tag -s, curl with safe flags).

### Removed

- **`-tags sqlite` portable variant** retired. Dockerfile.sqlite
  deleted; goreleaser `elsereno-sqlite` build gone;
  Makefile `build-sqlite` + `docker-sqlite` targets gone;
  CI `build-sqlite` job gone; `.golangci.yml` sqlite
  build-tag gone. Postgres is the only supported backend
  from v1.2. Operators running SQLite: see the migration
  path at the top of ADR-012 (now `superseded`).

### Fixed

- HART-IP handler now correctly distinguishes long- vs short-
  frame delimiters via the HIGH bit (0x80) per HART-FSK
  §9.1.2 — a low-nibble interpretation in the initial draft
  was wrong.
- ATModem read path no longer loses read-ahead bytes between
  phases (shared bufio.Reader cached on the struct).
- ATModem dialTimeout is now authoritative — `readUntilResult`
  runs the read in a goroutine + selects on ctx.Done so a
  stream without deadlines (net.Pipe) still honours the
  timeout.

## [1.1.0] — 2026-04-21

### Added — new features

- **Per-plugin offensive `WriteGatedHandler`** (ADR-040 close).
  `offensive/write/<proto>/gatedproxy.go` for modbus / s7 / enip
  with full wire-level Handle and protocol-native refusal frames
  (IllegalFunction, S7 AckData err-class 0x85, ENIP encapsulation
  status 0x0001). Session primitives (`AllowlistHash` +
  `SessionMutation`) for bacnet / dnp3 / iec104 / hartip / atg /
  fox; full Handle loops for those six ship in v1.2.
- **File-backed audit writer** at `~/.elsereno/audit.jsonl`
  (mode 0600, parent dir 0700). Chain-resumable across process
  restarts; `audit.VerifyFile` walks the chain end-to-end.
  `offensive/confirm/adapter.go` maps `confirm.AuditEvent` to
  `audit.Entry` without a schema migration.
- **Offensive CLI network delivery**: `elsereno write modbus
  send`, `elsereno exploit run`, `elsereno audit verify-file`
  tied together by `cmd/elsereno/offensive_runtime.go` (vault +
  writer + actor helper).
- **Server-Sent Events** at `GET /api/v1/stream`: process-local
  `internal/web/stream.Broadcaster` with channel-per-subscriber
  fan-out, `audit.FileWriter.SetObserver` hook, and
  `stream.TailAudit` cross-process file tailer so offensive
  verbs running in separate processes light up the dashboard.
  The dashboard inline template now carries a live-feed panel
  (EventSource, CSP-nonce whitelisted).
- **GHCR docker image** via goreleaser's `dockers_v2` block —
  multi-arch (linux/amd64 + linux/arm64) at
  `ghcr.io/robinr00t/elsereno:<tag>` + `:latest`, with
  `sbom: true` (CycloneDX) + `--attest=type=provenance,mode=max`
  attestations and cosign-keyless manifest signatures.
  `docker/setup-buildx-action@v3` + `docker/setup-qemu-action@v3`
  added to `release.yml` so the multi-arch + attestation
  pipeline works end-to-end.
- **Seccomp-bpf sandbox** for offensive subprocesses
  (ADR-042). `offensive/sandbox/bpf_linux.go` compiles
  per-profile denylist BPF programs; `installFilter` installs
  via `seccomp(SECCOMP_SET_MODE_FILTER, TSYNC)` so every
  goroutine-backing thread is covered. Profiles: `exploit`
  (base blocklist), `harvest` (+ file mutators), `dial` (+
  network openers). Wired into `write modbus send`,
  `exploit run`, `harvest *`, and `dial batch`. Integration
  tests fork a child and verify ptrace + socket return EPERM
  on native Linux.
- **OPC UA plugin** on port 4840. `internal/protocols/opcua/
  wire/` parses UA-TCP Part 6 §7.1 Hello/Acknowledge/Error
  frames; the probe classifies ACK / ERR / non-UA bytes.
  Default `ProxyHandler` refuses with a UA-native ERR frame
  (Bad_ResourceLimitsExceeded + "denied"). Write-gating
  (SecureChannel + Session + Write service) deferred to v1.2.
- **Wardialing batch** via `elsereno dial batch --numbers-file
  <path> --scope <scope.yaml>` — reads one number per line,
  classifies each against the ADR-041 dial guard, and appends
  one `offensive_dial` audit entry per decision. The seccomp
  `dial` profile is installed before classification. Default
  disposition is "preview" (audit-only dry-run); actual modem /
  VoIP delivery is a v1.2 carry-over.

### Changed

- `Dockerfile` + `Dockerfile.sqlite` pin Go 1.25.4 to match
  `go.mod`'s `go 1.25.0` requirement (previous 1.23.4 pin no
  longer passed `go mod download`).
- `elsereno dial` is now an umbrella verb with `validate`
  (single-number check, former top-level body) and `batch`
  (wardialing batch) subcommands.
- Dashboard auto-refresh interval extended from 30 s → 120 s
  because the SSE live feed replaces the need for frequent
  full-page reloads.

### Fixed

- CSP nonce is now threaded through request context via
  `internal/web/httpctx`; the dashboard's inline `<script>` and
  `<style>` tags carry matching `nonce` attributes. Inline
  styles were previously blocked by the Content-Security-Policy
  in most browsers (silent degradation to unstyled output).
- Legacy top-level `migrations/` directory removed; the
  `internal/db/migrations/` embed used by goose is the single
  source of truth. The audit-events-vs-SQL sync test walks
  every migration in order.

## [1.0.1] — 2026-04-21

### Fixed — release surface polish
- **cosign bundle**: goreleaser's `signs:` block now passes
  `--bundle=${artifact}.bundle` so the release publishes
  `checksums.txt.bundle` alongside the raw `checksums.txt.sig`.
  Consumers can run `cosign verify-blob --bundle checksums.txt.bundle
  …` without fetching the signing cert out-of-band.
- **SLSA provenance**: bumped `slsa-github-generator` from
  `v2.0.0` → `v2.1.0`. The v2.0.0 finaliser emitted exit 27
  (`SUCCESS=false`) even on a successful upload path, which is
  why v1.0.0 shipped without `.intoto.jsonl` assets. v2.1.0
  (2025-02-24) fixes the false-negative.
- **Pandoc pin**: release workflow installs pandoc 3.9.1 from
  the upstream `.deb` (was distro apt-get). Deterministic man-
  page output removes the reason we had to strip the strict
  "verify man pages in sync" step in the workflow.

### Changed — README
- Badge row (semver release, MIT licence, Go 1.25+, CI status,
  supply-chain status, SLSA 3).
- "Quick install (signed release)" section with the curl +
  shasum -c recipe + optional cosign bundle verification.
- Non-interactive vault-unlock snippet using
  `--vault-passphrase-file` pointing at ADR-026.

## [1.0.0] — 2026-04-20

### Added — F0 Scaffolding (closed 2026-04-19)
- Hexagonal Go 1.23 skeleton: `internal/core`, `internal/config`,
  `internal/exec` with `SafeCommand` + `CommandSpec`, `internal/audit`
  (placeholder chain), `internal/db` (goose migrations embed),
  `internal/render.SafeBytes`.
- Full `.context/` tree: 36 PITFs, 26 ADRs, templates, canonical
  docs, snapshots scaffolding.
- CI pipeline (lint + build ×3 + race/cover + fuzz smoke + sec +
  context-check), Makefile, Dockerfile + Dockerfile.sqlite,
  docker-compose.dev.yml, `.goreleaser.yml`, scripts, man sources.
- Root docs: `README.md`, `SECURITY.md`, `LEGAL.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `NON-GOALS.md`, `TODO.md`, `CLAUDE.md`.

### Added — F1 Inputs/scanner/scoring/triage/observability (closed 2026-04-19)
- Cobra CLI with `version/doctor/legal/plugins/config/scoring/vault/
  creds/db/audit/serve/scan/explain/why/triage/lint/fmt`.
- Koanf loader with unknown-field rejection (`ErrUnknownConfigField`).
- Zerolog with redaction hook (specific patterns + entropy >4.5 b/B +
  UUID v1–v5 exemption, PITF-004).
- Prometheus with low-cardinality label sanitiser (ASN numeric,
  country ISO 3166-1).
- pgx pool with ADR-021 TLS policy; goose migration runner via
  `pgx/v5/stdlib.OpenDBFromPool`.
- Real JCS audit canonicaliser (RFC 8785 via `gowebpki/jcs`).
- Encrypted vault at `~/.elsereno/vault.v1.bin` (AES-GCM +
  Argon2id + HKDF + memguard). CSRF key derived via HKDF from the
  vault master key.
- Scanner: A+AAAA+IDN resolve, dedupe, concurrent probes with global
  + per-host semaphores, token-bucket rate limiting, exponential
  backoff + jitter retries, circuit breaker, 5-minute temporal
  dedupe.
- Triage grouping (quick-win / strategic / routine).
- Outputs: NDJSON (schema `ndjson:v1`), CSV (`csv:v1`), HTML
  (`html:v1`).
- Shodan + Censys HTTP clients.
- Progress bars honouring `NO_COLOR`.
- Outbox worker with dead-letter after `max_attempts`.
- Retention with keep-if-referenced rule encoded in the Pruner
  interface.
- Web server scaffold (full timeouts, security headers, CSP nonces,
  `/healthz`, `/readyz`, CSRF via HKDF).
- banner plugin (first real Protocol).
- Integration test scaffold at `test/integration/` +
  `simulators/docker-compose.test.yml`.

### Added — F2 Legacy telephony (closed 2026-04-19)
- XOT (RFC 1613) plugin + simulator. TPKT/X.25 wire parser with 3
  fuzz targets (ADR-027).
- AT-modem plugin (Hayes / GSM / EN 81-28) + simulator. Line-
  oriented state machine with 64 KiB ceiling and `+CME/+CMS`
  error-code extraction. Vendor dictionary for Siemens, Nokia,
  Sierra, MultiTech, Cinterion, Telit, u-blox, Quectel, Huawei,
  KONE, Otis, Schindler. Proxy blocks ATD*, ATA, AT+CMGS, AT+CMGW,
  AT+CMSS, AT+CMGD, AT+CFUN, AT+CPWROFF, `+++` (ADR-028).
- Milestone: repo pushable to private GitHub.

### Added — F3 Proxy + Modbus (closed 2026-04-19)
- `internal/proxy`: generic TCP framework with Accept + Dial +
  per-connection idle deadline + symmetric Hook interface
  (PreHook with rewrite + PostHook observer). `LoggingHook` routes
  through `render.SafeBytes` (ADR-029).
- Modbus/TCP plugin (ADR-030): from-scratch MBAP + PDU parser,
  FC classifier (read / write / diagnostic / MEI / unknown),
  exception helper, FC 43/14 Device ID decoder, 3 fuzz targets.
  Probe sends FC 1 Read Coils + opportunistic FC 43/14. Proxy
  enforces the write-ban at the wire layer: every CategoryWrite
  FC, non-14 MEI sub-code, or Unknown FC is replied with
  IllegalFunction without touching upstream.
- `simulators/modbus/` (Go) for deterministic CI + pymodbus pointer
  for operator-driven richer scenarios.
- Chaos helpers under `test/chaos/` (`-tags chaos`):
  RandomDropReader, LatencyReader, FlipBitsWriter, EarlyCloser.
- Integration test exercising the proxy framework end-to-end.

### Added — F4 ICS plugins + dashboard + API (closed 2026-04-19)
- Eight new plugins, all with from-scratch wire parsers + probe +
  fuzz + ADR + protocol doc:
  `s7` (TPKT/COTP, 102), `enip` (EtherNet/IP CIP ListIdentity,
  44818), `bacnet` (BVLC Who-Is, UDP/47808), `dnp3` (IEEE 1815
  link frame, 20000), `iec104` (APCI TESTFR, 2404), `hartip`
  (session initiate, 5094), `fox` (Niagara Fox banner, 1911/4911),
  `atg` (Veeder-Root I20100, 10001). 12 plugins registered in the
  default build.
- `banner.DetectVendor()` with Moxa / Lantronix / Digi / NetBurner
  / KONE / Otis / Schindler / OpenSSH rules.
- Dashboard MVP at `/` (inline HTMX-ready HTML listing plugins);
  read-only API at `/api/v1/{plugins,scoring,health}` with envelope
  `{"schema":"api:v1","data":…}`.
- OpenAPI 3.1 spec at `docs/openapi.yaml`.
- Conpot honeypot added to `simulators/docker-compose.test.yml`
  with port maps for all new protocols.
- ADR-031..038.
- Fuzz-found panic in ENIP ListIdentity parser (truncated body)
  fixed with tighter bounds + corpus regression guard.

### Added — F5 Offensive build (closed 2026-04-19)
- ADR-039 triple-confirm wrapper (build tag + `--accept-writes` +
  `--confirm-target` + HMAC-SHA256 token derived via HKDF from the
  vault master key). Every Authorize call emits an audit event —
  allowed, denied, or failed — with payload hash but never the
  plaintext payload.
- ADR-040 per-plugin proxy write-gating. Every TCP-based plugin
  now refuses non-read frames at the wire layer in the default
  build with a protocol-native refusal response (S7 AckData
  err-class 0x85, ENIP status 0x0001, DNP3 FC 15 "Not Supported",
  IEC-104 STOPDT_act, HART-IP session-close status 0x04, ATG
  `9999FF1B` Data-Error). Fox is fail-closed; BACnet (UDP) errors
  immediately under the TCP proxy framework.
- ADR-041 dial guard. Unbypassable ≤3-digit hard block, plus
  scope.yaml `blocked_numbers` prefix/exact match. Wardialing
  batch stays vNext.
- ADR-042 Linux seccomp-bpf sandbox scaffold via pure-Go
  `golang.org/x/sys/unix.Prctl` (`PR_SET_NO_NEW_PRIVS`); BPF
  filter sequences land with F6 subprocess integrations.
- `offensive/write/{modbus,s7,enip,bacnet}` — write plugins with
  deterministic SHA-256 payload hashes. Modbus FC 5/6/15/16; S7
  WriteVar / PLC Stop / PLC Restart; ENIP Set Attribute Single /
  Reset; BACnet WriteProperty (UDP BVLC).
- `offensive/dial/Validate` — three-gate validator (normalise →
  hard ≤3-digit → scope blocked-numbers).
- `offensive/harvest` — Prober interface + four implementations:
  telnet (IAC negotiation + login state machine), ftp (RFC 959),
  http-basic (RFC 7617 with challenge-first), snmp (SNMPv2c
  GetRequest for sysDescr.0 with hand-crafted ASN.1 BER).
- `offensive/exploits` — registry-based harness + two public,
  stable DoS modules: **CVE-2015-5374** (Siemens SIPROTEC 4 /
  Compact EN100 UDP DoS) and **CVE-2019-10953** (Schneider /
  Allen-Bradley / Phoenix Contact CIP ListIdentity DoS).
- `internal/canary` — Sender interface + HTTP sender that POSTs
  `canary:v1` JSON envelopes with optional HMAC-SHA256 signature.
- `internal/scope.(*Scope).CheckDial` — scope side of the dial
  guard.
- `internal/exec.CommandSpec.AllowAnyPath` + `BypassAuditor` —
  `--no-allowlist` escape hatch; refuses to spawn when the
  audit auditor is missing or errors.

### Added — F6 Reporting + release (closed 2026-04-20)
- Five new output sinks: CEF 0.1 (ArcSight; 1..10 severity,
  sorted extensions), RFC 5424 syslog (facility local1 with
  `elsereno@32473` SD-ID), JIRA Cloud REST v3 (ADF description,
  severity→priority mapping), GitHub Issues REST (Bearer PAT +
  2022-11-28 API pin + markdown factor table), and a generic
  HMAC-SHA256-signed webhook.
- HTML report polish: dark-mode palette, per-protocol sections
  with count / max / avg, top-5 factor histogram, severity chips
  with level-specific colours.
- OpenAPI 3.1 autogenerada: `internal/web/openapi.Spec()` is the
  single source of truth; `GET /api/v1/openapi.yaml` serves it
  live; `elsereno api openapi [-o <path>]` refreshes the on-disk
  snapshot.
- Offensive CLI verbs behind `-tags offensive`:
  `elsereno write modbus` (dry-run PDU + payload hash),
  `elsereno exploit list|show|dry-run`,
  `elsereno harvest {telnet,ftp,http-basic,snmp}`,
  `elsereno dial --number <E.164>` with the three-gate
  validator in isolation. Default build unchanged (stub).
- `--vault-passphrase-file <0600 path>` on `vault init`,
  `vault unlock`, `serve`. `os.Lstat` rejects symlinks / pipes /
  devices; mode `perm &^ 0o600 != 0` rejects lax permissions;
  empty-file rejection; CRLF stripping. ADR-026 / PITF-016.
- Operator docs at `docs/protocols/` (12 per-plugin pages +
  README) covering probe bytes, proxy default policy, writes
  behind offensive build, scope + impact, public references.
- Dashboard polish (`/`): dark-mode, plugin grouping (default
  vs offensive), scoring sidebar (ADR-006 weights + severity
  thresholds), auto-refresh pending SSE.
- `RELEASING.md` operator runbook: goreleaser v2 dry-run
  recipe, SBOM via syft (CycloneDX 1.6), cosign keyless
  Sigstore signing + receiver verification, tagging /
  rollback.
- `.goreleaser.yml` migrated `archives.builds` →
  `archives.ids` (goreleaser v2).

### Added — F7 Hardening + 1.0 (closed 2026-04-20)
- Dockers_v2 migration (final goreleaser v2 deprecation cleared)
  + nightly per-target fuzz matrix (30 min per `Fuzz*` target)
  with artefact-uploaded corpora.
- Regression benchmarks: `benchmarks/baseline.txt` checked in;
  benchstat CI comments on every PR with the delta vs base;
  strict mode turns ≥ 10 % regressions into failures.
- OpenTelemetry tracing scaffolding: env-driven exporter
  (`none`/`stdout`/`otlp`), scanner retry/attempt loop emits
  spans with target/port/attempt/plugin attributes.
- 6 STRIDE threat-model docs under `.context/threat-model/`
  (vault-audit, web, scanner-proxy, exec-scope, offensive,
  telemetry-canary) with per-surface residual-risk policy.
- Supply-chain automation at `.github/workflows/supply-chain.
  yml`: OpenSSF Scorecard nightly, SLSA L3 provenance verify
  on tag, dependency-review with licence deny-list (GPL/AGPL/
  LGPL/SSPL/Commons-Clause/Elastic-2.0), osv-scanner,
  licenses-audit artefact.
- `internal/backup`: AES-256-GCM envelope (magic + version +
  salt + nonce + ciphertext) with two-stage HKDF key
  derivation. Salt bound into AEAD AAD so salt-swap attacks
  fail closed. 10 unit tests cover every tamper mode.
- `elsereno backup {create,restore,inspect}` CLI verbs
  honouring `--vault-passphrase-file` for non-interactive
  startup.
- Pentest dashboard panel at `/admin/security`: 11 in-process
  controls with status pills, code-path + ADR references, and
  links to all 6 threat-model docs + every external sec-suite
  job.
- `scripts/release-gate.sh` + `make release-gate`: 11 local
  checks (tests, lint, context, docs, goreleaser snapshot,
  sec-suite, benchmarks baseline) gate the v1.0 tag locally.
- `RELEASING.md` 1.0 section + new `SUPPLY-CHAIN.md` root doc
  with SLSA mapping + dep policy + SBOM diff recipe +
  secrets-rotation table.

### Current phase
**v1.0.0 signed release** is the next milestone (operator
task; `make release-gate` must be green on a clean tree).
See `.context/STATE.md` for authoritative live state,
`.context/snapshots/f7-hardening-1.0.md` for the last
retrospective.
