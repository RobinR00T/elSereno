# ElSereno, Original brief checklist

The original v1.0 brief checklist. **Closed 2026-04-25** with
v1.12.0; the items still open then are tracked in the table at the end,
refreshed against `v2.62.0` on 2026-10-18.

For the live state see `.context/STATE.md`. For the post-1.0
backlog see [`ROADMAP.md`](ROADMAP.md). For the forward-looking
ideas list (PBX, Shodan paginación, IPv6, …) see
[`TODO-vNext.md`](TODO-vNext.md).

## Operator-pending (no coding involved)

Status as of 2026-10-18 (latest tag `v2.62.0`; `main` is well past it, untagged: `git describe --tags` gives the count).

- [ ] **Revoke the bootstrap PAT**: 
  `https://github.com/settings/personal-access-tokens` +
  `rm ~/.elsereno/gh-token`. Created 2026-04-23; revocation pending
  (operator action).
- [x] **Flip repo to public**: done; `gh repo view` reports
  `"visibility":"PUBLIC"` (checked 2026-10-18).
- [x] **GitHub Actions**: the April 2026 stop was the org
  `allowed_actions=local_only` policy, not billing; fixed 2026-08-29,
  and ci / release / supply-chain / nightly / benchmarks run on `main`
  again (`.context/STATE.md`, 2026-08-31). Open part: no public OCI
  image; an anonymous pull of `ghcr.io/robinr00t/elsereno` answers
  `denied` (2026-10-18), and INSTALL builds the image locally.

## Brief delivery (compressed history)

The original brief had 7 phases plus a "vNext" wishlist. Every
phase closed during v1.0 (2026-04-19 → 2026-04-21). The vNext
items have either shipped during v1.2-v1.12 or moved to the
forward-looking lists:

| Brief item | Where it landed |
|------------|-----------------|
| F0, Scaffolding (cobra, koanf, audit chain, vault, telemetry, scoring, scope, doctor, exec, web server) | v1.0 |
| F1, Inputs (shodan/censys/list/stdin/nmapxml), scanner, scoring, triage, observability | v1.0 |
| F2a, XOT plugin + simulator | v1.0 |
| F2b, atmodem plugin + simulator | v1.0 |
| F3, TCP proxy framework + Modbus read/write-ban | v1.0 |
| F4, Plugins S7/ENIP/BACnet/DNP3/IEC-104/HART-IP/Fox/ATG/banner | v1.0 |
| F5, Offensive writes (Modbus/S7/CIP/BACnet) + exploits + harvest + dial + sandbox seccomp-bpf | v1.0 |
| F6, Reporting (HTML/CEF/Syslog/Webhook) + OpenAPI + dashboard polish + offensive CLI wiring | v1.0 |
| F7, Hardening + supply-chain (Scorecard, SLSA L3, OSV, OTel, backup, benchstat, release-gate) | v1.0 |
| vNext: OPC UA | v1.1 chunk 7 |
| vNext: Wardialing batch | v1.1 chunk 8 |
| vNext: Per-plugin offensive proxy gates | v1.1 chunks 1, v1.4 chunks 1-6 |
| vNext: SSE live scans | v1.1 chunk 4a |
| vNext: ONYPHE/FOFA/ZoomEye/Shodan-InternetDB inputs | v1.8 chunks 1-2 + v1.9 chunks 3-4 + v1.12 chunk 9 |
| vNext: PBX discovery (SIP/IAX2/pbxhttp) | v1.3 chunks 1-3 |
| vNext: TR-069/CWMP fingerprint | v1.4 chunk 5 |
| vNext: TR-069/CWMP gated proxy | v1.11 chunk 1 |
| vNext: BACnet UDP relay | v1.4 chunk 6 |
| vNext: per-object/per-path scoping across the 7 write-gates | v1.12 chunks 1-7, 10 + v1.13 chunks 3, 7 (BACnet WPM + DeleteObject) |
| vNext: input pagination | v1.12 chunk 8 |
| vNext: bulk InternetDB lookup | v1.13 chunk 1 |
| vNext: CWMP firmware pre-flight verifier + RPC case-warning + CWMP-over-TLS recipe | v1.13 chunks 2, 4, 5 |
| vNext: triage `utility` bucket | v1.13 chunk 6 |

## Brief items: where they stand on `v2.62.0` (2026-10-18)

Checked against `elsereno plugins list` (35 protocol plugins in the
default build), `elsereno --help` and `git log`.

| Item | State | Evidence |
|------|-------|----------|
| L2 PROFINET DCP/GOOSE/SV | **Partly done.** GOOSE/SV: offline decode and a passive monitor, live on Linux through an AF_PACKET socket (no gopacket). PROFINET DCP: offline codec only (`profinet decode`, `encode-identify`); no live identify | `goose`, `profinet` verbs; c4787af (2026-09-23), 1e919d0 (v2.39) |
| 11 legacy ICS protocols (CoDeSys, Omron FINS, MELSEC SLMP, PCWorx, ProConOS, Crimson, GE-SRTP, IEC 61850 MMS, KNX, M-Bus, DLMS/COSEM) | **Done as fingerprint plugins**: codesys (+ opt-in codesys-active), finsudp, slmp (+ melsoft), pcworx, proconos, redlion, gesrtp, mms, knxip, mbustcp, dlms. Offensive write-gates wired in `proxy listen` for finsudp, slmp, gesrtp, codesys, redlion; the dlms, knxip and mbustcp gates exist but no command reaches them | `plugins list`; 42c60cf (2026-08-31); TODO-vNext "write-gates huérfanos" |
| Windows support | **Cross-compile only** (default and mini builds, v2.34). No native sandbox (seccomp has no Windows twin; AppContainer / Job Objects not started) | `.goreleaser.yml` `goos: [linux, darwin, windows]`; 5ec0cab |
| Multi-user OIDC + roles | **Done for the API**: OIDC Bearer JWT with viewer / operator / admin roles (v2.43 config, v2.48 routes, v2.59 serve wiring); required off loopback. The HTML dashboard has no login of its own | `internal/web/auth/roles.go`; da33edc |
| Record & replay proxy sessions | **Done in the offensive build**: `proxy listen --record` and `proxy replay FILE` (v1.27-v1.30) | `cmd/elsereno/cmd_proxy_replay_offensive.go` |
| MITM transparent routing | **Open**, outside "audited proxy"; operator-mode decision | TODO-vNext.md |
| STIX 2.1 export | **Done**: `scan --output-format stix` (v1.15) | `internal/outputs/stix/` |
| TUI bubbletea | **Done**: `elsereno tui` (v1.29) | dc15e69 |
| IPv6 cross-cutting support | **Done** (v1.14) | MANUAL FAQ |

Still open beyond this table: DNP3 SAv5 gating, the live L2 PROFINET
identify, native Windows sandboxing, MITM routing, and the product
decisions listed in `TODO-vNext.md` (Modbus constant score, notes that
reach no output, the three orphan write-gates, and others).

Releases are cut by the operator. The last tag, `v2.62.0`, is from
2026-05-23; everything on `main` after it, from the 2026-08
legacy-ICS write-gates to PITF-099 and the PITF-100 rate limit, is
untagged (`git describe --tags` gives the commit count). The last
GitHub Release with binaries is `v2.37.0` (2026-05-16): tags v2.38 to
v2.62 were pushed without release assets.
