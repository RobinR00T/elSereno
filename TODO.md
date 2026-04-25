# ElSereno — Original brief checklist

The original v1.0 brief checklist. **Closed 2026-04-25** —
v1.12.0 shipped, every brief item is delivered (some during F0–F7,
some via the v1.1–v1.12 release cycles).

For the live state see `.context/STATE.md`. For the post-1.0
backlog see [`ROADMAP.md`](ROADMAP.md). For the forward-looking
ideas list (PBX, Shodan paginación, IPv6, …) see
[`TODO-vNext.md`](TODO-vNext.md).

## Operator-pending (no coding involved)

- [ ] **Revoke the bootstrap PAT** —
  `https://github.com/settings/personal-access-tokens` +
  `rm ~/.elsereno/gh-token`. Live since 2026-04-23 (~2 days
  exposure window).
- [ ] **Flip repo to public** — unlocks Scorecard / CodeQL /
  OSV full suite. Post-v1.12 decision.
- [ ] **Restore GitHub Actions billing** — re-enables cosign +
  SLSA + GHCR supply-chain layer. Free-tier flow (since v1.8)
  ships GPG-signed tag + SHA-256 + CycloneDX SBOMs locally.

## Brief delivery (compressed history)

The original brief had 7 phases plus a "vNext" wishlist. Every
phase closed during v1.0 (2026-04-19 → 2026-04-21). The vNext
items have either shipped during v1.2–v1.12 or moved to the
forward-looking lists:

| Brief item | Where it landed |
|------------|-----------------|
| F0 — Scaffolding (cobra, koanf, audit chain, vault, telemetry, scoring, scope, doctor, exec, web server) | v1.0 |
| F1 — Inputs (shodan/censys/list/stdin/nmapxml), scanner, scoring, triage, observability | v1.0 |
| F2a — XOT plugin + simulator | v1.0 |
| F2b — atmodem plugin + simulator | v1.0 |
| F3 — TCP proxy framework + Modbus read/write-ban | v1.0 |
| F4 — Plugins S7/ENIP/BACnet/DNP3/IEC-104/HART-IP/Fox/ATG/banner | v1.0 |
| F5 — Offensive writes (Modbus/S7/CIP/BACnet) + exploits + harvest + dial + sandbox seccomp-bpf | v1.0 |
| F6 — Reporting (HTML/CEF/Syslog/Webhook) + OpenAPI + dashboard polish + offensive CLI wiring | v1.0 |
| F7 — Hardening + supply-chain (Scorecard, SLSA L3, OSV, OTel, backup, benchstat, release-gate) | v1.0 |
| vNext: OPC UA | v1.1 chunk 7 |
| vNext: Wardialing batch | v1.1 chunk 8 |
| vNext: Per-plugin offensive proxy gates | v1.1 chunks 1, v1.4 chunks 1–6 |
| vNext: SSE live scans | v1.1 chunk 4a |
| vNext: ONYPHE/FOFA/ZoomEye/Shodan-InternetDB inputs | v1.8 chunks 1-2 + v1.9 chunks 3-4 + v1.12 chunk 9 |
| vNext: PBX discovery (SIP/IAX2/pbxhttp) | v1.3 chunks 1-3 |
| vNext: TR-069/CWMP fingerprint | v1.4 chunk 5 |
| vNext: TR-069/CWMP gated proxy | v1.11 chunk 1 |
| vNext: BACnet UDP relay | v1.4 chunk 6 |
| vNext: per-object/per-path scoping across the 7 write-gates | v1.12 chunks 1–7, 10 + v1.13 chunks 3, 7 (BACnet WPM + DeleteObject) |
| vNext: input pagination | v1.12 chunk 8 |
| vNext: bulk InternetDB lookup | v1.13 chunk 1 |
| vNext: CWMP firmware pre-flight verifier + RPC case-warning + CWMP-over-TLS recipe | v1.13 chunks 2, 4, 5 |
| vNext: triage `utility` bucket | v1.13 chunk 6 |

## Brief items still open (moved to v1.13+ backlog)

| Item | Notes | Tracker |
|------|-------|---------|
| L2 PROFINET DCP/GOOSE/SV (gopacket) | Layer-2 + raw sockets; needs CAP_NET_RAW | ROADMAP.md |
| 11 legacy ICS protocols (CoDeSys, Omron FINS, MELSEC SLMP, PCWorx, ProConOS, Crimson, GE-SRTP, IEC 61850 MMS, KNX, M-Bus, DLMS/COSEM) | One ciclo per protocol (~v1.4 sized) | ROADMAP.md |
| Windows support | Replace `syscall.*` per-platform; AppContainer / Job Objects vs seccomp | ROADMAP.md |
| Multi-user OIDC + roles | Auth system rewrite | ROADMAP.md |
| Record & replay proxy sessions | New subsystem | TODO-vNext.md |
| MITM transparent routing | Outside scope of "audited proxy" — operator-mode decision | TODO-vNext.md |
| STIX 2.1 export | Output sink, contained | ROADMAP.md |
| TUI bubbletea | New UX layer | TODO-vNext.md |
| IPv6 cross-cutting support | Operator-requested 2026-04-25 | ROADMAP.md |

The CHANGELOG entry for **v1.12.0** (2026-04-25) closes every
gate-tightening + input-pagination carry-over from v1.6–v1.11.

**v1.13 in flight on `main`** (no tag yet) — closes:
- BACnet per-object scoping for WPM (svc 16) + DeleteObject
  (svc 11) — chunks 3 + 7.
- InternetDB bulk lookup (file + stdin) — chunk 1.
- CWMP carry-overs from v1.11: firmware pre-flight verifier
  (chunk 2), RPC case-warning (chunk 4), CWMP-over-TLS
  operator recipe (chunk 5).
- Triage `utility` bucket — chunk 6 (was on TODO-vNext as a
  "Tools operativas" item).
- `make sec` ratchet fix — `b611f5c` swapped 18
  `//nolint:gosec` to native `// #nosec`.

Operator decides when to cut `v1.13.0`.
