---
phase: any
status: canonical
last-updated: 2026-04-19
---

# .context/ INDEX

Catálogo de ficheros de contexto. Las columnas *Trigger* y *Token budget*
guían la carga: cargar sólo lo necesario; `_quickref` + `STATE` + `conventions`
+ `pitfalls` siempre.

| File | Purpose | Phase | Token budget | Last updated | Trigger |
|------|---------|-------|-------------:|-------------|---------|
| `_quickref.md` | One-pager with stack + invariants | any | 900 | 2026-04-19 | Always |
| `STATE.md` | Current phase + in-progress work | any | 300 | 2026-04-19 | Always |
| `conventions.md` | Go style, testing, security hard rules | any | 2500 | 2026-04-19 | Always |
| `pitfalls.md` | Anti-pattern catalogue (PITF-001..036) | any | 5500 | 2026-04-19 | Always before editing |
| `architecture.md` | Package layout, module boundaries | any | 2000 | 2026-04-19 | Cross-cutting change |
| `glossary.md` | Shared vocabulary (ICS terms, domain) | any | 600 | 2026-04-19 | New contributor / protocol work |
| `scoring.md` | Scoring factors, weights, severities | any | 1500 | 2026-04-19 | Scoring work |
| `persistence.md` | Schema, migrations, retention | any | 2000 | 2026-04-19 | DB / audit work |
| `web.md` | HTTP server, auth, CSRF, rate limits | any | 1800 | 2026-04-19 | Web work |
| `testing-strategy.md` | Unit / fuzz / integration / e2e | any | 1200 | 2026-04-19 | Test work |
| `security-model.md` | Threat model, controls, sandbox | any | 1500 | 2026-04-19 | Security-sensitive change |
| `CHANGELOG.md` | One-liners per significant change | any | — | 2026-04-19 | After significant edit |
| `decisions/001..038.md` | ADRs (F0: 001-026; F2: 027-028; F3: 029-030; F4: 031-038) | — | 1200 each | — | When a decision is referenced |
| `protocols/_index.md` | Protocol catalogue (12 plugins, all implemented through F4) | any | 800 | 2026-04-19 | Protocol work |
| `protocols/<name>.md` | Per-protocol notes | protocol phase | 1500 each | — | Only for the protocol in scope |
| `templates/*.md` | Templates for ADR / protocol / pitfall / snapshot | — | — | 2026-04-19 | When creating a new doc |
| `snapshots/f0..f4-*.md` | Phase-closing snapshots (F0, F1, F2, F3, F4 all closed) | — | 1000 each | — | Post-phase retrospective |

## Current phase (2026-04-19)

F4 closed. Next is **F5 — offensive build** (`-tags offensive`):
writes / exploits / harvest / dial with triple confirm, seccomp-bpf
sandbox on Linux (ADR-010 supplementary), canary webhook, per-plugin
proxy write-gating for the 7 new F4 plugins. See `STATE.md` for
authoritative live state.
