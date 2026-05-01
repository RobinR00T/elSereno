---
phase: any
status: canonical
last-updated: 2026-05-01
token-budget: 2200
---

# TUI (interactive terminal UI)

## Status
v1.29 ships `elsereno tui` — bubbletea-based read-only viewer.
Default + offensive builds include it; the **mini** build excludes
the bubbletea / lipgloss / bubbles ecosystem to keep the device
binary small (`build-mini` ≈ 21 MB vs default ≈ 23 MB stripped).

## Verb
```
elsereno tui [--replay FILE | --feed - | --watch URL --bearer TOKEN]
```

The four flag groups are mutually exclusive. Without any flag the
TUI opens with the **Empty** feed — the panes render but no events
flow. Useful as a smoke test that the program starts cleanly.

| Flag             | Mode          | Source                                    |
|------------------|---------------|-------------------------------------------|
| (none)           | interactive   | `feeds.Empty` (no events)                 |
| `--replay FILE`  | replay        | `feeds.Replay` reading ndjson:v1 file     |
| `--feed -`       | feed (stdin)  | `feeds.Stdin` reading ndjson:v1 from pipe |
| `--watch URL`    | watch (SSE)   | `feeds.Watch` consuming `/api/v1/stream`  |

`--feed FILE` is rejected — that's `--replay`'s job. `--bearer`
without `--watch` is silently ignored.

## Layout
Four panes, lipgloss-styled, sized off `tea.WindowSizeMsg`:

```
┌─────────────────────────────────────────────────────────────┐
│ elsereno tui — mode=replay  src=…/shift.ndjson              │
├──────────────┬──────────────────────────┬───────────────────┤
│ scan         │ findings (cursor=12/40)  │ triage            │
│ 47%          │ 95 critical modbus 10.0… │ critical  3       │
│ (94 / 200)   │ 82 high     s7     10.0… │ high      7       │
│              │ 74 high     mms    10.0… │ medium   12       │
│              │ …                        │ low       9       │
│              │                          │ info     14       │
├──────────────┴──────────────────────────┴───────────────────┤
│ audit                                                       │
│ 12:00:01 vault_unlock by alice                              │
│ 12:00:03 run r-abc started                                  │
│ …                                                           │
└─────────────────────────────────────────────────────────────┘
```

Pane order (Tab cycle): findings → triage → audit → scan → findings.

## Key bindings
| Key            | Action                                      |
|----------------|---------------------------------------------|
| `q` / `ctrl+c` | quit                                        |
| `tab`          | focus next pane                             |
| `shift+tab`    | focus previous pane                         |
| `j` / `down`   | findings cursor +1 (only on findings pane)  |
| `k` / `up`     | findings cursor −1                          |
| `g` / `home`   | findings cursor → 0                         |
| `G` / `end`    | findings cursor → last                      |

Other panes are observe-only — j/k/g/G are routed to no-ops when
the focused pane is not findings.

## Architecture

```
cmd_tui.go ─┐
            └─→ pickFeed() ─→ tui.Feed (interface)
                                  │
                                  ├── feeds.Empty       (interactive)
                                  ├── feeds.Replay      (file)
                                  ├── feeds.Stdin       (pipe)
                                  └── feeds.Watch       (SSE)

tui.Run(ctx, mode, feed, out, in)
   ├── tea.NewProgram(model, AltScreen, ctx)
   └── go feed.Run(ctx, prog.Send)
```

Each Feed is a goroutine; it calls `emit(tea.Msg)` for every event
and returns when the source is exhausted or `ctx` cancels. The
runner pushes a `FeedClosedMsg{Mode, Err}` after Run returns so
the audit pane records the closure.

`tui.Model` is a pure-data struct — no I/O. `Update(tea.Msg)` folds
events into the next state; `View()` renders without side effects.
This shape lets unit tests drive Update + View directly without
spinning up a tea.Program.

## Wire formats

### NDJSON (replay + feed)
Identical to `internal/outputs/ndjson` (schema `ndjson:v1`):
```json
{"schema":"ndjson:v1","run_id":"…","target_id":"…","address":"…",
 "port":502,"protocol":"modbus","severity":"high","score":85,
 "factors":{…},"created_at":"2026-04-29T12:00:00Z"}
```
One record per line. Records with the wrong schema are skipped + a
synthetic AuditMsg ("ndjson: skipped line N: unknown schema …")
surfaces in the audit pane. Bad JSON is treated the same way —
**a single corrupt line never aborts a feed**.

### SSE (watch)
The dashboard's `/api/v1/stream` (handler at
`internal/web/handlers/stream.go`):
```
event: <kind>
id: <int64>
data: <single-line JSON object>
<blank line>
```
Kinds dispatched: `finding`, `audit`, `run_start`, `run_end`. An
unknown kind becomes a `tui.AuditMsg` ("watch: unknown event …")
so a future schema bump doesn't silently drop events.

### Reconnect contract (watch)
- Default 3 s retry interval (matches the server's `retry:` hint).
- Unbounded retries by default (interactive sessions live until
  q); `MaxRetries` bounds bench/script cases.
- 401 / 403 wrapped in `feeds.authError` + short-circuits the
  retry loop. Operator needs a fresh token, not another retry.
- `: keepalive` SSE comments (server emits every 15 s) are
  silently consumed.

## Build tag matrix
| Target    | Tags                      | Includes TUI |
|-----------|---------------------------|--------------|
| default   | (none)                    | yes          |
| offensive | `offensive`               | yes          |
| mini      | `mini`                    | **no**       |

Mini variant gets a stub verb (`cmd_tui_mini.go`) that prints a
descriptive error and exits with `EX_UNAVAILABLE` (69), so an
operator who runs `elsereno tui` against the wrong tarball sees:
```
elsereno: tui is not available in this build (the mini variant
excludes the bubbletea/lipgloss UI dependencies …)
```
…instead of cobra's "unknown command".

## ADRs touched
- ADR-005 (CLI must compile without web tree) — `feeds.Watch`
  duplicates the SSE payload structs locally rather than importing
  `internal/web/stream`. Wire format is the contract; duplication
  is annotated.
- ADR-006 (severity bands) — TUI's `severityOf(score)` mirrors the
  scoring service's bands. Test `TestAddFindingBucketing` gates
  every band edge.

## Test coverage (v1.29)
- `internal/tui/model_test.go` — 9 tests (Model state mutations)
- `internal/tui/update_test.go` — 7 tests (tea.Msg routing,
  key bindings)
- `internal/tui/feeds/replay_test.go` — 8 tests (file source,
  malformed line, schema mismatch, pacing, cancel)
- `internal/tui/feeds/stdin_test.go` — 7 tests (pipe semantics,
  EOF clean, cancel + close, defaults)
- `internal/tui/feeds/watch_test.go` — 13 tests (SSE decoding,
  4 event kinds, auth, retry, unknown kind, multi-line data)

Total: 44 tests, all passing under `-race`.

## Known limitations
- **Interactive mode** (no flag) currently uses `feeds.Empty`. The
  in-TUI scan launcher is a future enrichment — for now, drive
  the TUI from `--feed -` against a live `elsereno scan` pipe.
- **`teatest` integration** (full program-level tests) is deferred;
  the per-component coverage above gates the public surface.
- **Audit-pane filtering** (e.g. show only kind=audit) is not yet
  wired; operators see the full stream chronologically.
