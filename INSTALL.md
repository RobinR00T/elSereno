# Installing ElSereno

ElSereno ships as a **single static binary** (Go pure-stdlib, `CGO_ENABLED=0`). It runs on **any Linux ≥ kernel 2.6.32** and **macOS ≥ 11 (Big Sur)**, both `amd64` and `arm64`. No runtime dependencies, no shared libraries to install.

This document covers every supported install method, the per-platform feature matrix, and which path to pick.

---

## TL;DR — pick your path

| Use case | Best path | OS |
|---|---|---|
| **SOC server / always-on dashboard** | `apt install ./elsereno_<v>_amd64.deb` (or `.rpm`) | Linux |
| **Operator workstation, occasional scans** | Tarball into `~/bin/` | macOS or Linux |
| **Pen-test laptop with offensive verbs** | `elsereno-offensive` package or tarball | macOS or Linux |
| **Embedded / jump host / restricted device** | `elsereno-mini` package | Linux (typical) |
| **Air-gapped lab / kiosk** | Tarball + `cosign verify-blob` | either |
| **CI / build pipeline** | OCI image `ghcr.io/robinr00t/elsereno` | container |
| **K8s / Nomad / fleet rollout** | OCI image (distroless) + manifests | container |

---

## Build variants

ElSereno ships **three variants** in every release. Operators install the one that matches their threat model:

| Variant | Build tag | Binary name | Includes | Excludes | Size (stripped) |
|---|---|---|---|---|---|
| **default** | (none) | `elsereno` | All read-only verbs (scan, discover, explain, triage, audit, …) + dashboard (`serve`) + TUI (`tui`) + 28 fingerprint plugins | offensive verbs (write/exploit/harvest/dial) | **23.0 MB** |
| **offensive** | `offensive` | `elsereno-offensive` | Everything in default + writes/exploits/harvest/dial behind triple-confirm fences | nothing | **23.7 MB** |
| **mini** | `mini` | `elsereno-mini` | Everything in default minus the dashboard + OpenAPI machinery + TUI | `serve`, `api`, `tui` (stub error → use default) | **21.3 MB** |

### Which variant?

- **Default** is what you want unless you have a specific reason. Read-only auditing of ICS/OT exposure. The dashboard + TUI ship here.
- **Offensive** for authorised pen-test work. The triple-confirm fences (`--accept-writes` + `--confirm-target` + `--confirm-token` + a vault-derived audit key) prevent accidental writes; the binary still requires explicit operator opt-in for every mutation.
- **Mini** for embedded / jump-host / restricted-device deployments where the dashboard isn't needed and a smaller binary is preferred. Excluded code = excluded attack surface.

You can install **default + offensive together** on the same host (binaries have different names). Mini is mutually exclusive with the others (you'd just install one).

---

## Linux

### deb / rpm / apk packages (recommended for Linux servers)

Available since **v1.49**. Three packages per format:

```sh
# Debian / Ubuntu
sudo apt install ./elsereno_1.49.0_amd64.deb
# or:
sudo dpkg -i elsereno_1.49.0_amd64.deb && sudo apt-get install -f

# RHEL / CentOS / Fedora / Rocky / Alma
sudo dnf install ./elsereno-1.49.0-1.x86_64.rpm
# or with rpm directly:
sudo rpm -i elsereno-1.49.0-1.x86_64.rpm

# Alpine
sudo apk add --allow-untrusted ./elsereno-1.49.0.apk
```

**Available package names**: `elsereno` (default), `elsereno-offensive`, `elsereno-mini`. They can coexist.

What the deb/rpm install:

| Path | Owner | Mode | Purpose |
|---|---|---|---|
| `/usr/bin/elsereno` (or `-offensive` / `-mini`) | root | 0755 | binary |
| `/etc/elsereno/elsereno.yaml` | elsereno:elsereno | 0640 | config (sample, marked `noreplace`) |
| `/etc/elsereno/` | elsereno:elsereno | 0750 | config dir |
| `/usr/lib/systemd/system/elsereno-serve.service` | root | 0644 | dashboard daemon unit |
| `/usr/lib/systemd/system/elsereno-audit.service` | root | 0644 | audit fan-in daemon unit |
| `/usr/lib/tmpfiles.d/elsereno.conf` | root | 0644 | runtime + state dirs |
| `/usr/share/doc/elsereno/` | root | 0755 | LICENSE / SECURITY / sample config |
| `/usr/share/man/man1/elsereno.1` | root | 0644 | manpage |
| `/var/lib/elsereno/` | elsereno:elsereno | 0750 | persistent state (audit chain, vault) |
| `/var/log/elsereno/` | elsereno:elsereno | 0750 | logs |

The `elsereno` system user + group are created on `preinstall`. Persistent state survives uninstall (`apt remove`); only `apt purge` should ever wipe `/var/lib/elsereno`.

### systemd units

Two units ship and are **disabled by default**:

```sh
# Dashboard + /api/v1
sudo systemctl enable --now elsereno-serve.service

# SOC fan-in audit daemon (Unix-domain socket; optional)
sudo systemctl enable --now elsereno-audit.service
```

Hardening baked in: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `MemoryDenyWriteExecute`, empty `CapabilityBoundingSet`, `SystemCallFilter=@system-service ~@mount @swap @reboot @debug @cpu-emulation`, `SystemCallArchitectures=native`. The daemon doesn't need any capabilities — it uses Go's `net` package for IO.

### Tarball install (any Linux, no root)

```sh
curl -LO https://github.com/RobinR00T/elSereno/releases/download/v1.49.0/elsereno_1.49.0_linux_amd64.tar.gz
tar -xzf elsereno_1.49.0_linux_amd64.tar.gz
sudo mv elsereno /usr/local/bin/
elsereno doctor
```

For air-gapped / paranoid:

```sh
# Verify checksum
sha256sum -c checksums.txt
# Verify cosign signature (sigstore keyless)
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp 'https://github.com/RobinR00T/elSereno/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
# Verify SBOM (CycloneDX)
syft scan elsereno -o cyclonedx-json | diff - elsereno_1.49.0_linux_amd64.tar.gz.cyclonedx.json
```

### OCI image

```sh
docker run --rm -p 8787:8787 \
  -v /etc/elsereno:/etc/elsereno:ro \
  -v elsereno-state:/var/lib/elsereno \
  ghcr.io/robinr00t/elsereno:1.49.0 serve
```

The image is **distroless** (`gcr.io/distroless/static-debian12:nonroot`). No shell, no package manager, no SUID binaries. Image is signed (cosign keyless) and ships a CycloneDX SBOM as an OCI referrer:

```sh
cosign verify ghcr.io/robinr00t/elsereno:1.49.0 \
  --certificate-identity-regexp 'https://github.com/RobinR00T/elSereno/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
cosign download sbom ghcr.io/robinr00t/elsereno:1.49.0
```

---

## macOS

### Tarball install (no Homebrew yet)

```sh
# Apple Silicon
curl -LO https://github.com/RobinR00T/elSereno/releases/download/v1.49.0/elsereno_1.49.0_darwin_arm64.tar.gz
tar -xzf elsereno_1.49.0_darwin_arm64.tar.gz
sudo mv elsereno /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/elsereno  # if downloaded via browser
elsereno doctor

# Intel
curl -LO https://github.com/RobinR00T/elSereno/releases/download/v1.49.0/elsereno_1.49.0_darwin_amd64.tar.gz
…
```

The binary is **not notarised** because the project doesn't ship through the Mac App Store. If you downloaded via a browser, Gatekeeper will refuse to run it the first time. Strip the quarantine xattr (above) or use Homebrew once a tap exists (planned for v1.5x).

### launchd (manual; no native package yet)

For "always running" on macOS, write your own launchd plist:

```xml
<!-- /Library/LaunchDaemons/dev.elsereno.serve.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>           <string>dev.elsereno.serve</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/elsereno</string>
        <string>serve</string>
        <string>--config</string>
        <string>/etc/elsereno/elsereno.yaml</string>
    </array>
    <key>RunAtLoad</key>       <true/>
    <key>KeepAlive</key>       <true/>
    <key>UserName</key>        <string>elsereno</string>
    <key>StandardOutPath</key> <string>/var/log/elsereno/serve.out</string>
    <key>StandardErrorPath</key><string>/var/log/elsereno/serve.err</string>
</dict>
</plist>
```

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.elsereno.serve.plist
```

### Sandbox

Two build modes available since **v1.50**:

| Mode | Sandbox | How to build | Trade-off |
|------|---------|--------------|-----------|
| **Default macOS** (release tarball) | `sandbox: unavailable on darwin` warning; offensive verbs run with OS-level mitigations only (TCC, hardened runtime, SIP) | `make build-offensive` — `CGO_ENABLED=0`, fully static | No kernel sandbox; relies on macOS OS-level controls |
| **Sandboxed macOS** (opt-in build) | `sandbox_init(3)` enforced per-profile (.sb Scheme) for harvest/dial/exploit subprocesses | `make build-offensive-darwin-sandboxed` — `CGO_ENABLED=1` | Binary links against `libSystem.B.dylib` (SDK-version specific); not in release tarballs |

The opt-in mode applies a `.sb` Scheme profile per subprocess type:

  - **exploit** — full network access (the exploit IS the test) but `(deny process-exec)` so a successful RCE on the target can't pivot back to the operator's host. File writes restricted to `/tmp` + `/private/var/folders`.
  - **harvest** — `(allow network-outbound (remote tcp))` for the harvest endpoint, but `(deny process-exec)` and file writes restricted to `/tmp` only.
  - **dial** — `(deny network*)` (the subprocess only talks via inherited TTY/serial FDs). `(allow file-write* (subpath "/dev/tty"))` for legitimate UART config.

If you need fully-static + sandboxed on macOS at the same time: not possible (Apple's sandbox API is C-only). For full sandbox enforcement on a static binary, use the **Linux build** — seccomp-bpf has been wired up for harvest + dial profiles since v1.27 and works without cgo.

### OCI image

The image runs in Docker Desktop / Colima / OrbStack identically:

```sh
docker run --rm ghcr.io/robinr00t/elsereno:1.49.0 doctor
```

---

## Per-platform feature matrix

| Feature | Linux | macOS | OCI image | Notes |
|---|---|---|---|---|
| All scan/discover/audit verbs | ✅ | ✅ | ✅ | core functionality |
| Dashboard + TUI | ✅ | ✅ | ✅ (default tag) | TUI excluded from mini |
| Offensive proxy listen + write/exploit | ✅ | ✅ | offensive tag image | triple-confirm fences |
| seccomp-bpf sandbox for harvest / dial | ✅ | ❌ | ✅ | macOS uses sandbox_init via opt-in cgo build (v1.50+) |
| macOS `sandbox_init(3)` (cgo-gated) | n/a | ✅ via `build-offensive-darwin-sandboxed` | n/a | v1.50+; NOT in release tarballs |
| systemd integration | ✅ deb/rpm | ❌ | ❌ | use launchd manually on macOS |
| deb / rpm / apk packages | ✅ v1.49+ | ❌ | n/a | |
| Static binary (no libc) | ✅ | ✅ | ✅ | `CGO_ENABLED=0`; verifiable with `file` |
| Cosign signature on artefacts | ✅ | ✅ | ✅ | sigstore keyless |
| CycloneDX SBOM | ✅ | ✅ | ✅ (OCI referrer) | per-archive + per-image |
| SLSA v1.0 build provenance | ✅ | ✅ | ✅ | GitHub Attestations API |

### Linux advantages

- **Native packaging** (deb/rpm/apk via nfpm). One command to install. systemd units + log rotation + tmpfiles drop-in handled.
- **Full sandbox** via seccomp-bpf for the offensive verbs (harvest + dial).
- **No quarantine xattr** dance.
- **Smaller community/CI matrix to test against** — the project's CI gates Linux first.

### macOS advantages

- **Operator UX**: most pen-testers and SOC analysts run macOS daily; install + run without a VM.
- **TCC + hardened runtime** as a parallel mitigation layer (no equivalent on Linux).
- **No need for systemd** — launchd ships in the OS.
- **Apple Silicon perf** for crypto-heavy workloads (the audit chain hashing benefits).

---

## Verifying the install

After install, regardless of method:

```sh
elsereno doctor          # validates config + reachability + version
elsereno legal           # required acknowledgement on first use
elsereno version --json  # machine-readable: version, commit, date, build tags
```

`elsereno doctor` returns non-zero on any environmental issue (missing config, unreachable Postgres, vault locked, etc.) so it's safe in CI.

---

## Upgrading

### Distro packages

```sh
sudo apt update && sudo apt install elsereno     # apt picks up the new version
sudo systemctl restart elsereno-serve            # if the daemon was running
```

The `noreplace` flag on `/etc/elsereno/elsereno.yaml` means upgrades don't clobber operator edits — apt prompts on conflict, dnf saves to `.rpmnew`.

### Tarball

```sh
sudo cp /usr/local/bin/elsereno /usr/local/bin/elsereno.bak  # rollback insurance
sudo cp ./elsereno /usr/local/bin/elsereno
elsereno version
```

### OCI image

Pin to a specific tag in your manifest. `latest` is a convenience tag; production should pin to `1.49.0` etc.

---

## Uninstalling

### Distro packages

```sh
sudo systemctl stop elsereno-serve elsereno-audit          # automatic on remove
sudo apt remove elsereno         # keeps /etc, /var/lib, /var/log
sudo apt purge elsereno          # also removes config + state (DANGER)
```

State directories are intentionally preserved on `remove` so an operator who reinstalls keeps their audit chain + vault. Use `purge` only when fully decommissioning.

### Tarball

```sh
sudo rm /usr/local/bin/elsereno
sudo rm -rf /etc/elsereno /var/lib/elsereno /var/log/elsereno   # if applicable
```

### OCI image

`docker rmi ghcr.io/robinr00t/elsereno:1.49.0`. Volumes (state) survive image removal.

---

## Build from source

ElSereno needs Go 1.25+ and `make`. No cgo, no C toolchain, no Postgres dev headers.

```sh
git clone https://github.com/RobinR00T/elSereno
cd elSereno
make build              # default variant only
make build-offensive    # adds offensive
make build-mini         # adds mini
make ci                 # full lint + test + race + cover + fuzz + sec
```

Binaries land in `bin/`. To produce the deb/rpm/apk locally:

```sh
goreleaser release --snapshot --clean --skip=publish,docker
ls dist/*.deb dist/*.rpm dist/*.apk
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `command not found: elsereno` | not on `$PATH` | move binary to `/usr/local/bin/` or `~/bin/` (latter must be in PATH) |
| Gatekeeper blocks first run on macOS | quarantine xattr | `xattr -d com.apple.quarantine /path/to/elsereno` |
| `elsereno serve` exits with `vault locked` | vault not unlocked | `elsereno vault init && elsereno vault unlock`; for unattended: stage 0600 passphrase file + set `ELSERENO_VAULT_PASSPHRASE_FILE` |
| systemd unit refuses to start with `code=exited, status=64/USAGE` | invalid config | `elsereno doctor` to find the offending field; check `journalctl -u elsereno-serve` |
| `permission denied` on `/run/elsereno/audit.sock` | socket dir not yet created | `systemctl restart systemd-tmpfiles-setup` or reboot; the unit's `RuntimeDirectory=` covers this on start |
| Mini binary missing `tui` | by design | `tui` not available in mini; install the default package alongside (`elsereno tui`) or switch variants |
| OCI image `permission denied` writing audit | distroless `nonroot` user | mount a writable volume at `/var/lib/elsereno` owned by uid 65532 |

---

## Scan orchestration (v1.58+)

The `serve` verb can host a dashboard-driven scan-orchestration
endpoint family at `/api/v1/scans/`. Two flags control it:

| Flag | Default | Meaning |
|------|---------|---------|
| `--scan-store` | `off` | Backend: `off` (endpoints return 503), `memory` (in-process, jobs lost on restart), `db` (postgres-persistent, requires `DATABASE_URL`). |
| `--scan-pool` | `2` | Worker pool concurrency, clamped to `[1, 64]`. |

### Memory mode (development / on-demand operator runs)

```sh
elsereno serve --scan-store memory --scan-pool 4
```

No DB required. Submitted jobs run via the in-process worker
pool. Restarting `serve` loses queued jobs.

### DB mode (production)

```sh
DATABASE_URL=postgres://elsereno:****@127.0.0.1:5432/elsereno \
  elsereno db migrate          # ensure 00005_scan_jobs migration is applied
elsereno serve --scan-store db --scan-pool 4
```

Jobs survive restart. Two `serve` instances pointing at the
same DB safely race on the same job queue: the atomic
`UPDATE ... WHERE state IN (queued)` guarantees at most one
worker claims each job (no advisory locks needed).

### Submitting a job

**Dashboard (v1.62+)**: open http://127.0.0.1:8787/ and use
the "Scan jobs" panel. The submit form takes an input string,
plugin list, and default port; v1.63+ pushes state transitions
via SSE so the table updates in real time. The polling timer
stays as a safety net (2s while a job is queued/running, 10s
once everything is terminal). Each non-terminal row has a
Cancel button.

**Plugin selection (v1.64+)**:

- **One plugin** — name it: `modbus`
- **Multiple plugins** — comma-separate: `modbus,s7,enip`
  Each target gets every named plugin whose `DefaultPort`
  matches the target's port.
- **All plugins** — leave the field blank. The runner uses
  every registered plugin in the build (default-build
  registry; offensive plugins gated by `-tags offensive`).

**Autocomplete (v1.68+)**: the dashboard's plugin-name field is
backed by a native `<datalist>` populated from
`GET /api/v1/plugins` on page load. Click into the field and
the browser shows the full registered-plugin set with their
default ports + descriptions. Typing a prefix narrows the
suggestions. The dropdown is a discoverability aid for the
first plugin name; multi-token autocomplete after a comma is
not supported by `<datalist>` (a smarter tokenizing widget is
deferred).

**Scheduled scans (v1.70+)**: save a Job template that fires
automatically on a fixed interval (v1.70) or cron expression
(v1.73+). Useful for "scan my fleet every 6 hours" or "every
weekday at 09:00" continuous-monitoring workflows.

**Dashboard panel (v1.72+)**: open the dashboard and use the
"Scheduled scans" section. Create form takes name + input +
plugin(s) + interval (60s..7d). The table lists every saved
schedule with Edit / Enable/Disable / Delete buttons. The
intervals column renders human-friendly labels (`60` → `1m`,
`21600` → `6h`, `86400` → `1d`).

**Edit (v1.74+)**: each row's Edit button populates the create
form with the schedule's current values + flips the submit
button to "Update". Cancel button (visible only in edit mode)
resets back to create. ID, CreatedAt, LastFiredAt, Operator,
and Enabled survive the edit untouched — only the editable
fields (name, template, cadence) change. Curl path:

```sh
curl -X PUT http://127.0.0.1:8787/api/v1/schedules/{id} \
  -H "Content-Type: application/json" \
  -H "X-Operator: alice" \
  -d '{"name":"renamed","template":{"input":"list:fleet.txt","plugins":["modbus"]},"cron_expr":"0 9 * * 1-5"}'
```

Validation matches Create: name + template.input non-empty;
exactly one cadence (interval_seconds or cron_expr); cron
must parse if specified.

**curl path still works** (operator scripts / CI):

```sh
# Create:
curl -X POST http://127.0.0.1:8787/api/v1/schedules \
  -H "Content-Type: application/json" \
  -H "X-Operator: alice" \
  -d '{"name":"every-6h","template":{"input":"list:fleet.txt","plugins":["modbus"]},"interval_seconds":21600}'

# List + view:
curl http://127.0.0.1:8787/api/v1/schedules
curl http://127.0.0.1:8787/api/v1/schedules/{id}

# Toggle without delete (preserves history):
curl -X POST http://127.0.0.1:8787/api/v1/schedules/{id}/disable
curl -X POST http://127.0.0.1:8787/api/v1/schedules/{id}/enable

# Remove permanently:
curl -X DELETE http://127.0.0.1:8787/api/v1/schedules/{id}
```

`interval_seconds` is clamped to `[60, 604800]` (1 minute to
7 days). The Scheduler ticks every 30s (default; clamped
[10s, 5min]); a schedule whose `(LastFiredAt + IntervalSeconds)`
has passed fires on the next tick. Never-fired schedules fire
immediately.

**Cadence modes (v1.73+)**: a schedule chooses between
**interval** (every N seconds) or **cron** (5-field
expression). Exactly one is set per schedule:

| Mode      | Field             | Example                   |
|-----------|-------------------|---------------------------|
| interval  | `interval_seconds` | `21600` (every 6 h)      |
| cron      | `cron_expr`        | `0 2 * * *` (daily 02:00) |

The cron parser supports the standard 5-field syntax:

  - `*` (any), `N` (single), `N,M,...` (comma list),
    `N-M` (range), `*/S` (step), `N-M/S` (stepped range).
  - Day-of-month + day-of-week use Unix-cron OR semantics
    when both are restricted.
  - **Named shortcuts (v1.76+)**: `@yearly` / `@annually`
    (= `0 0 1 1 *`), `@monthly` (= `0 0 1 * *`),
    `@weekly` (= `0 0 * * 0`),
    `@daily` / `@midnight` (= `0 0 * * *`),
    `@hourly` (= `0 * * * *`). Lookup is case-insensitive.
    The schedule stores the operator's input verbatim so
    the dashboard renders `cron: @daily`, not the expanded
    form.
  - **Not supported**: `@reboot` (one-shot semantics don't
    fit periodic schedules), named months/weekdays
    (JAN..DEC, SUN..SAT), last-of-month / weekday-of-month.

```sh
# Cron-based schedule:
curl -X POST http://127.0.0.1:8787/api/v1/schedules \
  -H "Content-Type: application/json" \
  -H "X-Operator: alice" \
  -d '{"name":"weekday-am","template":{"input":"list:fleet.txt","plugins":["modbus"]},"cron_expr":"0 9 * * 1-5"}'
```

The dashboard form has a cadence-mode dropdown that toggles
between an "interval (s)" number input and a "cron" text input.
Submitting both → 400; submitting neither → 400.

**Timezone (v1.75+)**: cron schedules accept an optional
`timezone` field (IANA name) so the cron expression
evaluates against the operator's wall-clock instead of UTC:

```sh
# "Every weekday at 09:00 New York time":
curl -X POST http://127.0.0.1:8787/api/v1/schedules \
  -H "Content-Type: application/json" \
  -H "X-Operator: alice" \
  -d '{"name":"ny-9am","template":{"input":"list:fleet.txt","plugins":["modbus"]},"cron_expr":"0 9 * * 1-5","timezone":"America/New_York"}'
```

Validation uses `time.LoadLocation` (Go stdlib). The accepted
zone names match the host tzdata bundle — typo or
unknown-zone → 400 `schedules: scanorch: schedule timezone
invalid`. Empty / omitted timezone falls back to UTC
(back-compat with v1.73/v1.74 cron schedules).

DST is honored: a cron at `30 2 * * *` keeps firing at
local 02:30 across the spring-forward transition (skipping
to next valid local time the day of the gap). The dashboard
shows the timezone in the Interval column for cron
schedules: `cron: 0 9 * * 1-5 (America/New_York)`.

**Next-fire preview (v1.77+)**: the schedules table renders
a "Next fire" column with the predicted next firing time.
Schedules whose predicted next fire is already in the past
(overdue) are tagged so operators see at a glance which
ones will trigger on the next tick. The Create/Edit form
also has a "Preview next fire" button — clicking it sends
the current form values to `/api/v1/schedules/preview` and
shows the predicted next fire below the submit row,
including the timezone label for cron schedules:

```sh
# curl path:
curl -X POST http://127.0.0.1:8787/api/v1/schedules/preview \
  -H "Content-Type: application/json" \
  -d '{"name":"x","template":{"input":"stdin"},"cron_expr":"0 9 * * 1-5","timezone":"America/New_York"}'
# → {"data":{"next_fire_at":"...","timezone":"America/New_York"}}
```

The preview endpoint validates the same way as Create
(name + template.input non-empty; exactly one cadence;
cron parses if specified; timezone resolves via
`time.LoadLocation`). 400 surfaces the same sentinels as
Create. The preview is store-independent — no schedule is
created, no DB write happens.

**Multi-fire preview (v1.79+)**: pass `?count=N` (default 1,
capped at 10) to receive the next N firings as a
`next_fires` array. `next_fire_at` is preserved as
`next_fires[0]` for back-compat with v1.77/v1.78 callers.
The dashboard's "Preview next fire" button in cron mode
now requests `count=5` and renders an ordered list so
operators can sanity-check non-trivial patterns at a glance.

**Live preview (v1.80+)**: changes to any cadence field in
the dashboard form (mode dropdown / interval / cron /
timezone) trigger an auto-preview after a 350ms debounce —
operators see the predicted fire(s) update as they type.
The manual "Preview next fire" button remains as a
force-refresh.

```sh
# Next 5 fires for a weekday-09:00-NY schedule:
curl -X POST "http://127.0.0.1:8787/api/v1/schedules/preview?count=5" \
  -H "Content-Type: application/json" \
  -d '{"name":"x","template":{"input":"stdin"},"cron_expr":"0 9 * * 1-5","timezone":"America/New_York"}'
# → {"data":{"next_fire_at":"...", "next_fires":["...","...","...","...","..."], "timezone":"America/New_York"}}
```

**Optimistic locking (v1.78+)**: the dashboard's edit form
uses an `If-Match` header to prevent concurrent edits from
overwriting each other silently. Each schedule carries an
`updated_at` timestamp (RFC3339Nano) that bumps on every
edit. When the dashboard sends a PUT, it includes the
schedule's `updated_at` from when the form was loaded:

```sh
# curl path:
curl -X PUT http://127.0.0.1:8787/api/v1/schedules/{id} \
  -H "Content-Type: application/json" \
  -H "If-Match: 2026-05-10T19:00:00Z" \
  -H "X-Operator: alice" \
  -d '{"name":"renamed","template":{"input":"list:fleet.txt","plugins":["modbus"]},"cron_expr":"0 9 * * 1-5"}'
```

If another operator updated the schedule between read and
write, the server returns **412 Precondition Failed** and
the schedule is unchanged. The dashboard surfaces this as
"schedule was modified by another operator — refresh and
retry"; operator-driven `curl` scripts can detect 412 and
retry-with-fresh-read.

`If-Match` is **optional** — pre-v1.78 callers (and any
script that doesn't care about racy edits) can omit the
header and the precondition is skipped. Migration 00010
backfills `updated_at = created_at` on existing rows so
upgrades are non-disruptive.

**Persistence (v1.71+)**: the schedule store is automatically
chosen to match `--scan-store`:

| `--scan-store` | Schedule store     | Survives restart? |
|----------------|--------------------|-------------------|
| `memory`       | MemoryScheduleStore | No  |
| `db`           | DBScheduleStore (migration 00007) | Yes |
| `off`          | n/a — `/schedules` returns 503 | n/a |

Run `elsereno db migrate` to apply migration 00007 before
deploying v1.71+ in db-store mode.

Schedules are tied to the scan-orch wiring: the Scheduler
goroutine only spins up when `--scan-store != off`. Operators
running `--scan-store=off` see 503 from `/api/v1/schedules/`.

**Bulk submit (v1.69+)**: the "Bulk…" button on the dashboard
reveals a textarea — paste one input string per line and click
"Bulk submit". Plugin(s) + default port from the form above
apply to every line. Capped at 200 inputs per request to
protect the worker pool from a single-request DoS.

```sh
# curl shape:
curl -X POST http://127.0.0.1:8787/api/v1/scans/bulk \
  -H "Content-Type: application/json" \
  -H "X-Operator: alice" \
  -d '{"inputs":["list:t1.txt","list:t2.txt","internetdb:1.2.3.0/24"],
       "plugins":["modbus","s7"]}'
```

Response shape:

```json
{
  "schema": "api:v1",
  "data": {
    "submitted": [<Job>, <Job>, <Job>],
    "errors": []
  }
}
```

Per-input failures (typically empty inputs) populate `errors`
with `{index, input, error}` entries; the rest still land in
`submitted`. The HTTP status is 202 Accepted as long as the
request was syntactically valid — individual input failures
don't fail the batch.

**curl** (operator scripts / CI):

```sh
# Single plugin (back-compat with v1.61):
curl -X POST http://127.0.0.1:8787/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-Operator: alice" \
  -d '{"input":"list:targets.txt","plugins":["modbus"],"default_port":502}'

# Multi-plugin (v1.64+):
curl -X POST http://127.0.0.1:8787/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-Operator: alice" \
  -d '{"input":"list:targets.txt","plugins":["modbus","s7","enip"]}'

# All plugins (omit or empty):
curl -X POST http://127.0.0.1:8787/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-Operator: alice" \
  -d '{"input":"list:targets.txt"}'
```

Response: HTTP 202 + Job envelope with `state: "queued"`. The
SSE stream at `/api/v1/stream` emits `scan_state_change` events
on every transition; the dashboard listens directly. CLI
clients can poll `GET /api/v1/scans/{id}` instead.
`POST /api/v1/scans/{id}/cancel` aborts queued / running jobs.

**Stats semantics (v1.64+)**: under multi-plugin dispatch,
`targets_scanned` is the count of (target, plugin) probe
attempts, not unique targets. A target probed by 3 plugins
counts as 3. `findings_count` is the total findings produced
across all (target, plugin) combinations.

**Per-plugin breakdown (v1.66+)**: each Job carries a
`findings_by_plugin` map alongside `stats`, e.g.:

```json
{ "stats": { "targets_seen": 50, "findings_count": 12 },
  "findings_by_plugin": { "modbus": 7, "s7": 3, "enip": 2 } }
```

The dashboard surfaces this as a tooltip on the Findings count
column. Both `--scan-store=memory` and `--scan-store=db` modes
preserve the breakdown across restarts (v1.67+ adds migration
00006 for the JSONB column on `scan_jobs`). Run
`elsereno db migrate` to apply it; existing pre-v1.67 rows get
the column default `'{}'::jsonb` and decode to a nil map (no
breakdown shown for legacy completed jobs).

### Same on Linux + macOS

The orchestration endpoints behave identically across both
platforms — no platform-specific code paths. The only
difference: macOS runs of `elsereno serve --scan-store db`
require a Postgres reachable from your macOS host (typically
via the bundled `scripts/dev-db.sh` Docker container).

---

## Reference

- **Per-cycle changes**: [`CHANGELOG.md`](CHANGELOG.md)
- **Security model**: [`SECURITY.md`](SECURITY.md)
- **Threat model + non-goals**: [`NON-GOALS.md`](NON-GOALS.md)
- **Operator manual**: `man elsereno` (after install) or `man/man1/elsereno.1` in the source tree
- **Per-protocol notes**: `.context/protocols/<name>.md` in the source tree
