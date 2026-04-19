% ELSERENO.YAML(5) ElSereno configuration | File formats
% ElSereno project
% 2026-04-19

# NAME

**elsereno.yaml** — configuration file for *elsereno*(1)

# SYNOPSIS

**~/.config/elsereno/elsereno.yaml**, **./elsereno.yaml**, or any path
passed via the global **--config** flag.

# DESCRIPTION

ElSereno reads its configuration from the first of:

1. **--config** *path*
2. **$ELSERENO_CONFIG**
3. **$XDG_CONFIG_HOME/elsereno/elsereno.yaml**
4. **~/.config/elsereno/elsereno.yaml**
5. **~/.elsereno/elsereno.yaml**
6. **./elsereno.yaml**

Unknown keys are rejected at parse time with the error
**ErrUnknownConfigField** (see **elsereno-security**(7)).

# FIELDS

**retention.findings_days**, **retention.evidence_days**, **retention.runs_days**
:   Per-class retention. Evidence additionally follows a *keep-if-referenced*
    rule: a row is never deleted while a finding still references it.

**evidence.max_payload_bytes** (default **16384**)
:   Truncation ceiling for captured payloads. When truncated,
    **evidence.original_sha256** is populated with the SHA-256 of the full
    body.

**scanner.max_concurrent_targets** (default **100**)
**scanner.max_concurrent_per_host** (default **1**)
:   Concurrency caps.

**log.level** (default **info**), **log.output** (default **stderr**)
:   Log level and sink.

**shutdown.drain_timeout** (default **10s**)
:   Graceful drain window before forced exit.

**doctor.ntp_server**
:   Optional NTP server for drift check; empty disables it.

**database.max_conns** (default **10**)
**database.tls_required** ∈ {**auto**, **always**, **disable**} (default **auto**)
:   See **elsereno-security**(7). **disable** is rejected at runtime on
    non-loopback hosts.

**web.token_ttl_days** (default **30**)
**web.token_generation_cache_ttl** (default **5s**)
**web.rate_limit_per_min_ip** (default **100**, loopback exempt)
**web.rate_limit_per_min_token** (default **300**)
**web.max_body_bytes** (default **1048576**)
**web.read_header_timeout** (default **5s**)
**web.read_timeout** (default **30s**)
**web.write_timeout** (default **30s**)
**web.idle_timeout** (default **120s**)
:   HTTP server settings.

**readyz.audit_tail_entries** (default **100**)
:   Number of trailing audit entries verified by /readyz.

**exec.allowed_paths** (default **[/usr/bin, /usr/local/bin, /opt/homebrew/bin]**)
:   Resolved subprocess paths must be under one of these directories.

**outbox.max_attempts** (default **10**)
:   Maximum retries before an outbox entry is moved to **outbox_dead**.

# SEE ALSO

*elsereno*(1), *elsereno-scope*(5), *elsereno-scoring*(5),
*elsereno-security*(7).
