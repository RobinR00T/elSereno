% ELSERENO.YAML(5) ElSereno configuration | File formats
% ElSereno project
% 2026-04-19

# NAME

**elsereno.yaml**: configuration file for *elsereno*(1)

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

Durations are written as text (**30s**, **2m0s**); a bare number, a
negative duration or an unknown key stops the command with exit 78.
Until 2026-10-17 a file with any duration or list did not load at all
(PITF-096). The defaults are what **elsereno config show** prints.

Read by the binary:

**scanner.max_concurrent_targets** (default **100**)
**scanner.max_concurrent_per_host** (default **1**)
:   Concurrency caps of **scan** and of the dashboard scans of **serve**;
    **max_concurrent_per_host** also caps **discover**. A **--profile**
    other than **normal**, and the **--max-concurrent** and
    **--max-conns-per-host** flags, override them for that run.

**database.max_conns** (default **10**)
**database.tls_required** in {**auto**, **always**, **disable**} (default **auto**)
:   Postgres pool size and TLS; see **elsereno-security**(7). The
    connection itself comes from **DATABASE_URL**.

**web.read_header_timeout** (default **5s**)
**web.read_timeout** (default **30s**)
**web.write_timeout** (default **30s**)
**web.idle_timeout** (default **2m0s**)
:   HTTP server timeouts of **serve**; zero means the built-in default.

**web.rate_limit_per_min_ip** (default **100**)
**web.rate_limit_per_min_token** (default **300**)
:   Request caps of **serve**: a token bucket per client IP (loopback
    exempt; IPv6 by /64) and per Bearer token or, without one, **X-Operator** name
    (in any auth mode; loopback included). Over either cap: **429** with
    **Retry-After: 60**; **/healthz** and **/readyz** are never limited;
    **0** turns that cap off (so does a negative value). **X-Forwarded-For**
    is ignored, so behind a same-host reverse proxy every client is exempt
    loopback: rate limit in that proxy.

**auth.oidc.issuer**, **auth.oidc.audience**, **auth.oidc.jwks_url**
:   OIDC for **serve**; required on a non-loopback address.

Accepted but not read by anything yet (setting them changes nothing):
**retention.findings_days**, **retention.evidence_days**,
**retention.runs_days**, **evidence.max_payload_bytes**, **log.level**,
**log.output**, **shutdown.drain_timeout**, **doctor.ntp_server**,
**web.token_ttl_days**, **web.token_generation_cache_ttl**,
**web.max_body_bytes**, **readyz.audit_tail_entries** (only the stub
**audit verify**), **exec.allowed_paths** (it does not limit which
binaries run), **outbox.max_attempts**, and **auth.oidc.clock_skew**
(fixed at 60s in the code).

# SEE ALSO

*elsereno*(1), *elsereno-scope*(5), *elsereno-scoring*(5),
*elsereno-security*(7).
