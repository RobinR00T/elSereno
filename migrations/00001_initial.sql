-- +goose Up
-- +goose StatementBegin

CREATE TABLE schema_info (
    contract_name TEXT PRIMARY KEY,
    version       TEXT NOT NULL,
    since         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO schema_info(contract_name, version) VALUES
    ('ndjson','v1'),
    ('api','v1');

CREATE TABLE web_state (
    key              TEXT PRIMARY KEY,
    token_generation BIGINT NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO web_state(key) VALUES ('default');

CREATE TABLE runs (
    id           UUID PRIMARY KEY,
    started_at   TIMESTAMPTZ NOT NULL,
    finished_at  TIMESTAMPTZ,
    status       TEXT NOT NULL,
    scope_hash   BYTEA,
    operator     TEXT
);

CREATE TABLE targets (
    id          UUID PRIMARY KEY,
    address     INET NOT NULL,
    port        INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    asn         INTEGER,
    country     CHAR(2),
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(address, port)
);

CREATE TABLE findings (
    id           UUID PRIMARY KEY,
    run_id       UUID NOT NULL REFERENCES runs(id),
    target_id    UUID NOT NULL REFERENCES targets(id),
    protocol     TEXT NOT NULL,
    severity     TEXT NOT NULL,
    score        INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    finding_hash BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    factors      JSONB NOT NULL
);
CREATE INDEX findings_score_severity_idx ON findings(score, severity);
CREATE INDEX findings_run_idx            ON findings(run_id);
CREATE INDEX findings_protocol_idx       ON findings(protocol);
CREATE INDEX findings_hash_idx           ON findings(finding_hash);

CREATE TABLE evidence (
    id                UUID PRIMARY KEY,
    finding_id        UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    payload           BYTEA NOT NULL,
    payload_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    original_size     INTEGER,
    -- original_sha256 is populated ONLY when payload_truncated = TRUE.
    original_sha256   BYTEA,
    captured_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
    id         UUID PRIMARY KEY,
    run_id     UUID REFERENCES runs(id),
    target_id  UUID REFERENCES targets(id),
    protocol   TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at   TIMESTAMPTZ,
    transcript JSONB
);

-- audit_log event_type is the source of truth for the enumeration
-- (ADR-023, PITF-030). Go constants in internal/audit/events.go mirror
-- this list; a unit test enforces they remain in sync.
CREATE TABLE audit_log (
    id                  BIGSERIAL PRIMARY KEY,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor               TEXT NOT NULL,
    event_type          TEXT NOT NULL CHECK (event_type IN (
        'genesis','chain_rebase','purge_event',
        'token_rotate','token_reveal',
        'vault_init','vault_unlock','vault_lock',
        'creds_store','creds_show_reveal','creds_rotate','creds_purge',
        'scope_applied',
        'serve_start','serve_stop',
        'protocol_probe','protocol_repl_command',
        'offensive_write','offensive_dial','offensive_sms','offensive_harvest',
        'admin_action'
    )),
    payload             JSONB NOT NULL,
    payload_tombstoned  BOOLEAN NOT NULL DEFAULT FALSE,
    prev_hash           BYTEA NOT NULL,
    entry_hash          BYTEA NOT NULL UNIQUE
);
CREATE INDEX audit_log_occurred_at_idx ON audit_log(occurred_at);

-- audit_purge_markers records every `audit purge` operation. The FK
-- points at the purge_event row in audit_log; ON DELETE RESTRICT makes
-- it safe because ADR-013 guarantees that `audit compact` never removes
-- entries with event_type in (genesis, chain_rebase, purge_event).
CREATE TABLE audit_purge_markers (
    id             BIGSERIAL PRIMARY KEY,
    performed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    purged_before  TIMESTAMPTZ NOT NULL,
    purged_rows    BIGINT NOT NULL,
    audit_entry_id BIGINT NOT NULL REFERENCES audit_log(id) ON DELETE RESTRICT
);

CREATE TABLE outbox (
    id           UUID PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    kind         TEXT NOT NULL,
    payload      JSONB NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    next_try_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ
);
CREATE INDEX outbox_pending_idx ON outbox(next_try_at) WHERE delivered_at IS NULL;

CREATE TABLE outbox_dead (
    id         UUID PRIMARY KEY,
    moved_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    kind       TEXT NOT NULL,
    payload    JSONB NOT NULL,
    attempts   INTEGER NOT NULL,
    last_error TEXT
);
CREATE INDEX outbox_dead_moved_at_idx ON outbox_dead(moved_at);

CREATE TABLE tags (
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    key       TEXT NOT NULL,
    value     TEXT NOT NULL,
    PRIMARY KEY (target_id, key)
);

CREATE TABLE scope_history (
    id         BIGSERIAL PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scope_yaml TEXT NOT NULL,
    scope_hash BYTEA NOT NULL
);

CREATE TABLE creds_vault (
    name       TEXT PRIMARY KEY,
    ciphertext BYTEA NOT NULL,
    nonce      BYTEA NOT NULL,
    salt       BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS creds_vault;
DROP TABLE IF EXISTS scope_history;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS outbox_dead;
DROP TABLE IF EXISTS outbox;
DROP TABLE IF EXISTS audit_purge_markers;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS targets;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS web_state;
DROP TABLE IF EXISTS schema_info;

-- +goose StatementEnd
