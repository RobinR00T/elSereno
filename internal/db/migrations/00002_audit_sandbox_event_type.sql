-- +goose Up
-- +goose StatementBegin

-- ADR-042 (v1.1 chunk 6): record a dedicated audit event each
-- time the seccomp-bpf sandbox is loaded before an offensive
-- verb's network delivery. The CHECK enumeration on audit_log
-- is auto-named `audit_log_event_type_check` by Postgres (inline
-- constraint in migration 00001); drop + re-add to extend it.

ALTER TABLE audit_log DROP CONSTRAINT audit_log_event_type_check;

ALTER TABLE audit_log ADD CONSTRAINT audit_log_event_type_check
    CHECK (event_type IN (
        'genesis','chain_rebase','purge_event',
        'token_rotate','token_reveal',
        'vault_init','vault_unlock','vault_lock',
        'creds_store','creds_show_reveal','creds_rotate','creds_purge',
        'scope_applied',
        'serve_start','serve_stop',
        'protocol_probe','protocol_repl_command',
        'offensive_write','offensive_dial','offensive_sms','offensive_harvest',
        'offensive_sandbox',
        'admin_action'
    ));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Downgrade path: restore the pre-v1.1 enumeration. Any rows
-- with event_type='offensive_sandbox' must be purged or remapped
-- first; we refuse the downgrade if such rows exist because the
-- audit chain invariant (prev_hash → entry_hash) would be broken
-- by silent deletion.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM audit_log WHERE event_type = 'offensive_sandbox') THEN
        RAISE EXCEPTION
            'refusing downgrade: audit_log still contains offensive_sandbox rows; purge or remap before downgrading (ADR-013/ADR-025)';
    END IF;
END$$;

ALTER TABLE audit_log DROP CONSTRAINT audit_log_event_type_check;

ALTER TABLE audit_log ADD CONSTRAINT audit_log_event_type_check
    CHECK (event_type IN (
        'genesis','chain_rebase','purge_event',
        'token_rotate','token_reveal',
        'vault_init','vault_unlock','vault_lock',
        'creds_store','creds_show_reveal','creds_rotate','creds_purge',
        'scope_applied',
        'serve_start','serve_stop',
        'protocol_probe','protocol_repl_command',
        'offensive_write','offensive_dial','offensive_sms','offensive_harvest',
        'admin_action'
    ));

-- +goose StatementEnd
