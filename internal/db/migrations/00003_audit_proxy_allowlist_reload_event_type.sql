-- +goose Up
-- +goose StatementBegin

-- v1.17 chunk 5: record a dedicated audit event each time the
-- v1.17-chunk-4 SIGUSR1 in-process allow-file reload fires
-- (success or failure). The CHECK enumeration on audit_log
-- is auto-named `audit_log_event_type_check` by Postgres
-- (extended in migration 00002 for offensive_sandbox); drop +
-- re-add to extend it again.

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
        'admin_action',
        'proxy_allowlist_reload'
    ));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Downgrade path: restore the v1.16 enumeration (without the
-- v1.17-chunk-5 reload event). Refuse the downgrade if rows
-- with the new event_type exist; a silent purge would break
-- the audit chain invariant (prev_hash → entry_hash; ADR-013
-- / ADR-025).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM audit_log WHERE event_type = 'proxy_allowlist_reload') THEN
        RAISE EXCEPTION
            'refusing downgrade: audit_log still contains proxy_allowlist_reload rows; purge or remap before downgrading (ADR-013/ADR-025)';
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
        'offensive_sandbox',
        'admin_action'
    ));

-- +goose StatementEnd
