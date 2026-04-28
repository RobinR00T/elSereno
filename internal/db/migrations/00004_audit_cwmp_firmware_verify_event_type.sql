-- +goose Up
-- +goose StatementBegin

-- v1.19 chunk 3: record a dedicated audit event each time the
-- v1.19-chunk-3 async firmware re-fetch fires. Triggered by the
-- CWMP TransferComplete observer when --verify-firmware-on-
-- complete is set + the TransferComplete carries a resolved
-- Authorisation with a non-empty AllowlistSHA256. The CHECK
-- enumeration on audit_log was extended in migration 00002
-- (offensive_sandbox) and 00003 (proxy_allowlist_reload); drop
-- + re-add to extend it again.

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
        'proxy_allowlist_reload',
        'cwmp_firmware_verify'
    ));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Downgrade path: restore the v1.17 enumeration. Refuse the
-- downgrade if rows of the new type exist; silent purge would
-- break the audit chain invariant (ADR-013 / ADR-025).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM audit_log WHERE event_type = 'cwmp_firmware_verify') THEN
        RAISE EXCEPTION
            'refusing downgrade: audit_log still contains cwmp_firmware_verify rows; purge or remap before downgrading (ADR-013/ADR-025)';
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
        'admin_action',
        'proxy_allowlist_reload'
    ));

-- +goose StatementEnd
