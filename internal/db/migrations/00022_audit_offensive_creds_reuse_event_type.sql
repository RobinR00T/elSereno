-- +goose Up
-- +goose StatementBegin

-- Record the offensive credential-reuse check (creds-check reuse): one
-- row per credential tried against one target, carrying the credential's
-- source label and a salted fingerprint (never the password), the
-- target, the protocol and whether it was accepted. The CHECK
-- enumeration on audit_log was last extended in 00020
-- (dnp3_gate_decision); drop and re-add to extend it again.

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
        'cwmp_firmware_verify',
        'dnp3_iin_alert',
        'dnp3_gate_decision',
        'offensive_creds_reuse'
    ));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Downgrade path: restore the 00020 enumeration. Refuse the downgrade
-- if rows of the new type exist; a silent purge would break the audit
-- chain invariant (ADR-013 / ADR-025).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM audit_log WHERE event_type = 'offensive_creds_reuse') THEN
        RAISE EXCEPTION
            'refusing downgrade: audit_log still contains offensive_creds_reuse rows; purge or remap before downgrading (ADR-013/ADR-025)';
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
        'proxy_allowlist_reload',
        'cwmp_firmware_verify',
        'dnp3_iin_alert',
        'dnp3_gate_decision'
    ));

-- +goose StatementEnd
