// Package creds implements the encrypted credential vault.
//
// AES-GCM + Argon2id (time=3, memory=64 MiB, threads=4). Master key is
// unlock-once in a memguard.LockedBuffer; zeroised on vault lock or on
// SIGINT/SIGTERM (ADR-018). HKDF-SHA256 derivations power the CSRF key
// (ADR-017) and future key material.
//
// vault init creates the vault; creds show --reveal prints the stored
// plaintext and a stderr notice without the value. No vault or creds
// verb writes to the audit chain yet: the creds_* and vault_* event
// types exist in internal/audit but nothing emits them. Env-based passphrases emit a TTY warning (ADR-026).
package creds
