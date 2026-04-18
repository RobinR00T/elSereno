// Package creds implements the encrypted credential vault.
//
// AES-GCM + Argon2id (time=3, memory=64 MiB, threads=4). Master key is
// unlock-once in a memguard.LockedBuffer; zeroised on vault lock or on
// SIGINT/SIGTERM (ADR-018). HKDF-SHA256 derivations power the CSRF key
// (ADR-017) and future key material.
//
// creds init creates the vault; creds show --reveal emits the stored
// plaintext and logs an audit entry (creds_show_reveal) without the
// value itself. Env-based passphrases emit a TTY warning (ADR-026).
package creds
