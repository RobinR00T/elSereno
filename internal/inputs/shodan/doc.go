// Package shodan reads Shodan API results into core.Target values.
// Credentials come from the vault (preferred) or env (ADR-026);
// warnings are emitted on TTY when env is used (PITF-032).
package shodan
