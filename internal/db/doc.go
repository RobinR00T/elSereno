// Package db wraps pgxpool with ElSereno-specific defaults
// (max 10 connections, TLS per ADR-021) and embeds goose migrations.
// Migration 00001 is the authoritative DDL and the source of truth for
// the audit_log.event_type enumeration (ADR-023, PITF-030).
package db
