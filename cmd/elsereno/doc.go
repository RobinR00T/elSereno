// Package main is the ElSereno command-line entry-point.
//
// The binary hosts the CLI verbs (version, doctor, init, serve, scan, repl,
// proxy, triage, diff, explain, why, lint, fmt, db, audit, vault, creds,
// token, legal, config, plugins, completion) plus a small number of
// internal helpers such as gen-man.
//
// Signal handling is installed via signal.NotifyContext; a first signal
// cancels the root context and drains within shutdown.drain_timeout; a
// second signal exits immediately. Exit codes follow the Unix 128+signum
// convention (SIGINT -> 130, SIGTERM -> 143).
//
// Plugin registration happens via blank imports in plugins.go (default
// build) and plugins_offensive.go (guarded by -tags offensive).
package main
