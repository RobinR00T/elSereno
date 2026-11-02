// Package outbox implements the retry + dead-letter worker for
// asynchronous deliveries (webhooks, exports). Entries live in the
// `outbox` table; failures past max_attempts move to `outbox_dead`
// (PITF-027). This package exposes the worker loop and an in-memory
// store (MemStore). No Postgres store is written and no command runs
// the worker yet: webhooks and exports deliver inline.
package outbox
