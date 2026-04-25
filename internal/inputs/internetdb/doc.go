// Package internetdb is the Shodan InternetDB
// (internetdb.shodan.io) attack-surface input client. v1.12
// chunk 9 — the 6th attack-surface provider after Shodan,
// Censys, FOFA, ZoomEye, ONYPHE — and the only one that
// requires NO API key. Free for low-volume use; rate-limited
// to ~10 rps by upstream.
//
// Unlike the other providers, InternetDB is lookup-by-IP, not
// search-by-query: the operator gives an IP, the API returns
// the open ports + hostnames + tags Shodan has on file. The
// CLI surface uses `--input internetdb:<ip>` (single-IP today;
// bulk lookup is a v1.13+ follow-up).
//
// API reference: https://internetdb.shodan.io/
package internetdb
