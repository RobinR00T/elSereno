// Package onyphe is the ONYPHE (onyphe.io) attack-surface
// input. Parallel to internal/inputs/{shodan,censys,fofa,zoomeye}.
//
// ONYPHE ("Open Network, Yield Protocol History + Exposure")
// is a French threat-intelligence / cyber-defence data source
// with strong coverage of exposed industrial equipment +
// passive DNS + datascan-style banners. Operators often use it
// to cross-reference Shodan hits or to find devices that
// Shodan doesn't surface (ONYPHE scans some ports Shodan
// doesn't, like 10001/tcp Veeder-Root).
//
// Auth: single API key delivered via
// `Authorization: bearer <key>` header. Query syntax is
// ONYPHE's OQL ("ONYPHE Query Language"), not Elasticsearch-
// style.
//
// API reference: https://www.onyphe.io/documentation/api
package onyphe
