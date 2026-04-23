// Package zoomeye is the ZoomEye (zoomeye.org) attack-surface
// input. Parallel to internal/inputs/shodan + internal/inputs/
// fofa.
//
// ZoomEye is another alternative to Shodan / Censys / ONYPHE
// with strong coverage of APAC networks. It has a broader app-
// fingerprint library than FOFA for certain OT vendors, which
// is why operators ask for both FOFA + ZoomEye alongside the
// existing Shodan client.
//
// Auth differs from FOFA: ZoomEye uses an `API-KEY` HTTP header
// (or `Authorization: JWT <token>`) rather than URL query
// credentials. API reference: https://www.zoomeye.org/doc
package zoomeye
