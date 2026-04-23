// Package fofa is the FOFA (fofa.info) attack-surface input.
// Mirrors the Shodan client layout — fetches hits from FOFA's
// Search API and decodes them into core.Target values that the
// scanner can deduplicate + probe.
//
// FOFA is an alternative to Shodan / Censys / ONYPHE widely used
// across Asia-Pacific network research; it indexes a broader
// set of ICS / OT banners than Shodan for some geographies,
// which is why operators ask for it alongside the existing
// integrations.
//
// API reference: https://fofa.info/api
package fofa
