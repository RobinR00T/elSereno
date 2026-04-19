package telemetry

import (
	"math"
	"regexp"
	"strings"
)

// RedactedPlaceholder is the literal substituted for any value that
// triggers the redaction rules. Callers and tests compare against this
// exact string.
const RedactedPlaceholder = "[REDACTED]"

// RedactionPatterns enumerates the case-insensitive key name patterns
// that force redaction regardless of value entropy. This list is the
// source of truth referenced from .context/conventions.md and
// PITF-004.
var RedactionPatterns = []string{
	"api_key", "secret_key", "private_key", "access_key",
	"session_key", "encryption_key",
	"auth_token", "refresh_token", "bearer_token",
	"password", "passphrase", "secret",
	"authorization", "cookie",
}

// uuidRe matches RFC 4122 v1-v5 UUIDs in canonical 8-4-4-4-12 form,
// case-insensitive. Values that match are exempted from the entropy
// heuristic so request IDs and similar identifiers survive logging
// (PITF-004).
var uuidRe = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`,
)

// EntropyThresholdBitsPerByte is the bits-per-byte threshold above
// which a long string is treated as likely-random (credentials,
// tokens). 4.5 is the number from the brief and PITF-004.
const EntropyThresholdBitsPerByte = 4.5

// MinEntropyLen is the minimum length a value must reach before the
// entropy heuristic fires. Short strings are noisy; 21 keeps short IDs
// and common acronyms clean.
const MinEntropyLen = 21

// Redact returns the original value or the placeholder based on:
//  1. Key name matches one of RedactionPatterns (case-insensitive).
//  2. OR value is longer than MinEntropyLen-1, has entropy above
//     EntropyThresholdBitsPerByte, AND is NOT a UUID.
//
// The function is zero-allocation on clean values.
func Redact(key, value string) string {
	if value == "" {
		return value
	}
	if keyMatchesRedactionPattern(key) {
		return RedactedPlaceholder
	}
	if len(value) >= MinEntropyLen && !uuidRe.MatchString(value) {
		if ShannonEntropy(value) > EntropyThresholdBitsPerByte {
			return RedactedPlaceholder
		}
	}
	return value
}

// keyMatchesRedactionPattern checks the key against RedactionPatterns
// case-insensitively. The key is normalised by lowercasing and
// converting dashes and spaces to underscores so that "Shodan-API-KEY"
// and "api_key" compare as equivalent.
func keyMatchesRedactionPattern(key string) bool {
	if key == "" {
		return false
	}
	normalised := strings.ToLower(key)
	normalised = strings.NewReplacer("-", "_", " ", "_").Replace(normalised)
	for _, p := range RedactionPatterns {
		if strings.Contains(normalised, p) {
			return true
		}
	}
	return false
}

// ShannonEntropy returns the Shannon entropy of s in bits per byte.
// Values of zero are returned for the empty string.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	// Byte-level frequency is what the brief prescribes; UTF-8 strings
	// containing multi-byte runes are treated by their bytes, which is
	// conservative (high-entropy).
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
