package core

// UUID is a 128-bit identifier represented as its 8-4-4-4-12 string form.
//
// The F0 scaffold ships a minimal string-typed UUID to keep the domain
// package free of external dependencies. Adapters that hit the database
// or the wire format will round-trip through github.com/google/uuid via
// the uuid.go shim.
type UUID string
