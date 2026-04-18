package config

import "errors"

// ErrUnknownConfigField is returned by the loader when the YAML file
// contains a field that is not part of the declared schema. It lives
// here (not in core) per PITF-009.
var ErrUnknownConfigField = errors.New("config: unknown field")

// ErrInvalidConfig is returned for values that pass type checking but
// fail business validation (e.g. database.tls_required=disable against
// a non-loopback host — ADR-021, PITF-022).
var ErrInvalidConfig = errors.New("config: invalid value")
