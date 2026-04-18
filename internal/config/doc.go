// Package config is the root configuration loader.
//
// Precedence (first match wins):
//   1. --config <path>
//   2. $ELSERENO_CONFIG
//   3. $XDG_CONFIG_HOME/elsereno/elsereno.yaml
//   4. ~/.config/elsereno/elsereno.yaml
//   5. ~/.elsereno/elsereno.yaml
//   6. ./elsereno.yaml
//
// The full F0 implementation uses koanf + validator + a struct-tag
// walker that rejects unknown YAML fields (ErrUnknownConfigField).
// This F0 scaffold provides the Config struct and the sentinel so that
// callers compile; koanf is wired in F1.
package config
