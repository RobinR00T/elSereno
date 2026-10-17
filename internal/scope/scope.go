package scope

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"

	"local/elsereno/internal/core"
)

// ErrOutOfScope is returned by a Scope.Check that rejects a target.
var ErrOutOfScope = errors.New("scope: target out of scope")

// Scope is the parsed representation of scope.yaml (section 15 of the
// project brief). Ranges and Ports are applied by Check, Protocols by
// CheckPlugin, Dial by CheckDial; Binds and Canary are parsed (so
// KnownFields accepts them) but no caller applies them.
type Scope struct {
	Version   int         `yaml:"version"`
	Ranges    []RangeDecl `yaml:"ranges"`
	Ports     PortDecl    `yaml:"ports"`
	Protocols ProtoDecl   `yaml:"protocols"`
	Binds     BindDecl    `yaml:"binds"`
	Dial      DialDecl    `yaml:"dial"`
	Canary    CanaryDecl  `yaml:"canary"`
}

// RangeDecl is one CIDR entry.
type RangeDecl struct {
	CIDR string `yaml:"cidr"`
	Note string `yaml:"note"`
}

// PortDecl is the allow/deny port lists. Deny wins over allow.
type PortDecl struct {
	Allow []int `yaml:"allow"`
	Deny  []int `yaml:"deny"`
}

// ProtoDecl is the allow/deny protocol lists.
type ProtoDecl struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// BindDecl lists bind addresses serve is allowed to use.
type BindDecl struct {
	Allow []string `yaml:"allow"`
}

// DialDecl holds dial blacklists above the always-on ≤3-digit block.
type DialDecl struct {
	BlockedNumbers []string `yaml:"blocked_numbers"`
}

// CanaryDecl is the optional canary webhook.
type CanaryDecl struct {
	Enabled      bool   `yaml:"enabled"`
	AlertWebhook string `yaml:"alert_webhook"`
}

// Load parses a scope.yaml file. Returns nil and no error if `path` is
// empty; callers handle the "no scope declared" case separately.
func Load(path string) (*Scope, error) {
	if path == "" {
		return nil, nil
	}
	// #nosec G304 -- caller-supplied scope path
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scope: read %q: %w", path, err)
	}
	var s Scope
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("scope: parse %q: %w", path, err)
	}
	return &s, nil
}

// Check returns nil if the target is in scope (its port and its
// address); ErrOutOfScope otherwise.
func (s *Scope) Check(target core.Target) error {
	if err := s.CheckPort(int(target.Port)); err != nil {
		return err
	}
	return s.CheckAddr(target.Address)
}

// CheckAddr returns nil if the address is in one of the declared
// ranges, or if none is declared.
func (s *Scope) CheckAddr(addr netip.Addr) error {
	if s == nil || len(s.Ranges) == 0 {
		return nil
	}
	for _, r := range s.Ranges {
		prefix, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			continue
		}
		if prefix.Contains(addr.Unmap()) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s not in any declared range", ErrOutOfScope, addr)
}

// CheckPort returns nil if the ports lists let the port through.
func (s *Scope) CheckPort(p int) error {
	if s == nil {
		return nil
	}
	return s.checkPort(p)
}

// CheckPlugin returns nil if the scope's protocols lists let the named
// plugin run. An entry matches the plugin's name or its protocol, the
// part of the name before the first "-": "s7" covers s7 and
// s7-exposure, "opcua" covers opcua and opcua-exposure, and
// "s7-exposure" covers only that plugin (opcuahttps is a name of its
// own). Entries are compared without regard to case. Deny wins over
// allow; an empty allow list lets through every plugin not denied.
func (s *Scope) CheckPlugin(name string) error {
	if s == nil {
		return nil
	}
	family := name
	if i := strings.IndexByte(name, '-'); i > 0 {
		family = name[:i]
	}
	matches := func(entry string) bool {
		entry = strings.TrimSpace(entry)
		return strings.EqualFold(entry, name) || strings.EqualFold(entry, family)
	}
	for _, d := range s.Protocols.Deny {
		if matches(d) {
			return fmt.Errorf("%w: protocol of plugin %q denied (%q)", ErrOutOfScope, name, d)
		}
	}
	if len(s.Protocols.Allow) == 0 {
		return nil
	}
	for _, a := range s.Protocols.Allow {
		if matches(a) {
			return nil
		}
	}
	return fmt.Errorf("%w: plugin %q not in protocols allow list", ErrOutOfScope, name)
}

// CheckProtocol returns nil if proto is allowed by the scope, comparing
// the exact string. Commands check plugins with CheckPlugin.
func (s *Scope) CheckProtocol(proto string) error {
	if s == nil {
		return nil
	}
	for _, d := range s.Protocols.Deny {
		if d == proto {
			return fmt.Errorf("%w: protocol %q denied", ErrOutOfScope, proto)
		}
	}
	if len(s.Protocols.Allow) > 0 {
		for _, a := range s.Protocols.Allow {
			if a == proto {
				return nil
			}
		}
		return fmt.Errorf("%w: protocol %q not in allow list", ErrOutOfScope, proto)
	}
	return nil
}

// CheckDial returns nil if `normalisedNumber` is not in the scope's
// blocked_numbers list. Entries match if they are a prefix or an
// exact match of the normalised number (operators typically paste
// country-code prefixes to block whole regions). The number arrives
// normalised (offensive/dial.Normalise drops "+", a leading "00" and
// punctuation) but the entries are compared as written, so an entry
// with "+" or "00" never matches: write "90", not "0090" or "+90".
//
// This method is the *scope half* of the dial guard (ADR-041 gate
// 2). The ≤3-digit hard block lives in offensive/dial/validate.go
// where it cannot be bypassed by an absent scope file.
func (s *Scope) CheckDial(normalisedNumber string) error {
	if s == nil {
		return nil
	}
	for _, e := range s.Dial.BlockedNumbers {
		if e == "" {
			continue
		}
		if normalisedNumber == e {
			return fmt.Errorf("%w: dial number matches blocked entry %q", ErrOutOfScope, e)
		}
		if len(normalisedNumber) > len(e) && normalisedNumber[:len(e)] == e {
			return fmt.Errorf("%w: dial number prefix matches blocked entry %q", ErrOutOfScope, e)
		}
	}
	return nil
}

func (s *Scope) checkPort(p int) error {
	for _, d := range s.Ports.Deny {
		if d == p {
			return fmt.Errorf("%w: port %d denied", ErrOutOfScope, p)
		}
	}
	if len(s.Ports.Allow) > 0 {
		for _, a := range s.Ports.Allow {
			if a == p {
				return nil
			}
		}
		return fmt.Errorf("%w: port %d not in allow list", ErrOutOfScope, p)
	}
	return nil
}
