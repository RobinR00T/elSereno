package scope

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"go.yaml.in/yaml/v3"

	"local/elsereno/internal/core"
)

// ErrOutOfScope is returned by a Scope.Check that rejects a target.
var ErrOutOfScope = errors.New("scope: target out of scope")

// Scope is the parsed representation of scope.yaml (section 15 of the
// project brief). Only the fields used by F1 are populated; F2+
// layers (dial.blocked_numbers, canary.alert_webhook) are tolerated
// but unused for now.
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

// Check returns nil if the target is in scope; ErrOutOfScope otherwise.
func (s *Scope) Check(target core.Target) error {
	if s == nil {
		return nil
	}
	if err := s.checkPort(int(target.Port)); err != nil {
		return err
	}
	if len(s.Ranges) == 0 {
		return nil
	}
	for _, r := range s.Ranges {
		prefix, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			continue
		}
		if prefix.Contains(target.Address.Unmap()) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s not in any declared range", ErrOutOfScope, target.Address)
}

// CheckProtocol returns nil if proto is allowed by the scope.
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
