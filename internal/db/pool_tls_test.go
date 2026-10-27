package db

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"local/elsereno/internal/config"
)

func TestTLSVerifiesPeer(t *testing.T) {
	cb := func(tls.ConnectionState) error { return nil }
	cases := []struct {
		name string
		cfg  *tls.Config
		want bool
	}{
		{"nil", nil, false},
		{"require (encrypt only)", &tls.Config{InsecureSkipVerify: true}, false},                    // #nosec G402 -- fixture: the unverified config the gate must reject
		{"verify-ca (callback)", &tls.Config{InsecureSkipVerify: true, VerifyConnection: cb}, true}, // #nosec G402 -- fixture: verify-ca sets a callback
		{"verify-full", &tls.Config{InsecureSkipVerify: false}, true},
	}
	for _, c := range cases {
		if got := tlsVerifiesPeer(c.cfg); got != c.want {
			t.Errorf("%s: tlsVerifiesPeer=%v want %v", c.name, got, c.want)
		}
	}
}

func connWith(host string, tc *tls.Config) *pgx.ConnConfig {
	cc := &pgx.ConnConfig{}
	cc.Host = host
	cc.TLSConfig = tc
	return cc
}

func TestApplyTLSPolicy_RejectsUnverifiedRemote(t *testing.T) {
	require := &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- fixture: sslmode=require (encrypt, no verify), which the gate must reject

	// always + remote + require -> rejected.
	if err := applyTLSPolicy(connWith("db.remote", require), config.TLSAlways); !errors.Is(err, ErrTLSUnverified) {
		t.Fatalf("always+require should be ErrTLSUnverified, got %v", err)
	}
	// auto + remote + require -> rejected.
	if err := applyTLSPolicy(connWith("db.remote", require), config.TLSAuto); !errors.Is(err, ErrTLSUnverified) {
		t.Fatalf("auto+remote+require should be ErrTLSUnverified, got %v", err)
	}
	// always + remote + verify-full -> ok.
	verifyFull := &tls.Config{} // InsecureSkipVerify false = verifies the peer
	if err := applyTLSPolicy(connWith("db.remote", verifyFull), config.TLSAlways); err != nil {
		t.Fatalf("always+verify-full should pass, got %v", err)
	}
	// auto + loopback + require -> ok (loopback is exempt).
	if err := applyTLSPolicy(connWith("127.0.0.1", require), config.TLSAuto); err != nil {
		t.Fatalf("auto+loopback should pass regardless of sslmode, got %v", err)
	}
}
