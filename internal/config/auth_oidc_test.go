package config_test

import (
	"testing"
	"time"

	"local/elsereno/internal/config"
)

// TestOIDCEnabled_RequiresAllThree: any single missing field
// → Enabled() false. Prevents the footgun where issuer is set
// but jwks_url is forgotten and tokens silently pass.
func TestOIDCEnabled_RequiresAllThree(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.OIDCConfig
		want bool
	}{
		{"all empty", config.OIDCConfig{}, false},
		{"only issuer",
			config.OIDCConfig{Issuer: "https://idp"}, false},
		{"only audience",
			config.OIDCConfig{Audience: "elsereno"}, false},
		{"only jwks",
			config.OIDCConfig{JWKSURL: "https://idp/jwks"}, false},
		{"issuer + audience, no jwks",
			config.OIDCConfig{
				Issuer:   "https://idp",
				Audience: "elsereno",
			}, false},
		{"all three set",
			config.OIDCConfig{
				Issuer:   "https://idp",
				Audience: "elsereno",
				JWKSURL:  "https://idp/jwks",
			}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.Enabled(); got != tc.want {
				t.Errorf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestOIDCEnabled_ClockSkewIndependent: clock_skew alone
// doesn't enable OIDC. Operators must set the three URL fields.
func TestOIDCEnabled_ClockSkewIndependent(t *testing.T) {
	cfg := config.OIDCConfig{ClockSkew: 30 * time.Second}
	if cfg.Enabled() {
		t.Errorf("clock_skew alone should NOT enable OIDC")
	}
}

// TestAuthConfig_DefaultDisabled: the zero-value AuthConfig
// has OIDC disabled. Critical: serve must not enforce auth
// on a freshly-bootstrapped install.
func TestAuthConfig_DefaultDisabled(t *testing.T) {
	var ac config.AuthConfig
	if ac.OIDC.Enabled() {
		t.Errorf("default AuthConfig should have OIDC disabled")
	}
}
