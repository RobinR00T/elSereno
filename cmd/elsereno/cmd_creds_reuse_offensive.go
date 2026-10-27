//go:build offensive

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/core"
	"local/elsereno/offensive/creds"
)

type reuseOpts struct {
	target      string
	protocol    string
	scopePath   string
	ppFile      string
	timeout     time.Duration
	jsonOut     bool
	confirmed   bool
	credsFile   string
	vaultAddr   string
	vaultMount  string
	vaultPath   string
	vaultToken  string
	endpoint    string
	endpointTk  string
	tlsPin      string
	insecureTLS bool
}

// newCredsCheckReuseCmd is the credential-reuse check: it tries
// credentials the operator already holds (from a 0600 file, Vault KV v2,
// or a JSON endpoint) against one OT target over HTTP Basic or SSH,
// auth-only. It evidences the IT->OT credential-reuse path.
const reuseLongHelp = `Verifies whether credentials that already exist in your estate also
open an OT device: the IT->OT credential-reuse path that turns a foothold
in the office network into control of the plant.

Credentials come from YOUR store, never a wordlist, through one source:

  --creds-file PATH          a 0600 file: JSON [{"user","pass","source"}]
                             or a {"user":"pass"} map, or "user:pass" lines
  --vault-addr/-mount/-path  a HashiCorp Vault KV v2 secret; the token is
    --vault-token-file PATH  read from a 0600 file and sent in a header
  --endpoint-url URL         a JSON endpoint returning the same shapes;
    --endpoint-token-file    optional 0600 bearer-token file

The credential store is contacted with TLS verification ON. Sending the
operator's real credentials to the device needs an authenticated channel,
so the target device UI (http-basic) must be either pinned or explicitly
accepted as unverified:

  --tls-pin HEX     pin the device's TLS leaf-certificate SHA-256 (works
                    with self-signed certs; blocks an on-path MITM)
  --insecure-tls    acknowledge sending credentials over TLS with NO
                    certificate verification (also required for ssh,
                    whose host key is not verified)

Without one of these the check refuses to run, because an on-path
attacker could otherwise harvest the very credentials being tested.

Protocols:

  --protocol http-basic   --target https://hmi.internal  (every probe a GET;
                          only tried when the baseline GET returns 401/403)
  --protocol ssh          --target plc.internal:22       (password auth only;
                          a successful login is closed with no session and
                          no command run)

The password is never printed and never written to the audit log; each
attempt is recorded with the credential's source and a per-run salted
fingerprint only.

AUTHORIZED USE ONLY. Run only against systems you are authorized to test.
Requires --confirm-authorized and --vault-passphrase-file (for audit keying).

Examples:

  elsereno creds-check reuse --protocol ssh --target plc.internal:22 \
    --creds-file ./ad-service-accounts.600 --insecure-tls \
    --vault-passphrase-file ~/.elsereno/pass.600 --confirm-authorized

  elsereno creds-check reuse --protocol http-basic --target https://hmi.internal \
    --tls-pin 9f2c...<64 hex> \
    --vault-addr https://vault.internal:8200 --vault-mount secret \
    --vault-path ot/shared-admin --vault-token-file ~/.vault-token.600 \
    --vault-passphrase-file ~/.elsereno/pass.600 --confirm-authorized`

func newCredsCheckReuseCmd() *cobra.Command {
	var o reuseOpts
	cmd := &cobra.Command{
		Use:   "reuse",
		Short: "Check whether credentials from your own store are reused on an OT target (offensive, AUTHORIZED USE ONLY)",
		Long:  reuseLongHelp,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCredsCheckReuse(cmd, o)
		},
	}
	addReuseFlags(cmd, &o)
	return cmd
}

// addReuseFlags registers the flags for `creds-check reuse`.
func addReuseFlags(cmd *cobra.Command, o *reuseOpts) {
	f := cmd.Flags()
	f.StringVar(&o.target, "target", "", "https:// URL (http-basic) or host:port (ssh) of the device")
	f.StringVar(&o.protocol, "protocol", creds.ProtoHTTPBasic, "http-basic | ssh")
	f.DurationVar(&o.timeout, "timeout", 20*time.Second, "overall check timeout")
	f.BoolVar(&o.jsonOut, "json", false, "emit the report as JSON")
	f.BoolVar(&o.confirmed, "confirm-authorized", false, "acknowledge you are authorized to test this target (required)")
	f.StringVar(&o.credsFile, "creds-file", "", "0600 file of credentials")
	f.StringVar(&o.vaultAddr, "vault-addr", "", "HashiCorp Vault base URL (e.g. https://vault:8200)")
	f.StringVar(&o.vaultMount, "vault-mount", "secret", "Vault KV v2 mount")
	f.StringVar(&o.vaultPath, "vault-path", "", "Vault KV v2 secret path")
	f.StringVar(&o.vaultToken, "vault-token-file", "", "0600 file holding the Vault token")
	f.StringVar(&o.endpoint, "endpoint-url", "", "JSON credential endpoint URL")
	f.StringVar(&o.endpointTk, "endpoint-token-file", "", "0600 file holding the endpoint bearer token")
	f.StringVar(&o.tlsPin, "tls-pin", "", "hex SHA-256 of the device's TLS leaf certificate to pin (http-basic)")
	f.BoolVar(&o.insecureTLS, "insecure-tls", false, "acknowledge sending credentials over an unverified TLS/SSH channel")
	addPassphraseFileFlag(cmd, &o.ppFile)
	addScopeFlag(cmd, &o.scopePath)
}

func runCredsCheckReuse(cmd *cobra.Command, o reuseOpts) error {
	if o.target == "" {
		return fail(core.ExitUsage, fmt.Errorf("--target is required"))
	}
	if !o.confirmed {
		return fail(core.ExitUsage, fmt.Errorf(
			"--confirm-authorized is required: run this only against systems you are authorized to test"))
	}
	if o.protocol != creds.ProtoHTTPBasic && o.protocol != creds.ProtoSSH {
		return fail(core.ExitUsage, fmt.Errorf("--protocol must be %q or %q", creds.ProtoHTTPBasic, creds.ProtoSSH))
	}
	if err := checkReuseTLSPosture(o); err != nil {
		return fail(core.ExitUsage, err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()

	// Scope-check the target and get the address to pin connections to.
	gate, err := loadScopeGate(o.scopePath)
	if err != nil {
		return err
	}
	var dialAddr string
	if o.protocol == creds.ProtoHTTPBasic {
		dialAddr, err = gate.urlDialAddr(ctx, o.target, "http-basic")
	} else {
		dialAddr, err = gate.hostPort(ctx, o.target, "ssh")
	}
	if err != nil {
		return err
	}

	// The credential store is verified; the device UI is not.
	storeClient := &http.Client{Timeout: o.timeout}
	credList, err := loadReuseCreds(ctx, o, storeClient)
	if err != nil {
		return fail(core.ExitError, err)
	}
	if len(credList) == 0 {
		return fail(core.ExitNoInput, creds.ErrNoCreds)
	}

	rt, err := newOffensiveRuntime(cmd, o.ppFile)
	if err != nil {
		return err
	}
	defer rt.Close()

	checker, err := creds.NewReuseChecker()
	if err != nil {
		return fail(core.ExitSoftware, err)
	}
	checker.SSHTimeout = o.timeout
	checker.Audit = reuseAuditor(rt.Writer, rt.Actor)

	rep, err := dispatchReuse(ctx, checker, o, dialAddr, credList)
	if err != nil {
		return fail(core.ExitError, err)
	}
	return reportReuse(cmd, rep, rt.AuditPath(), o.jsonOut)
}

// checkReuseTLSPosture enforces that credentials are only sent over a
// channel whose peer is authenticated. http-basic may pin the device
// leaf certificate (--tls-pin) or explicitly accept an unverified link
// (--insecure-tls); ssh has no pin, so it requires the acknowledgement.
// Without one, a reuse check would ship the operator's real credentials
// to a target an on-path attacker could impersonate.
func checkReuseTLSPosture(o reuseOpts) error {
	if o.tlsPin != "" {
		if o.protocol != creds.ProtoHTTPBasic {
			return fmt.Errorf("--tls-pin only applies to --protocol %q", creds.ProtoHTTPBasic)
		}
		if _, err := normaliseTLSPin(o.tlsPin); err != nil {
			return err
		}
		return nil // pinned: authenticated channel, no ack needed
	}
	if !o.insecureTLS {
		return fmt.Errorf(
			"sending credentials needs an authenticated channel: pass --tls-pin <sha256> (http-basic) " +
				"or acknowledge an unverified channel with --insecure-tls")
	}
	return nil
}

// normaliseTLSPin lower-cases and validates a 64-hex-char SHA-256 pin.
func normaliseTLSPin(pin string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(pin))
	b, err := hex.DecodeString(p)
	if err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("--tls-pin must be a %d-character hex SHA-256 of the leaf certificate", 2*sha256.Size)
	}
	return p, nil
}

// dispatchReuse runs the configured protocol's reuse check.
func dispatchReuse(ctx context.Context, checker *creds.ReuseChecker, o reuseOpts, dialAddr string, credList []creds.Credential) (creds.ReuseReport, error) {
	if o.protocol == creds.ProtoSSH {
		sshAddr := o.target
		if dialAddr != "" {
			sshAddr = dialAddr
		}
		return checker.CheckSSH(ctx, sshAddr, credList)
	}
	checker.HTTPClient = deviceClient(o.timeout, dialAddr, o.tlsPin)
	return checker.CheckHTTPBasic(ctx, o.target, credList)
}

// loadReuseCreds reads credentials from exactly one configured source.
func loadReuseCreds(ctx context.Context, o reuseOpts, store *http.Client) ([]creds.Credential, error) {
	switch {
	case o.credsFile != "":
		return creds.LoadCredsFile(o.credsFile)
	case o.vaultPath != "":
		if o.vaultAddr == "" || o.vaultToken == "" {
			return nil, fmt.Errorf("--vault-path needs --vault-addr and --vault-token-file")
		}
		return creds.LoadVaultKV2(ctx, store, o.vaultAddr, o.vaultMount, o.vaultPath, o.vaultToken)
	case o.endpoint != "":
		return creds.LoadJSONEndpoint(ctx, store, o.endpoint, o.endpointTk)
	default:
		return nil, fmt.Errorf("one credential source is required: --creds-file, --vault-path or --endpoint-url")
	}
}

// deviceClient builds the HTTP client for the device UI. When pin is a
// valid SHA-256 the leaf certificate is authenticated against it (chain
// and hostname still skipped, so self-signed device certs work); this
// stops an on-path attacker from harvesting the credentials under test.
// With an empty pin the caller has passed --insecure-tls, so the link is
// encrypted but unverified. Redirects are not followed, and the
// connection is pinned to dialAddr when a scope gave one.
func deviceClient(timeout time.Duration, dialAddr, pin string) *http.Client {
	tc := &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- device UIs are self-signed; leaf authenticated by --tls-pin when set, else --insecure-tls acknowledged
	if pin != "" {
		want, _ := normaliseTLSPin(pin) // already validated in checkReuseTLSPosture
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("creds: device presented no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if got := hex.EncodeToString(sum[:]); got != want {
				return fmt.Errorf("creds: device certificate %s does not match --tls-pin", got)
			}
			return nil
		}
	}
	tr := &http.Transport{TLSClientConfig: tc}
	if dialAddr != "" {
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dialAddr)
		}
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// reuseAuditor writes one append-only audit row per attempt. The payload
// carries the source and a fingerprint, never the password.
func reuseAuditor(w audit.Writer, actor string) creds.Auditor {
	return func(ctx context.Context, target, protocol string, r creds.ReuseResult) error {
		payload, err := json.Marshal(map[string]any{
			"category":    "creds_reuse",
			"target":      target,
			"protocol":    protocol,
			"user":        r.User,
			"source":      r.Source,
			"fingerprint": r.Fingerprint,
			"accepted":    r.Accepted,
			"captured_at": time.Now().UTC().Format(time.RFC3339Nano),
		})
		if err != nil {
			return err
		}
		_, err = w.Append(ctx, audit.Entry{
			EventType: audit.EventOffCredsReuse,
			Actor:     actor,
			Payload:   payload,
		})
		return err
	}
}

func reportReuse(cmd *cobra.Command, rep creds.ReuseReport, auditPath string, jsonOut bool) error {
	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	cmd.Printf("Target:    %s (%s)\n", rep.Target, rep.Protocol)
	if rep.Protocol == creds.ProtoHTTPBasic {
		cmd.Printf("Baseline:  %s\n", rep.Baseline)
		if rep.Tested == 0 {
			cmd.Println("The endpoint does not gate on HTTP Basic auth; no credentials to judge.")
			cmd.Printf("Audit log: %s\n", auditPath)
			return nil
		}
	}
	cmd.Printf("Tried:     %d credential(s)\n", rep.Tested)
	if len(rep.Accepted) == 0 {
		cmd.Println("No supplied credential was accepted.")
	} else {
		cmd.Printf("[!] CREDENTIAL REUSE: %d credential(s) accepted (SP 800-82 r4 Table 13 / MITRE ATT&CK for ICS T0859):\n", len(rep.Accepted))
		for _, r := range rep.Accepted {
			cmd.Printf("    user=%s  source=%s  fp=%s  (%s)\n", r.User, r.Source, r.Fingerprint, r.Detail)
		}
	}
	cmd.Printf("Audit log: %s\n", auditPath)
	return nil
}
