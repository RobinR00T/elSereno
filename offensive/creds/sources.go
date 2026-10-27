//go:build offensive

package creds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// maxCredFile caps a credential or token file so a wrong path (a disk
// image, a log) cannot be slurped into memory.
const maxCredFile = 1 << 20 // 1 MiB

// readSecretFile reads path after refusing it unless it is a regular file
// with mode 0600 (no group or other bits). A credential or token file
// that the group or the world can read is itself the exposure this tool
// looks for, so it will not read one (CLAUDE.md: secrets live in a 0600
// file). It returns the trimmed contents.
func readSecretFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("creds: %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("creds: %s has mode %04o; it must be 0600 (no group or other access) for a secret file", path, perm)
	}
	f, err := os.Open(path) // #nosec G304 -- operator-supplied secret file, perm-checked above
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxCredFile))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// LoadCredsFile reads credentials from a 0600 file. Two shapes are
// accepted, chosen by the first non-space byte:
//
//	JSON (starts with '[' or '{'):
//	  [{"user":"svc","pass":"...","source":"ad-service"}, ...]   (array)
//	  {"svc":"...", "root":"..."}                                (user->pass map)
//	Lines (anything else): one "user:pass" per line, '#' comments
//	  and blank lines ignored; the first ':' splits.
//
// The source label defaults to "file:<name>" and is kept from the JSON
// array form when given.
func LoadCredsFile(path string) ([]Credential, error) {
	content, err := readSecretFile(path)
	if err != nil {
		return nil, err
	}
	label := "file:" + baseName(path)
	trimmed := strings.TrimLeft(content, " \t\r\n")
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
		return parseJSONCreds([]byte(trimmed), label)
	}
	var out []Credential
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, p, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("creds: %s: line %q is not user:pass", path, line)
		}
		out = append(out, Credential{User: u, Pass: p, Source: label})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("creds: %s held no credentials", path)
	}
	return out, nil
}

// parseJSONCreds decodes the array or map JSON shapes.
func parseJSONCreds(b []byte, label string) ([]Credential, error) {
	var arr []struct {
		User, Pass, Source string
	}
	if json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
		out := make([]Credential, 0, len(arr))
		for _, c := range arr {
			src := c.Source
			if src == "" {
				src = label
			}
			out = append(out, Credential{User: c.User, Pass: c.Pass, Source: src})
		}
		return out, nil
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("creds: JSON is neither [{user,pass}] nor {user:pass}: %w", err)
	}
	out := make([]Credential, 0, len(m))
	for u, p := range m {
		out = append(out, Credential{User: u, Pass: p, Source: label})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("creds: JSON held no credentials")
	}
	return out, nil
}

// LoadVaultKV2 reads one HashiCorp Vault KV v2 secret and turns its data
// into credentials. The token is read from tokenFile (0600); it is sent
// in the X-Vault-Token header, never on argv or in the URL. TLS
// verification is the caller's client's (verification stays on: the
// secret store is infrastructure, not a device UI).
//
// The secret's data map is read in two shapes:
//
//	username + password fields -> one credential
//	otherwise, each field whose value is "user:pass" -> one credential
func LoadVaultKV2(ctx context.Context, client *http.Client, addr, mount, path, tokenFile string) ([]Credential, error) {
	token, err := readSecretFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("creds: vault token: %w", err)
	}
	url := fmt.Sprintf("%s/v1/%s/data/%s", strings.TrimRight(addr, "/"), mount, strings.TrimLeft(path, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("creds: vault GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("creds: vault returned %d for %s", resp.StatusCode, url)
	}
	var env struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCredFile)).Decode(&env); err != nil {
		return nil, fmt.Errorf("creds: vault KV v2 decode: %w", err)
	}
	return credsFromMap(env.Data.Data, "vault:"+mount+"/"+path)
}

// LoadJSONEndpoint reads credentials from a generic JSON endpoint. When
// tokenFile is non-empty its 0600 contents are sent as a bearer token.
// The body is an array of {user,pass,source?} or a {user:pass} map. TLS
// verification is the caller's client's.
func LoadJSONEndpoint(ctx context.Context, client *http.Client, url, tokenFile string) ([]Credential, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if tokenFile != "" {
		token, err := readSecretFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("creds: endpoint token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("creds: endpoint GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("creds: endpoint returned %d for %s", resp.StatusCode, url)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxCredFile))
	if err != nil {
		return nil, err
	}
	return parseJSONCreds(b, "endpoint:"+url)
}

// credsFromMap turns a Vault data map into credentials.
func credsFromMap(m map[string]any, label string) ([]Credential, error) {
	str := func(k string) (string, bool) {
		v, ok := m[k].(string)
		return v, ok
	}
	if u, ok := str("username"); ok {
		if p, ok := str("password"); ok {
			return []Credential{{User: u, Pass: p, Source: label}}, nil
		}
	}
	if u, ok := str("user"); ok {
		if p, ok := str("pass"); ok {
			return []Credential{{User: u, Pass: p, Source: label}}, nil
		}
	}
	var out []Credential
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if u, p, found := strings.Cut(s, ":"); found {
			out = append(out, Credential{User: u, Pass: p, Source: label + "#" + k})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("creds: vault secret %s has no username/password field and no user:pass values", label)
	}
	return out, nil
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}
