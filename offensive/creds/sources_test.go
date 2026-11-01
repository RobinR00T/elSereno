//go:build offensive

package creds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func write600(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadCredsFileShapes(t *testing.T) {
	lines := write600(t, "l.600", "# comment\nsvc:secret1\nroot:toor\n\n")
	if got, err := LoadCredsFile(lines); err != nil || len(got) != 2 || got[0].User != "svc" || got[0].Pass != "secret1" {
		t.Fatalf("lines: %+v %v", got, err)
	}
	arr := write600(t, "a.600", `[{"user":"a","pass":"b","source":"ad"},{"user":"c","pass":"d"}]`)
	got, err := LoadCredsFile(arr)
	if err != nil || len(got) != 2 || got[0].Source != "ad" || got[1].Source != "file:a.600" {
		t.Fatalf("array: %+v %v", got, err)
	}
	mp := write600(t, "m.600", `{"admin":"pw"}`)
	if got, err := LoadCredsFile(mp); err != nil || len(got) != 1 || got[0].User != "admin" || got[0].Pass != "pw" {
		t.Fatalf("map: %+v %v", got, err)
	}
}

func TestLoadCredsFileRejectsLoosePerms(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(p, []byte("a:b\n"), 0o644); err != nil { // #nosec G306 -- deliberately loose perms to test rejection
		t.Fatal(err)
	}
	if _, err := LoadCredsFile(p); err == nil {
		t.Fatal("0644 credential file must be refused")
	}
	if _, err := LoadCredsFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestLoadVaultKV2(t *testing.T) {
	token := write600(t, "tok.600", "s.XYZ")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "s.XYZ" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path != "/v1/secret/data/ot/admin" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"data":{"username":"svc","password":"p@ss"}}}`))
	}))
	defer srv.Close()
	got, err := LoadVaultKV2(context.Background(), srv.Client(), srv.URL, "secret", "ot/admin", token)
	if err != nil || len(got) != 1 || got[0].User != "svc" || got[0].Pass != "p@ss" {
		t.Fatalf("vault: %+v %v", got, err)
	}
}

func TestLoadVaultKV2UserPassMap(t *testing.T) {
	token := write600(t, "tok.600", "t")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"data":{"a":"u1:p1","b":"u2:p2","note":"ignore"}}}`))
	}))
	defer srv.Close()
	got, err := LoadVaultKV2(context.Background(), srv.Client(), srv.URL, "secret", "x", token)
	if err != nil || len(got) != 2 {
		t.Fatalf("vault map: %+v %v", got, err)
	}
}

func TestLoadJSONEndpoint(t *testing.T) {
	token := write600(t, "tok.600", "bear")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bear" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`[{"user":"x","pass":"y"}]`))
	}))
	defer srv.Close()
	got, err := LoadJSONEndpoint(context.Background(), srv.Client(), srv.URL, token)
	if err != nil || len(got) != 1 || got[0].User != "x" {
		t.Fatalf("endpoint: %+v %v", got, err)
	}
}
