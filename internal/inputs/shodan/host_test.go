package shodan_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"local/elsereno/internal/inputs/shodan"
)

func TestHostParsesExposure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "" {
			http.Error(w, "no key", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("history") != "true" {
			http.Error(w, "history flag not forwarded", http.StatusBadRequest)
			return
		}
		// Port 502 appears twice (history), 44818 once, one bad port.
		fmt.Fprint(w, `{
			"ip_str": "10.0.0.5",
			"hostnames": ["plc.example"],
			"os": null,
			"ports": [502, 44818],
			"data": [
				{"port":502,"transport":"tcp","product":"Modbus","timestamp":"2026-01-01T00:00:00","vulns":{"CVE-2020-1111":{},"CVE-2019-2222":{}}},
				{"port":502,"transport":"tcp","product":"Modbus","timestamp":"2026-02-01T00:00:00"},
				{"port":44818,"transport":"tcp","product":"EtherNet/IP"},
				{"port":99999,"transport":"tcp"}
			]
		}`)
	}))
	defer srv.Close()

	c, err := shodan.New("dummy", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.BaseURL = srv.URL

	info, err := c.Host(context.Background(), "10.0.0.5", true)
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if info.IP != "10.0.0.5" || len(info.Data) != 4 {
		t.Fatalf("unexpected host info: %+v", info)
	}

	// Targets de-duplicate the repeated port and drop the bad one.
	targets := info.Targets()
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 (dedup 502, drop 99999)", len(targets))
	}

	// CVE union across services.
	cves := info.CVEs()
	if len(cves) != 2 || cves[0] != "CVE-2019-2222" || cves[1] != "CVE-2020-1111" {
		t.Fatalf("unexpected CVEs: %v", cves)
	}
}

func TestHostNotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "No information available", http.StatusNotFound)
	}))
	defer srv.Close()
	c, _ := shodan.New("k", 0)
	c.BaseURL = srv.URL
	_, err := c.Host(context.Background(), "10.0.0.9", false)
	if !errors.Is(err, shodan.ErrHostNotFound) {
		t.Fatalf("got %v, want ErrHostNotFound", err)
	}
}

func TestHostRejectsBadIP(t *testing.T) {
	t.Parallel()
	c, _ := shodan.New("k", 0)
	_, err := c.Host(context.Background(), "not-an-ip", false)
	if err == nil {
		t.Fatal("expected error on malformed ip")
	}
}
