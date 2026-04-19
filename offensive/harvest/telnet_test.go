//go:build offensive

package harvest

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeTelnet accepts one connection, runs the given script
// (sequence of writes-from-server + expected-input-matchers), and
// closes. The script maps sent bytes to the server's next response.
type fakeTelnet struct {
	banner      string
	user        string
	pass        string
	shellPrompt string
}

func (f *fakeTelnet) run(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(f.banner)); err != nil {
		return
	}
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	got := strings.TrimRight(line, "\r\n")
	if got != f.user {
		_, _ = conn.Write([]byte("Login incorrect\r\n"))
		return
	}
	_, _ = conn.Write([]byte("Password: "))
	line, err = r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	got = strings.TrimRight(line, "\r\n")
	if got != f.pass {
		_, _ = conn.Write([]byte("Login incorrect\r\n"))
		return
	}
	_, _ = conn.Write([]byte(f.shellPrompt))
}

func startFakeTelnet(t *testing.T, f *fakeTelnet) string {
	t.Helper()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.run(c)
		}
	}()
	return ln.Addr().String()
}

func TestTelnet_HappyPath(t *testing.T) {
	addr := startFakeTelnet(t, &fakeTelnet{
		banner:      "Welcome to router 3.2\r\nlogin: ",
		user:        "admin",
		pass:        "admin",
		shellPrompt: "\r\nroot@router:~# ",
	})
	p := &TelnetProber{DialTimeout: 2 * time.Second, IOTimeout: 1 * time.Second}
	res, err := p.Probe(context.Background(), addr, []Credential{
		{Username: "root", Password: "root"},
		{Username: "admin", Password: "admin"},
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Credential.Username != "admin" || res.Credential.Password != "admin" {
		t.Fatalf("wrong credential: %+v", res.Credential)
	}
}

func TestTelnet_NoHit(t *testing.T) {
	addr := startFakeTelnet(t, &fakeTelnet{
		banner:      "login: ",
		user:        "admin",
		pass:        "hunter2",
		shellPrompt: "# ",
	})
	p := &TelnetProber{DialTimeout: 2 * time.Second, IOTimeout: 500 * time.Millisecond}
	_, err := p.Probe(context.Background(), addr, []Credential{
		{Username: "admin", Password: "admin"},
		{Username: "root", Password: "root"},
	})
	if !errors.Is(err, ErrNoHit) {
		t.Fatalf("expected ErrNoHit, got %v", err)
	}
}

func TestTelnet_EmptyCredsSkipped(t *testing.T) {
	addr := startFakeTelnet(t, &fakeTelnet{
		banner:      "login: ",
		user:        "admin",
		pass:        "admin",
		shellPrompt: "# ",
	})
	p := &TelnetProber{DialTimeout: 2 * time.Second, IOTimeout: 500 * time.Millisecond}
	_, err := p.Probe(context.Background(), addr, []Credential{{}})
	if !errors.Is(err, ErrNoHit) {
		t.Fatalf("empty creds should skip, got %v", err)
	}
}

func TestPromptDetectors(t *testing.T) {
	for _, s := range []string{"login:", "Username: ", "USER: "} {
		if !containsLoginPrompt(s) {
			t.Errorf("should match login: %q", s)
		}
	}
	for _, s := range []string{"Password: ", "PASSWD:"} {
		if !containsPasswordPrompt(s) {
			t.Errorf("should match password: %q", s)
		}
	}
	for _, s := range []string{"root@x:/#", "user@x:/$", "cisco>", "PS %"} {
		if !containsShellPrompt(s) {
			t.Errorf("should match shell: %q", s)
		}
	}
	for _, s := range []string{"Login incorrect\n", "Authentication failed", "access denied"} {
		if !containsLoginFail(s) {
			t.Errorf("should match fail: %q", s)
		}
	}
}
