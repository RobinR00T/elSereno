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

type fakeFTP struct {
	user, pass string
}

func (f *fakeFTP) run(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("220 Welcome\r\n"))
	r := bufio.NewReader(conn)
	userGot := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(cmd, "USER "):
			userGot = strings.TrimPrefix(cmd, "USER ")
			_, _ = conn.Write([]byte("331 Need password\r\n"))
		case strings.HasPrefix(cmd, "PASS "):
			p := strings.TrimPrefix(cmd, "PASS ")
			if userGot == f.user && p == f.pass {
				_, _ = conn.Write([]byte("230 Login OK\r\n"))
			} else {
				_, _ = conn.Write([]byte("530 Bad creds\r\n"))
			}
			return
		default:
			_, _ = conn.Write([]byte("500 Unknown\r\n"))
			return
		}
	}
}

func startFakeFTP(t *testing.T, f *fakeFTP) string {
	t.Helper()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

func TestFTP_HappyPath(t *testing.T) {
	addr := startFakeFTP(t, &fakeFTP{user: "anonymous", pass: "guest"})
	p := NewFTP()
	p.IOTimeout = 1 * time.Second
	res, err := p.Probe(context.Background(), addr, []Credential{
		{Username: "admin", Password: "admin"},
		{Username: "anonymous", Password: "guest"},
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Credential.Username != "anonymous" {
		t.Fatalf("wrong credential: %+v", res.Credential)
	}
}

func TestFTP_NoHit(t *testing.T) {
	addr := startFakeFTP(t, &fakeFTP{user: "nobody", pass: "nopass"})
	p := NewFTP()
	p.IOTimeout = 500 * time.Millisecond
	_, err := p.Probe(context.Background(), addr, []Credential{{Username: "admin", Password: "admin"}})
	if !errors.Is(err, ErrNoHit) {
		t.Fatalf("want ErrNoHit, got %v", err)
	}
}

func TestReadFTPResponse_MultiLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("220-first line\r\n220-second\r\n220 final\r\n"))
	line, code, err := readFTPResponse(r)
	if err != nil {
		t.Fatal(err)
	}
	if code != 220 {
		t.Fatalf("code = %d, want 220", code)
	}
	if !strings.HasPrefix(line, "220 final") {
		t.Fatalf("line = %q", line)
	}
}
