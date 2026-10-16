package inputs_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"local/elsereno/internal/inputs"
)

func TestRedactQuery_URLError(t *testing.T) {
	ue := &url.Error{
		Op:  "Get",
		URL: "https://api.example/search?email=ops%40example.com&key=s3cr3t-key&query=port%3A502",
		Err: context.DeadlineExceeded,
	}
	err := inputs.RedactQuery(fmt.Errorf("fofa: http: %w", ue), "key", "email")
	msg := err.Error()
	for _, leak := range []string{"s3cr3t-key", "ops%40example.com", "ops@example.com"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error still carries %q: %s", leak, msg)
		}
	}
	if !strings.Contains(msg, "key="+inputs.Redacted) || !strings.Contains(msg, "query=port%3A502") {
		t.Fatalf("want the key redacted and the query kept: %s", msg)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("the cause is no longer reachable with errors.Is")
	}
	for e := errors.Unwrap(err); e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), "s3cr3t-key") {
			t.Fatalf("an unwrapped error still carries the key: %v", e)
		}
	}
}

func TestRedactQuery_UnwrappedURLErrorKeepsItsType(t *testing.T) {
	ue := &url.Error{Op: "Get", URL: "https://api.example/host/1.2.3.4?key=s3cr3t-key", Err: errors.New("refused")}
	err := inputs.RedactQuery(ue, "key")
	var got *url.Error
	if !errors.As(err, &got) || strings.Contains(err.Error(), "s3cr3t-key") {
		t.Fatalf("want a *url.Error without the key, got %T %v", err, err)
	}
}

func TestRedactQuery_UnparseableURLDropsQuery(t *testing.T) {
	ue := &url.Error{Op: "parse", URL: "http://[bad host/search?key=s3cr3t-key", Err: errors.New("bad")}
	msg := inputs.RedactQuery(ue, "key").Error()
	if strings.Contains(msg, "s3cr3t-key") {
		t.Fatalf("error still carries the key: %s", msg)
	}
}

func TestRedactQuery_OtherErrorsUnchanged(t *testing.T) {
	base := errors.New("shodan: status 401")
	if got := inputs.RedactQuery(base, "key"); !errors.Is(got, base) || got.Error() != base.Error() {
		t.Fatalf("got %v, want the same error", got)
	}
	if inputs.RedactQuery(nil, "key") != nil {
		t.Fatal("nil must stay nil")
	}
}
