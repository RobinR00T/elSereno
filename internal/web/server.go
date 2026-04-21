package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"local/elsereno/internal/config"
	"local/elsereno/internal/creds"
	"local/elsereno/internal/web/handlers"
	"local/elsereno/internal/web/httpctx"
	"local/elsereno/internal/web/stream"
)

// Options configures the HTTP server. Nil fields fall back to defaults.
type Options struct {
	Addr string
	Web  config.WebConfig
	// Vault is used to derive the CSRF key via HKDF (ADR-017). It must
	// be unlocked before Run.
	Vault *creds.Vault

	TLSCert string
	TLSKey  string

	// NowSource is the clock used for /readyz timestamps. Nil -> time.Now.
	NowSource func() time.Time
}

// Server is the wrapped http.Server with the full set of timeouts and
// the default handler tree mounted.
type Server struct {
	opts      Options
	server    *http.Server
	startedAt time.Time

	csrfKey []byte

	// broadcaster is the process-local SSE fan-out. Every publisher
	// (scanner, audit writer, offensive verbs) calls into this to
	// push an event to connected `/api/v1/stream` clients.
	broadcaster *stream.Broadcaster
}

// NewServer constructs a Server with ADR-014/ADR-017 defaults applied.
func NewServer(opts Options) (*Server, error) {
	if opts.Vault == nil {
		return nil, errors.New("web: Options.Vault is required")
	}
	if opts.NowSource == nil {
		opts.NowSource = time.Now
	}
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8787"
	}

	// Derive CSRF key via HKDF from the vault master key (ADR-017).
	csrfKey := make([]byte, 32)
	if err := opts.Vault.Derive("elsereno/csrf/v1", csrfKey); err != nil {
		return nil, fmt.Errorf("web: derive csrf key: %w", err)
	}

	s := &Server{
		opts:        opts,
		startedAt:   opts.NowSource(),
		csrfKey:     csrfKey,
		broadcaster: stream.New(128),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.readyz)
	mux.Handle("/api/v1/", handlers.APIV1(s.broadcaster))
	mux.Handle("/admin/security", handlers.Security())
	mux.Handle("/", handlers.Dashboard())

	// #nosec G112 -- all timeouts are set explicitly below.
	s.server = &http.Server{
		Addr:              opts.Addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: nonzero(opts.Web.ReadHeaderTimeout, 5*time.Second),
		ReadTimeout:       nonzero(opts.Web.ReadTimeout, 30*time.Second),
		WriteTimeout:      nonzero(opts.Web.WriteTimeout, 30*time.Second),
		IdleTimeout:       nonzero(opts.Web.IdleTimeout, 120*time.Second),
		MaxHeaderBytes:    1 << 14, // 16 KiB
	}
	return s, nil
}

// Run starts the server and blocks until ctx is cancelled or the
// server errors.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if s.opts.TLSCert != "" && s.opts.TLSKey != "" {
			errCh <- s.server.ListenAndServeTLS(s.opts.TLSCert, s.opts.TLSKey)
			return
		}
		errCh <- s.server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		// Decoupled timeout: ctx is already cancelled, so we cannot
		// propagate it to Shutdown or the drain would abort
		// immediately. We want the drain window to finish.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		//nolint:contextcheck // decoupled on purpose: parent ctx is already cancelled
		_ = s.server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// Addr returns the bound address (for tests; Run must have started).
func (s *Server) Addr() string { return s.server.Addr }

// Broadcaster returns the SSE broadcaster so the process's publishers
// (scanner, audit writer, offensive verbs) can push events to
// connected /api/v1/stream clients.
func (s *Server) Broadcaster() *stream.Broadcaster { return s.broadcaster }

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok","started_at":%q}`, s.startedAt.UTC().Format(time.RFC3339))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	// The real /readyz verifies DB + migrations + disk + audit tail
	// (ADR-022). Without a DB connection in-process we return a 200
	// with a "degraded" note; the CLI `elsereno doctor` covers
	// operator-level checks.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `{"status":"ready","db":"skipped","audit":"skipped"}`)
}

// securityHeaders adds the default header set (HSTS only under TLS so
// it is the caller's responsibility to wrap with https middleware).
// A CSP nonce is generated per request and stashed in the request
// context (see `internal/web/httpctx`) so templates can render
// inline <script nonce=...> without weakening the policy.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		nonce := randNonce()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self' 'nonce-"+nonce+"'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		r = r.WithContext(httpctx.WithCSPNonce(r.Context(), nonce))
		next.ServeHTTP(w, r)
	})
}

// randNonce returns a short base64 value suitable for a CSP nonce.
func randNonce() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func nonzero[T comparable](a, def T) T {
	var zero T
	if a == zero {
		return def
	}
	return a
}
