package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"local/elsereno/internal/web/stream"
)

// SSE wire constants. Keeping them named avoids magic numbers in
// the handler and makes the heartbeat cadence visible.
const (
	// sseHeartbeatInterval is how often we emit a `: keepalive`
	// comment so intermediate proxies don't close an idle stream
	// and browsers keep the tab's connection alive.
	sseHeartbeatInterval = 15 * time.Second
	// sseRetryMS is the `retry:` hint the browser uses when it
	// needs to reconnect (3s is the node-sse default and matches
	// what humans perceive as "immediate").
	sseRetryMS = 3000
)

// Stream returns the SSE handler that exposes the broadcaster at
// `GET /api/v1/stream`. Every connected client gets every event
// published after it connected; slow clients are disconnected
// rather than allowed to stall the broadcaster (see
// `stream.Broadcaster` contract).
//
// Wire contract (see `docs/openapi.yaml`):
//
//	event: <kind>
//	id: <int64>
//	data: <json-payload>
//
// followed by a blank line. A `retry:` hint is emitted once at
// connection time; a `: keepalive` comment is emitted every
// `sseHeartbeatInterval` so reverse proxies don't idle-close
// the connection.
func Stream(b *stream.Broadcaster) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			// The default http.Server always supports flushing, but
			// a middleware could have wrapped the writer. Fail loud
			// rather than silently buffer the stream.
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		h := w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-cache, no-transform")
		h.Set("Connection", "keep-alive")
		// Disable nginx buffering on the off-chance the dashboard
		// ends up behind one. The X- prefix is the de-facto standard.
		h.Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		// Emit retry hint up-front. Browsers honour the last retry:
		// value seen; a single emit is enough.
		if _, err := fmt.Fprintf(w, "retry: %d\n\n", sseRetryMS); err != nil {
			return
		}
		flusher.Flush()

		ch, dropped, cancel := b.Subscribe()
		defer cancel()

		heartbeat := time.NewTicker(sseHeartbeatInterval)
		defer heartbeat.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-dropped:
				// The broadcaster dropped us for lagging behind the
				// event buffer. End the response so the client
				// reconnects fresh (via the retry hint) and resyncs,
				// rather than sitting on a stream that now only gets
				// heartbeats.
				return
			case ev, ok := <-ch:
				if !ok {
					// cancel closed the channel, or the server is
					// shutting down. Either way, end gracefully.
					return
				}
				if err := writeSSEEvent(w, ev); err != nil {
					return
				}
				flusher.Flush()
			case <-heartbeat.C:
				// Leading colon = SSE comment; browsers ignore it
				// but proxies see traffic and don't idle-close.
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})
}

// writeSSEEvent encodes one event as SSE lines followed by a blank
// line (the SSE framing separator). Our publishers JSON-encode the
// payload, so it is normally newline-free, but this function does not
// trust that: a raw newline in the kind or payload would otherwise
// terminate a line early and let an attacker inject extra SSE fields
// or whole events. The kind is stripped of CR/LF and a multi-line
// payload is emitted as one `data:` line per line, which is exactly
// how the SSE spec reassembles it (L8).
func writeSSEEvent(w http.ResponseWriter, ev stream.Event) error {
	// The kind → `event:` mapping lets EventSource clients filter
	// per-topic with `es.addEventListener("finding", …)` while
	// clients that just want everything use the default `message`
	// listener.
	kind := strings.NewReplacer("\r", "", "\n", "").Replace(string(ev.Kind))
	if _, err := fmt.Fprintf(w, "event: %s\n", kind); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "id: %s\n", strconv.FormatInt(ev.ID, 10)); err != nil {
		return err
	}
	// Payload is already JSON; wrap it once. An empty payload is
	// still valid, we emit `data: {}` so the parser gets an
	// object rather than choking on blank content.
	payload := ev.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	// Split on \n so an embedded newline cannot break framing; each
	// physical line becomes its own `data:` field (trailing \r
	// trimmed) and the client concatenates them with \n.
	for _, line := range bytes.Split(payload, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	return nil
}
