package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"local/elsereno/internal/core"
	"local/elsereno/internal/inputs/preview"
)

// PreviewInput returns the `GET /api/v1/inputs/preview` handler.
// v1.36+: dashboard --input parity with the scan / tui verbs.
//
// Query params:
//
//	kind          required. list:<path> | nmap:<path> | stdin
//	default_port  optional. Default 0 (no default; parse error
//	              if any host omits its port).
//
// Response (JSON):
//
//	{
//	  "schema": "api:v1",
//	  "data": {
//	    "count":    int,           // number of targets parsed
//	    "targets":  [<Target>],    // sample (capped at 200)
//	    "truncated": bool          // true when count > 200
//	  }
//	}
//
// Failure modes:
//
//	400  malformed kind, unknown kind (provider kinds are
//	     explicitly rejected via ErrUnsupportedKind), bad
//	     default_port. Reuses the preview package's error
//	     wording so operators see the same message as the
//	     CLI.
//	404  list:/nmap: path doesn't exist (or isn't readable)
//	500  parse failure inside the underlying parser.
//
// Why a sample cap at 200 entries: the dashboard wants a
// preview, not a full target dump. Operators dealing with
// 50k-entry CIDR sweeps don't need to round-trip 50k JSON
// objects through the dashboard; they want "yes, my list:
// parses cleanly" + a sample to eyeball.
func PreviewInput() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := r.URL.Query().Get("kind")
		if kind == "" {
			http.Error(w, "preview: missing required ?kind=", http.StatusBadRequest)
			return
		}
		var defaultPort core.Port
		if dp := r.URL.Query().Get("default_port"); dp != "" {
			n, err := strconv.Atoi(dp)
			if err != nil || n < 0 || n > 0xFFFF {
				http.Error(w,
					fmt.Sprintf("preview: invalid default_port %q (want 0..65535)", dp),
					http.StatusBadRequest)
				return
			}
			defaultPort = core.Port(n)
		}

		targets, err := preview.Parse(r.Context(), preview.Opts{
			Kind:        kind,
			DefaultPort: defaultPort,
		})
		if err != nil {
			handlePreviewError(w, err)
			return
		}
		writeJSON(w, envelope{
			Schema: "api:" + APIVersion,
			Data:   buildPreviewResponse(targets),
		})
	})
}

// handlePreviewError maps the preview package's error types
// onto HTTP status codes. Pulled out so the handler stays
// readable.
func handlePreviewError(w http.ResponseWriter, err error) {
	var unsup preview.ErrUnsupportedKind
	if errors.As(err, &unsup) {
		http.Error(w, unsup.Error(), http.StatusBadRequest)
		return
	}
	// Filesystem errors from os.Open. Map to 404 so the
	// dashboard can show a friendly "file not found" message.
	// os.IsNotExist handles *PathError wrapping itself.
	if os.IsNotExist(err) {
		http.Error(w, "preview: "+err.Error(), http.StatusNotFound)
		return
	}
	http.Error(w, "preview: "+err.Error(), http.StatusInternalServerError)
}

// previewResponse is the JSON shape the handler returns.
type previewResponse struct {
	Count     int            `json:"count"`
	Targets   []previewEntry `json:"targets"`
	Truncated bool           `json:"truncated"`
}

// previewEntry is the per-target shape. We don't reuse
// repo.Finding / core.Target verbatim because the preview
// audience just wants address + port + the IPv4/IPv6
// disambiguator.
type previewEntry struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Family  string `json:"family"` // "ipv4" or "ipv6"
}

// previewSampleCap is the limit on entries returned in the
// JSON sample. Same threshold the TUI uses for findings tail.
const previewSampleCap = 200

func buildPreviewResponse(targets []core.Target) previewResponse {
	out := previewResponse{Count: len(targets)}
	cap := previewSampleCap
	if len(targets) <= cap {
		cap = len(targets)
	} else {
		out.Truncated = true
	}
	out.Targets = make([]previewEntry, 0, cap)
	for i := 0; i < cap; i++ {
		fam := "ipv4"
		if targets[i].Address.Is6() && !targets[i].Address.Is4In6() {
			fam = "ipv6"
		}
		out.Targets = append(out.Targets, previewEntry{
			Address: targets[i].Address.String(),
			Port:    int(targets[i].Port),
			Family:  fam,
		})
	}
	return out
}
