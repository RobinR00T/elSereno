package stdin

import (
	"context"
	"io"

	"local/elsereno/internal/core"
	"local/elsereno/internal/inputs/list"
)

// Parse reads newline-separated targets from r (typically os.Stdin).
// It is a thin wrapper around internal/inputs/list that keeps stdin as
// a first-class input per the brief.
func Parse(ctx context.Context, r io.Reader, opts list.ParseOptions) ([]core.Target, error) {
	return list.Parse(ctx, r, opts)
}
