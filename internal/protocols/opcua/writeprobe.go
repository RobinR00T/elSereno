package opcua

import (
	"context"
	"io"

	"local/elsereno/internal/protocols/opcua/wire"
)

// objectsFolderNodeID is the OPC UA ObjectsFolder (ns=0, i=85): the
// conventional root of a server's live process data, so the walk starts
// there rather than at the Root folder (whose Types/Views subtrees hold no
// writeable process tags).
var objectsFolderNodeID = wire.FourByteNodeID(85)

// defaultWalkBudget bounds the walk when the caller passes maxNodes<=0.
const defaultWalkBudget = 500

// WriteableNode is one address-space node the anonymous user can write.
type WriteableNode struct {
	NodeID          string // canonical NodeId text ("ns=2;s=Setpoint", ...)
	BrowseName      string
	UserAccessLevel byte
}

// WriteableWalkResult is the outcome of the writeable-tag walk. It embeds
// the anonymous-access result (the walk only runs when a session opens) and
// adds what the walk found. Writeable is the headline: nodes a stranger can
// change.
type WriteableWalkResult struct {
	AnonymousAccessResult
	FoldersBrowsed int
	VariablesRead  int
	Writeable      []WriteableNode
	// Truncated is true when the node budget was reached before the address
	// space was fully walked, so Writeable may be incomplete.
	Truncated bool
}

// ProbeWriteableNodes opens an anonymous session (exactly like
// ProbeAnonymousAccess) and, if it opens, walks the address space from
// ObjectsFolder (i=85) over forward hierarchical references: it descends
// into Objects/Views and, for every Variable it meets, reads the
// UserAccessLevel attribute and flags the ones the anonymous user can write
// (AccessLevel CurrentWrite bit). The walk is a breadth-first traversal
// bounded by maxNodes (total nodes tracked and folders browsed), so a huge
// or hostile address space cannot run away. It is strictly read-only: it
// reads attributes, it never issues a Write. The caller sets deadlines on
// conn.
func ProbeWriteableNodes(ctx context.Context, conn io.ReadWriter, endpointURL string, maxNodes int) (WriteableWalkResult, error) {
	var out WriteableWalkResult
	sess, res, err := establishAnonymousSession(ctx, conn, endpointURL)
	out.AnonymousAccessResult = res
	if err != nil || sess == nil {
		return out, err // not exposed (or a transport error): nothing to walk
	}
	if maxNodes <= 0 {
		maxNodes = defaultWalkBudget
	}

	visited := map[string]bool{wire.NodeIDText(objectsFolderNodeID): true}
	queue := [][]byte{objectsFolderNodeID}

	for len(queue) > 0 {
		if ctx.Err() != nil {
			break
		}
		if out.FoldersBrowsed >= maxNodes {
			out.Truncated = true
			break
		}
		node := queue[0]
		queue = queue[1:]

		refs, ok := sess.browse(node)
		if !ok {
			continue // treat an unbrowsable node as a dead end, not fatal
		}
		out.FoldersBrowsed++

		// Split children: Variables get their UserAccessLevel read in one
		// batch; everything else (Object/View/...) is queued to descend.
		var vars []wire.BrowseRef
		for _, r := range refs {
			if r.NodeClass == wire.NodeClassVariable {
				vars = append(vars, r)
				continue
			}
			k := wire.NodeIDText(r.NodeID)
			if visited[k] {
				continue
			}
			if len(visited) >= maxNodes {
				out.Truncated = true
				continue
			}
			visited[k] = true
			queue = append(queue, r.NodeID)
		}
		out.appendWriteable(sess, vars)
	}
	// Past the setup guard above, err is nil and the walk itself has no
	// error path: browse/read failures are soft dead ends (ok=false), by
	// design, so a partial walk still returns what it found.
	return out, nil //nolint:nilerr // walk failures are intentionally soft; setup error already handled
}

// appendWriteable reads the UserAccessLevel of every Variable in vars (one
// ReadRequest) and appends those the anonymous user can write to out.
func (out *WriteableWalkResult) appendWriteable(sess *uaSession, vars []wire.BrowseRef) {
	if len(vars) == 0 {
		return
	}
	nodes := make([][]byte, len(vars))
	for i, v := range vars {
		nodes[i] = v.NodeID
	}
	results, ok := sess.readUserAccessLevels(nodes)
	if !ok || len(results) != len(vars) {
		return // a mismatched result count is unsafe to align: skip this batch
	}
	out.VariablesRead += len(vars)
	for i, v := range vars {
		dv := results[i]
		if !dv.HasValue {
			continue
		}
		ual := byte(dv.UintValue & 0xff) // #nosec G115 -- UserAccessLevel is a Byte; only the low 8 bits are defined
		if ual&wire.AccessLevelCurrentWrite != 0 {
			out.Writeable = append(out.Writeable, WriteableNode{
				NodeID:          wire.NodeIDText(v.NodeID),
				BrowseName:      v.BrowseName,
				UserAccessLevel: ual,
			})
		}
	}
}
