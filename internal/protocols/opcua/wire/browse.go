package wire

// Browse-service encode/decode for the OPC UA writeable-tag walk. Browse
// discovers the NodeIds to read: starting from a folder (ObjectsFolder
// i=85) and following HierarchicalReferences, it returns the child nodes
// and their NodeClass, so the walk can pick out the Variables and then
// Read their UserAccessLevel. Read-only recon.
//
// VALIDATION NOTE: as with read.go, no real Browse capture exists for this
// project, so this codec is grounded in OPC-UA Part 4 (§5.8.2 Browse,
// §7.3 BrowseDescription, §7.29 ReferenceDescription) + Part 6 (§5.2
// binary encoding, ExpandedNodeId/QualifiedName) and validated by
// round-trip + a spec-crafted BrowseResponse fixture, not by real bytes.

// referenceTypeHierarchical is HierarchicalReferences (ns=0, i=33): the
// supertype of HasComponent, HasProperty and the folder-membership
// reference (i=35), so browsing it with includeSubtypes=true walks the
// whole containment tree.
const referenceTypeHierarchical uint16 = 33

// browseDirectionForward is BrowseDirection=Forward (Part 4 §7.5): follow
// references away from the start node (into its children).
const browseDirectionForward uint32 = 0

// browseResultMaskAll asks the server to populate every ReferenceDescription
// field (Part 4 §7.3, BrowseResultMask): ReferenceType|IsForward|NodeClass|
// BrowseName|DisplayName|TypeDefinition = 0x3F. NodeClass is the one the
// walk needs; requesting all keeps the response self-describing.
const browseResultMaskAll uint32 = 0x3F

// Caps on the arrays a BrowseResponse may carry, so a hostile server can't
// drive a huge allocation from an array count.
const (
	maxBrowseResults = 1024
	maxBrowseRefs    = 65536
)

// BrowseRef is one child reference from a BrowseResponse. NodeID is the
// raw NodeId bytes of the target (ExpandedNodeId flags stripped), ready to
// feed straight into a ReadRequest.
type BrowseRef struct {
	NodeID     []byte
	NodeClass  uint32
	BrowseName string
}

// EncodeBrowseRequestTCP builds a BrowseRequest MSG on an open, activated
// secure channel that browses one node's forward HierarchicalReferences.
// nodeToBrowse is the raw NodeId bytes (e.g. FourByteNodeID(85)); maxRefs
// caps references per node (0 = server default).
func EncodeBrowseRequestTCP(channelID, tokenID, seqNum, reqID uint32, authToken, nodeToBrowse []byte, maxRefs uint32) []byte {
	b := putSymmetricHeader(channelID, tokenID, seqNum, reqID)
	b = putFourByteNodeID(b, TypeIDBrowseRequest)
	b = putRequestHeader(b, authToken)
	// BrowseRequest body (Part 4 §5.8.2).
	// view: ViewDescription = null viewId + timestamp + viewVersion.
	b = append(b, 0x00, 0x00) // viewId: null NodeId (TwoByte, id 0)
	b = putU32(b, 0)          // timestamp DateTime low ...
	b = putU32(b, 0)          // ... (8 bytes) = 0
	b = putU32(b, 0)          // viewVersion
	b = putU32(b, maxRefs)    // requestedMaxReferencesPerNode
	// nodesToBrowse: one BrowseDescription.
	b = putI32(b, 1)
	b = append(b, nodeToBrowse...)                      // nodeId
	b = putU32(b, browseDirectionForward)               // browseDirection
	b = putFourByteNodeID(b, referenceTypeHierarchical) // referenceTypeId i=33
	b = append(b, 0x01)                                 // includeSubtypes = true
	b = putU32(b, 0)                                    // nodeClassMask = 0 (all classes)
	b = putU32(b, browseResultMaskAll)                  // resultMask
	return wrap(MessageMessage, b)
}

// expandedNodeID reads an ExpandedNodeId (Part 6 §5.2.2.10) and returns
// the raw bytes of its NodeId part, with the ExpandedNodeId flag bits
// (NamespaceUri 0x80, ServerIndex 0x40) cleared from the encoding byte so
// the result is a plain, reusable NodeId. The NamespaceUri/ServerIndex
// extras are consumed but not included.
func (c *cur) expandedNodeID() []byte {
	if c.err != nil {
		return nil
	}
	start := c.off
	encByte := c.u8()
	switch NodeIDEncoding(encByte & 0x0F) {
	case NodeIDTwoByte:
		c.skip(1)
	case NodeIDFourByte:
		c.skip(3)
	case NodeIDNumeric:
		c.skip(6)
	case NodeIDString, NodeIDByteString:
		c.skip(2)
		c.byteString()
	case NodeIDGuid:
		c.skip(2 + 16)
	default:
		c.err = ErrShortResponse
		return nil
	}
	end := c.off // end of the NodeId part
	if encByte&0x80 != 0 {
		_ = c.str() // NamespaceUri
	}
	if encByte&0x40 != 0 {
		c.skip(4) // ServerIndex
	}
	if c.fail() || start >= end || end > len(c.b) {
		return nil
	}
	out := make([]byte, end-start)
	copy(out, c.b[start:end])
	out[0] &= 0x0F // strip ExpandedNodeId flags -> plain NodeId encoding byte
	return out
}

// qualifiedName reads a QualifiedName (Part 6 §5.2.2.13) and returns its
// name (the namespaceIndex is skipped).
func (c *cur) qualifiedName() string {
	c.skip(2) // namespaceIndex u16
	return c.str()
}

// ParseBrowseResponse walks a BrowseResponse MSG body (the bytes after the
// 8-byte UA-TCP header) and returns the child references across all
// BrowseResults, each with its target NodeId, NodeClass and BrowseName.
// Fail-closed on truncation or an over-large array count.
func ParseBrowseResponse(msgBody []byte) ([]BrowseRef, bool) {
	c := &cur{b: msgBody}
	c.skip(16) // SecureChannelId + TokenId + SequenceNumber + RequestId
	c.nodeID() // message TypeId
	c.responseHeader()
	nres := c.arrayLen() // results []BrowseResult
	if c.fail() || nres > maxBrowseResults {
		return nil, false
	}
	var refs []BrowseRef
	for i := int32(0); i < nres && !c.fail(); i++ {
		_ = c.u32()    // BrowseResult.statusCode
		c.byteString() // BrowseResult.continuationPoint
		nref := c.arrayLen()
		if c.fail() || nref > maxBrowseRefs {
			return nil, false
		}
		for j := int32(0); j < nref && !c.fail(); j++ {
			c.nodeID()                // ReferenceDescription.referenceTypeId
			c.skip(1)                 // isForward (Boolean)
			nid := c.expandedNodeID() // nodeId (ExpandedNodeId target)
			bn := c.qualifiedName()   // browseName
			_ = c.localizedText()     // displayName
			nc := c.u32()             // nodeClass (Int32 enum)
			c.expandedNodeID()        // typeDefinition (discarded)
			if !c.fail() && nid != nil {
				refs = append(refs, BrowseRef{NodeID: nid, NodeClass: nc, BrowseName: bn})
			}
		}
	}
	if c.fail() {
		return nil, false
	}
	return refs, true
}
