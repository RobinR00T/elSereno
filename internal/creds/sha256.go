package creds

import "crypto/sha256"

// sha256new is a tiny shim around crypto/sha256.New so callers in
// vault.go don't need to import crypto/sha256 directly. HKDF's New
// takes a hash.Hash constructor, so we pass this value.
var sha256new = sha256.New
