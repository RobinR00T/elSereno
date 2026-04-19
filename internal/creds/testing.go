package creds

// SnapshotForTesting exposes the internal VaultState for round-trip
// tests. It is not part of the public API; the name is deliberately
// explicit so production callers never rely on it.
func (v *Vault) SnapshotForTesting() VaultState {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.state
}
