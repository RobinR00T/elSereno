package audit

// EventType is the enumerated kind of an audit entry. The source of
// truth is the SQL CHECK constraint in migration 00001 (ADR-023); the
// constants below mirror it and are verified against the migration at
// test time.
type EventType string

// Event-type constants mirror the SQL CHECK enumeration in migration
// 00001. Values contain words like "reveal" and "token" because that is
// the on-wire audit schema; gosec G101 is disarmed locally because these
// are event-name literals, not credentials.
const (
	// EventGenesis is the first entry in a fresh audit chain; prev_hash is zeros.
	EventGenesis      EventType = "genesis"
	EventChainRebase  EventType = "chain_rebase"
	EventPurge        EventType = "purge_event"
	EventTokenRotate  EventType = "token_rotate" // #nosec G101 -- event name
	EventTokenReveal  EventType = "token_reveal" // #nosec G101 -- event name
	EventVaultInit    EventType = "vault_init"
	EventVaultUnlock  EventType = "vault_unlock"
	EventVaultLock    EventType = "vault_lock"
	EventCredsStore   EventType = "creds_store"       // #nosec G101 -- event name
	EventCredsReveal  EventType = "creds_show_reveal" // #nosec G101 -- event name
	EventCredsRotate  EventType = "creds_rotate"      // #nosec G101 -- event name
	EventCredsPurge   EventType = "creds_purge"       // #nosec G101 -- event name
	EventScopeApplied EventType = "scope_applied"
	EventServeStart   EventType = "serve_start"
	EventServeStop    EventType = "serve_stop"
	EventProtoProbe   EventType = "protocol_probe"
	EventProtoREPL    EventType = "protocol_repl_command"
	EventOffWrite     EventType = "offensive_write"
	EventOffDial      EventType = "offensive_dial"
	EventOffSMS       EventType = "offensive_sms"
	EventOffHarvest   EventType = "offensive_harvest"
	EventAdmin        EventType = "admin_action"
)

// AllEventTypes is the canonical sorted list used by the synchronisation
// test against the migration DDL. The order matches the SQL CHECK
// enumeration in migrations/00001_initial.sql to keep the diff small.
var AllEventTypes = []EventType{
	EventGenesis, EventChainRebase, EventPurge,
	EventTokenRotate, EventTokenReveal,
	EventVaultInit, EventVaultUnlock, EventVaultLock,
	EventCredsStore, EventCredsReveal, EventCredsRotate, EventCredsPurge,
	EventScopeApplied,
	EventServeStart, EventServeStop,
	EventProtoProbe, EventProtoREPL,
	EventOffWrite, EventOffDial, EventOffSMS, EventOffHarvest,
	EventAdmin,
}

// IsProtectedMetadata reports whether a row with the given event type
// is immune to audit compact (ADR-013, ADR-025).
func IsProtectedMetadata(t EventType) bool {
	switch t {
	case EventGenesis, EventChainRebase, EventPurge:
		return true
	default:
		return false
	}
}
