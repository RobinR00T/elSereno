package core

import "errors"

// Domain-wide sentinel errors. Adapter-specific sentinels (e.g.
// ErrChainBroken, ErrUnknownConfigField) live in their emitting package.
var (
	// ErrTimeout indicates that an operation timed out. Wraps context.DeadlineExceeded
	// when the deadline was externally imposed.
	ErrTimeout = errors.New("elsereno: operation timed out")

	// ErrProtocol indicates that a wire-format violation was detected.
	// Callers should treat this as non-retryable against the same target.
	ErrProtocol = errors.New("elsereno: protocol violation")

	// ErrAuth indicates that authentication was required and either
	// missing or rejected.
	ErrAuth = errors.New("elsereno: authentication required or rejected")

	// ErrValidation indicates that user-supplied input failed validation.
	ErrValidation = errors.New("elsereno: validation failed")

	// ErrNotAuthorized indicates that the action is not permitted in the
	// current build (e.g. offensive action in default build) or by the
	// current scope.
	ErrNotAuthorized = errors.New("elsereno: not authorised")

	// ErrScopeViolation indicates that the target or operation lies
	// outside the authorised scope.
	ErrScopeViolation = errors.New("elsereno: scope violation")

	// ErrEvidenceTruncated signals that captured bytes were truncated at
	// evidence.max_payload_bytes. Callers that need the full body must
	// refer to evidence.original_sha256.
	ErrEvidenceTruncated = errors.New("elsereno: evidence truncated")
)
