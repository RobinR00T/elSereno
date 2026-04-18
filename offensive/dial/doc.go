//go:build offensive

// Package dial performs individual dialling against AT modems. Requires
// -tags offensive AND --dial-allowed; numbers with <=3 digits are
// always blocked; additional blacklists come from scope.yaml. Batch
// wardialing is vNext.
package dial
