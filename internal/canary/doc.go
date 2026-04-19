// Package canary posts out-of-scope alerts to the webhook declared
// in scope.yaml.canary.alert_webhook. A canary fires when an
// operator attempts anything the scope rejects (target not in any
// range, port denied, protocol denied, dial number blocked, offensive
// operation denied). The webhook is best-effort: failure to POST
// never blocks the operator — it is logged and surfaced in the audit
// chain.
package canary
