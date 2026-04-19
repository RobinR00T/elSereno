# Non-goals

ElSereno deliberately does not attempt to be any of the following:

- **Not a SIEM.** We do not ingest, correlate, or retain security events from
  third-party sources as a long-lived stream. Findings are per-run artefacts.
- **Not an exploitation framework like Metasploit.** Offensive capabilities are
  deliberately narrow, opt-in via `-tags offensive`, and require triple-confirm
  for writes. We do not maintain an exploit database.
- **Not a corporate asset inventory.** ElSereno audits exposure; CMDB / asset
  management is out of scope.
- **Not a collaborative multi-user platform in v1.** Single-operator workflow
  only. Multi-user with OIDC is vNext.
- **Not an IDS / real-time alerting stream.** No continuous monitoring with
  live alert pipelines. Remediation orchestration belongs elsewhere.
- **Not a remediation orchestrator.** We surface findings with scoring and
  explanations; acting on them is the operator's responsibility.
- **No Windows support in v1.** Linux and macOS only (amd64, arm64). Windows
  is vNext.
- **No batch wardialing in v1.** Individual dial with triple-confirm is
  allowed in the offensive build; batch wardialing with a scope file is vNext.
