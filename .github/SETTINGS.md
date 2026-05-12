# GitHub repo settings — expected configuration

This file documents the GitHub repo-level settings that ElSereno
expects. **These cannot be fully managed in version control**
(GitHub doesn't expose every setting via API or `.github/`
files), so this doc is the source of truth for what a human or
admin must configure manually.

> When you flip a repo (PRIVATE → PUBLIC, fork settings change,
> new admins, etc.), walk this checklist top to bottom.

---

## 1. General

`Settings → General`:

| Setting | Expected | Why |
|---|---|---|
| Default branch | `main` | Convention |
| Allow squash merging | ✅ ON | We use squash for PR merges |
| Allow merge commits | ❌ OFF | Prefer linear history |
| Allow rebase merging | ❌ OFF | Squash is canonical |
| Always suggest updating PR branches | ✅ ON | Prevents stale-base merges |
| Automatically delete head branches | ✅ ON | Hygiene; `--delete-branch` does it too |
| Allow auto-merge | ✅ ON | Required for `gh pr merge --auto` |

---

## 2. Branches → branch protection rules

`Settings → Branches → main`:

| Rule | Expected |
|---|---|
| Require a pull request before merging | ❌ OFF (single-operator workflow uses direct commits to `main`) |
| Require status checks to pass before merging | ❌ OFF currently; ON candidate when more contributors |
| Require branches to be up to date before merging | ❌ OFF (else Dependabot batches need constant rebase) |
| Require conversation resolution | ❌ OFF |
| Require signed commits | ❌ OFF (we sign tags, not every commit) |
| Require linear history | ✅ ON (matches squash-only merge policy) |
| Allow force pushes | ❌ OFF on main |
| Allow deletions | ❌ OFF on main |

> When multi-operator workflow lands (vNext OIDC), tighten:
> require status checks + PR review.

---

## 3. Actions → General

`Settings → Actions → General`:

### Actions permissions

| Setting | Expected |
|---|---|
| Actions permissions | ✅ "Allow all actions and reusable workflows" |

(All the actions we use are well-known: `actions/*`,
`securego/gosec`, `golangci/golangci-lint-action`,
`goreleaser/goreleaser-action`, `dependabot/fetch-metadata`,
`ossf/scorecard-action`, etc. Restricting to "RobinR00T
only" would break almost every workflow.)

### Approval for running fork pull request workflows from contributors

| Setting | Expected | Why |
|---|---|---|
| Approval policy | ✅ "Require approval for first-time contributors who are new to GitHub" | Dependabot bots and established users pass auto; only literal brand-new GitHub accounts need approval |

> ⚠️ Default after flipping PUBLIC is "Require approval for all
> external contributors" — this BLOCKS Dependabot. Must be
> changed manually after a flip. See `docs/OPERATIONS.md`
> §"Post-public-flip checklist".

### Workflow permissions

| Setting | Expected | Why |
|---|---|---|
| Token permissions | ✅ "Read and write permissions" | Needed for goreleaser to push releases + auto-approve workflow |
| Allow GitHub Actions to create and approve pull requests | ✅ ON | Needed for the auto-approve-dependabot workflow |

---

## 4. Code security

`Settings → Code security`:

| Setting | Expected | Why |
|---|---|---|
| Private vulnerability reporting | ✅ ON | Channel for security disclosures |
| Dependency graph | ✅ ON | Required for Dependabot + dependency-review |
| Dependabot alerts | ✅ ON | Alert on vulnerable deps |
| Dependabot security updates | ✅ ON | Auto-PRs for security fixes |
| Dependabot version updates | ✅ ON (config in `.github/dependabot.yml`) | Weekly bumps |
| Grouped security updates | ✅ ON | Reduces PR noise |
| Code scanning (CodeQL) | ✅ ON | The `analyze (go)` check needs this |
| CodeQL setup | ✅ "Default" | Auto-config for Go |
| Secret scanning | ✅ ON | Detect committed secrets |
| Secret scanning push protection | ✅ ON | Block secret push at git-push time |

> ⚠️ Default after flipping PUBLIC is many of these OFF —
> Advanced Security features don't auto-enable on flip. Walk
> the checklist after every visibility change.

---

## 5. Pages

`Settings → Pages`:

| Setting | Expected |
|---|---|
| Source | None (or GitHub Actions if `docs/` is published) |

(No production GH Pages site as of v1.88.)

---

## 6. Secrets and variables → Actions

`Settings → Secrets and variables → Actions`:

| Secret | When set | Purpose |
|---|---|---|
| (none required for base CI) | — | All canonical workflows use `GITHUB_TOKEN` (auto-provisioned) |
| `COSIGN_*` | When publishing to Sigstore (release-time) | Optional; CI falls back to OIDC keyless |
| `GHCR_TOKEN` | When pushing OCI images | Optional; PAT with `packages:write` |

> NEVER commit secrets to the repo. The vault model (see
> `docs/SECURITY.md`) is the canonical place for production
> secrets.

---

## 7. Dependabot (separate sidebar entry)

`Settings → Code security` (covered above).

The Dependabot CONFIG lives in `.github/dependabot.yml`. The
SETTINGS toggles live in the GH UI. Both must agree.

---

## 8. Webhooks + integrations

`Settings → Webhooks` / `Settings → Integrations`:

| Item | Expected |
|---|---|
| Webhooks | None unless an external CI/SIEM is wired |
| GitHub Apps | None unless a future Slack/Jira integration |

---

## How to verify all this from CLI

Most can be checked via `gh api`:

```bash
# General
gh repo view RobinR00T/elSereno \
    --json visibility,defaultBranchRef,deleteBranchOnMerge,squashMergeAllowed,mergeCommitAllowed,rebaseMergeAllowed

# Branch protection
gh api repos/RobinR00T/elSereno/branches/main/protection 2>/dev/null \
    || echo "(no protection on main)"

# Actions permissions
gh api repos/RobinR00T/elSereno/actions/permissions

# Workflow permissions
gh api repos/RobinR00T/elSereno/actions/permissions/workflow

# Code scanning
gh api repos/RobinR00T/elSereno/code-scanning/default-setup \
    --jq '.state'    # expected: configured

# Vulnerability alerts
gh api repos/RobinR00T/elSereno/vulnerability-alerts \
    -i 2>&1 | head -1   # expected: HTTP/2.0 204
```

The settings UI is at:

```
https://github.com/RobinR00T/elSereno/settings
```

---

## Why this file exists

In May 2026 we flipped the repo PRIVATE→PUBLIC and discovered:

1. Code Scanning was OFF (had to enable).
2. Approval policy was at its restrictive default, blocking
   Dependabot.
3. `Commons-Clause` in `dependency-review-config.yml` was an
   invalid SPDX id (CI failure).
4. 7 Dependabot PRs piled up waiting for manual approval.

This file is the playbook so the next time settings need to be
re-verified (admin handoff, repo migration, after another
flip), there's a single checklist to walk.

See also: [`docs/OPERATIONS.md`](../docs/OPERATIONS.md) for
operational runbooks and `memory/elsereno_operational_playbook.md`
(Claude memory) for the per-gotcha catalogue.
