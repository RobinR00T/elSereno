# ElSereno — operations runbooks

Runbooks operacionales para mantenimiento, releases, hygiene
del repo. Léelo cuando vayas a:

- Hacer un release (cycle close + tag + goreleaser).
- Resolver PRs de Dependabot bloqueadas.
- Flipear visibilidad del repo (PRIVATE ↔ PUBLIC).
- Diagnosticar CI fallando.
- Onboardear un admin nuevo / handoff.

> Documentos hermanos:
> - [`MANUAL.md`](MANUAL.md) — referencia CLI completa.
> - [`DEV-SETUP.md`](DEV-SETUP.md) — clonar repo + dev workflow.
> - [`SECURITY.md`](SECURITY.md) — modelo de seguridad.
> - [`.github/SETTINGS.md`](../.github/SETTINGS.md) — config esperada de GitHub.

---

## Índice

1. [Release de un nuevo cycle (v1.x)](#1-release-de-un-nuevo-cycle)
2. [Dependabot policy + workflow](#2-dependabot-policy)
3. [Post-public-flip checklist](#3-post-public-flip-checklist)
4. [Troubleshooting CI](#4-troubleshooting-ci)
5. [Re-auth de `gh` tras revocar PAT](#5-re-auth-gh)
6. [DR — backup + restore](#6-disaster-recovery)
7. [Admin handoff](#7-admin-handoff)
8. [Audit checklist (`scripts/audit.sh`)](#8-audit-checklist)

---

## 1. Release de un nuevo cycle

Resumen del flujo canónico para cerrar un cycle vN.M y
publicar release.

### Prerequisitos

- Working tree limpio.
- HEAD apuntando al feat-commit (no al docs-close commit aún).
- Lint + tests verdes (`make ci`).
- Vault del binario inicializado (para signing si aplica).
- `gh` autenticado como `RobinR00T`.

### Flujo

```bash
cd "/Users/danielsolisagea/AI projects/elsereno"

# 1. Asegúrate de estar al día:
git status -s     # vacío
git pull --rebase origin main

# 2. Cierra el cycle con su commit de docs (STATE/CHANGELOG/etc):
git commit -m "docs(vN.M): close cycle — <feature line>"

# 3. Crea el tag firmado:
git tag -s vN.M.0 -m "$(cat <<'EOF'
vN.M.0 — <one-line summary>

<full release notes body — copy from .context/snapshots/vN.M.0-*.md>
EOF
)"

# 4. Push:
git push origin main
git push origin vN.M.0

# 5. Release con goreleaser (LOCAL — NO confíes en CI hasta
#    que billing esté restored):
GITHUB_TOKEN=$(gh auth token) \
GITHUB_REPOSITORY=RobinR00T/elSereno \
    goreleaser release --clean --skip=sign,docker

#    --skip=sign  → cosign keyless expiry 300s, no práctico local
#    --skip=docker → Docker images requieren buildx + registry
#                    login; CI lo hace cuando workflows estén ON

# 6. Verifica:
gh release view vN.M.0 --json url,assets -q '"url: " + .url + "\nassets: " + (.assets|length|tostring)'

# 7. (Opcional) Aplica migraciones en DB de prod, si aplica:
export DATABASE_URL=...
elsereno db migrate up
```

### Si goreleaser falla

| Error | Solución |
|---|---|
| `missing GITHUB_TOKEN` | Falta `GITHUB_TOKEN=$(gh auth token)` |
| `template ... GITHUB_REPOSITORY` | Falta `GITHUB_REPOSITORY=RobinR00T/elSereno` |
| `docker images: invalid buildx driver` | Falta `--skip=docker` |
| `cosign: expired_token` | Falta `--skip=sign` |
| `scm releases: 422` con "Release already exists" | `gh release delete vN.M.0 --yes --cleanup-tag=false` y re-corre |

Detalle completo en
[`MANUAL.md §10 Troubleshooting`](MANUAL.md#10-troubleshooting).

---

## 2. Dependabot policy

ElSereno trata las PRs de Dependabot con esta política:

| Tipo de bump | Trato | Quién lo decide |
|---|---|---|
| `patch` (X.Y.Z → X.Y.Z+1) | Auto-merge si CI verde | El workflow `auto-approve-dependabot.yml` |
| `minor` (X.Y → X.Y+1) | Auto-merge si CI verde | El workflow `auto-approve-dependabot.yml` |
| `major` (X → X+1) | Label `needs-major-bump-review` + espera humano | Operador |
| Security advisory | Label `security` + prioridad alta | Operador |

### Configuración

- **`.github/dependabot.yml`** — schedule weekly Monday 06:00
  CET, grouped minor+patch, 10 PRs simultáneas máximo,
  separate ecosystems (gomod, github-actions, docker).

- **`.github/workflows/auto-approve-dependabot.yml`** — escucha
  `pull_request_target`, usa `dependabot/fetch-metadata@v2`
  para clasificar el bump, aplica auto-approve + auto-merge
  para minor+patch, label para major.

### Si Dependabot crea muchas PRs de golpe (post-flip o reset)

```bash
# Lista todas las abiertas:
gh pr list --state open --author 'app/dependabot' \
    --repo RobinR00T/elSereno

# Para cada una que no esté siendo auto-mergeada (CI roja,
# merge conflict, branch protection), revisar individualmente:
gh pr view <N> --repo RobinR00T/elSereno

# Patrones comunes:
#   - CI gated (post-PUBLIC flip): ver §3.
#   - merge conflict: `gh pr comment <N> --body "@dependabot rebase"`
#   - rebase imposible: `gh pr comment <N> --body "@dependabot recreate"`
#   - bump problemático: `gh pr comment <N> --body "@dependabot ignore this dependency"`
```

### Cuándo un major bump puede mergearse

- Lee el CHANGELOG upstream.
- Comprueba que las APIs usadas no cambiaron (en `actions/checkout v3→v4`, el ENV `GITHUB_TOKEN` perm changed, etc.).
- `make ci` debe pasar.
- Si toca infra (e.g. `actions/setup-go major`), prueba en branch nueva primero.

---

## 3. Post-public-flip checklist

Tras flipear el repo PRIVATE → PUBLIC (o al revés), GitHub NO
preserva todos los settings. Camina esta checklist.

### Estado por defecto tras un flip a PUBLIC (problemático)

| Setting | Default post-flip | Lo que queremos |
|---|---|---|
| Code scanning | OFF | ✅ ON (CodeQL Default) |
| Secret scanning | depende del plan | ✅ ON con push protection |
| Approval policy | "all external contributors" | "first-time GitHub users only" |
| Vulnerability alerts | depende | ✅ ON |

### Walk-through

```bash
# 1. Code Scanning
open "https://github.com/RobinR00T/elSereno/settings/security_analysis"
#    → Code scanning → "Set up" → "Default" → Save

# 2. Approval policy
open "https://github.com/RobinR00T/elSereno/settings/actions"
#    → "Approval for fork pull request workflows from contributors"
#    → "Require approval for first-time contributors who are new to GitHub"

# 3. Workflow permissions
#    En la misma página de Settings → Actions:
#    → "Read and write permissions" (no "Read repository contents only")
#    → ☑ "Allow GitHub Actions to create and approve pull requests"

# 4. Secret scanning
open "https://github.com/RobinR00T/elSereno/settings/security_analysis"
#    → Secret scanning + push protection → Enable

# 5. Trigger re-runs de las PRs Dependabot abiertas:
for n in $(gh pr list --state open --author 'app/dependabot' \
                --repo RobinR00T/elSereno --json number -q '.[].number'); do
  gh pr comment "$n" --repo RobinR00T/elSereno --body "@dependabot recreate"
done

# 6. Verifica via API:
gh api repos/RobinR00T/elSereno/code-scanning/default-setup --jq '.state'
# → "configured"

gh api repos/RobinR00T/elSereno/actions/permissions/workflow \
    --jq '.default_workflow_permissions'
# → "write"
```

**Tiempo estimado**: 5-10 min cuando ya sabes los pasos.

---

## 4. Troubleshooting CI

Tabla síntoma → causa más probable → fix. Para diagnóstico
estructurado, ve a [`MANUAL.md §10`](MANUAL.md#10-troubleshooting).

| Síntoma | Causa | Fix |
|---|---|---|
| `lint` falla con "Go language version (go1.23) lower than targeted (1.25)" | golangci-lint binario stale | Workflow ya pin `v2.11.4` desde commit `<TBD>`. Verifica + bump si necesitas Go nuevo. |
| `dependency review`: "Invalid license(s) in deny-licenses: Commons-Clause" | SPDX inválido en `.github/dependency-review-config.yml` | Borra el ID (no es SPDX real). Arreglado en `aeae4e3`. |
| `analyze (go)`: "Code scanning is not enabled" | Code Scanning OFF en Settings | Settings → Security → Code scanning → Enable Default |
| `sec`: gosec issues > 0 | Vulnerabilidades reales o markers nosec faltantes | `gosec ./...` local; añade `// #nosec G<NNN>` con rationale donde aplique |
| `secrets`: gitleaks fail | Falsos positivos o secret real committed | Revisa SARIF; añade exclusiones en `.gitleaks.toml` si es FP |
| Workflow runs reportan "no checks reported" | Approval policy bloquea | §3 |
| PR tiene "merge conflict" tras merges en main | Base desactualizada | `@dependabot rebase` |
| `gh pr merge --auto` "failed" | PR ya verde — `--auto` no aplica | Usa `gh pr merge --squash --delete-branch` (sin `--auto`) |
| Dependency graph UI muestra "Your .github/dependabot.yml contained invalid details" + "did not contain a minimum number of items 1" | `ignore: []` (o cualquier array vacío) en `dependabot.yml` viola el schema (minItems: 1) | Borrar el array vacío o ponerle al menos 1 entry. Documentar formato esperado via comentarios YAML, no via array vacío |

---

## 5. Re-auth `gh`

Cuando un PAT se revoca, `gh` keyring queda inválido. Re-auth:

```bash
gh auth login -h github.com
# Choose:
#   - GitHub.com (no Enterprise)
#   - HTTPS protocol
#   - Yes (authenticate Git with credentials)
#   - Login with a web browser
# Te dará un código one-shot que pegas en el browser.
```

Tras esto el token será `gho_*` (OAuth) en lugar de `github_pat_*`
(fine-grained PAT). OAuth es más cómodo (no caduca per-default,
no necesita renovar manualmente).

Si necesitas un PAT específico (e.g. para un CI runner que no
puede usar OAuth), genera uno desde:

```
https://github.com/settings/personal-access-tokens/new
```

Permisos mínimos para elsereno tooling:
- `Contents: read & write`
- `Pull requests: read & write` (si vas a mergear PRs)
- `Metadata: read` (default)

Para release flow con goreleaser, además:
- `Actions: read & write` (opcional)

---

## 6. Disaster recovery

Cubierto en detalle en [`MANUAL.md §20`](MANUAL.md#20-backup--disaster-recovery).
Resumen:

### Backup nightly

```bash
elsereno vault unlock --vault-passphrase-file /etc/elsereno/vault.pp
elsereno backup create --output /var/backups/elsereno-$(date +%Y%m%d).tar.gz.enc
find /var/backups -name 'elsereno-*.tar.gz.enc' -mtime +30 -delete
```

### Restore en máquina nueva

```bash
elsereno backup inspect --input /var/backups/elsereno-YYYYMMDD.tar.gz.enc
elsereno backup restore --input ... --to /tmp/restored
install -m 0600 /tmp/restored/vault.v1.bin /var/lib/elsereno/
install -m 0640 /tmp/restored/audit.jsonl /var/lib/elsereno/
systemctl start elsereno
elsereno audit verify-file   # exit-0 confirma chain intacto
```

### Test trimestral

Restora en sandbox cada Q. Si la passphrase no la recuerdas,
backup es papel mojado. Anótala en un password manager con
2FA.

---

## 7. Admin handoff

Si transfieres el repo a otra cuenta GitHub (org, otro user,
etc.), camina:

1. **Tag GPG key**: la nueva cuenta sigue siendo capaz de
   firmar nuevas tags. Importa la clave pública del mantenedor
   en su keyring + configura `git config user.signingkey`.
2. **`.github/SETTINGS.md`**: walk through con el nuevo admin
   — qué configuraciones esperar y cómo verificarlas.
3. **Webhooks externos**: si hay alguno (SIEM, ticketing),
   regenera el secret + actualiza en el sistema receiver.
4. **Dependabot secrets**: si la org viene con secrets
   alternativos, configura.
5. **Branch protection**: si la nueva org tiene policy global,
   review + ajustar a `.github/SETTINGS.md`.
6. **Public visibility**: si flippeas la visibility con el
   transfer, walk §3 de este doc.
7. **Memory de Claude**: si el nuevo admin trabaja con Claude
   también, comparte el playbook
   `memory/elsereno_operational_playbook.md` (no commiteable;
   es por-cuenta-Claude).

---

## 8. Audit checklist

`scripts/audit.sh` es un comando único proactivo que valida TODA
la clase de problemas que hemos cazado durante v1.74–v1.88
(YAML schema, dependabot empty arrays, broken markdown links,
Go toolchain pin, CVEs en stdlib, build/lint/test/gosec/govulncheck,
context-check, tag signatures, GitHub repo state).

### Cuándo correrlo

| Momento | Modo | Tiempo aprox. |
|---|---|---|
| Antes de cada commit "close de cycle" | `--full` | ~5 min |
| Durante desarrollo (sanity check rápido) | `--quick` | ~5 s |
| En cada push/PR | CI (`audit.yml`) automático | ~6–8 min |
| Auditoría semanal de stdlib CVEs | CI cron lunes 06:00 UTC | automático |
| Antes de abrir tarea nueva en sesión Claude | `--quick` | ~5 s |

### Cómo correrlo

```bash
# Sanity rápido (YAML + docs + git + toolchain):
scripts/audit.sh --quick

# Audit completo:
scripts/audit.sh --full

# Modo CI (output friendly para GitHub Actions; sin colores):
scripts/audit.sh --ci
```

### Qué chequea exactamente

13 categorías, todas idempotentes:

| # | Check | Por qué |
|---|-------|---------|
| 1 | Git state (clean + sync) | evita commit accidental con basura |
| 2 | YAML syntax | `.github/*.yml`, docker-compose, openapi, goreleaser |
| 3 | Dependabot schema | detecta `ignore: []` (gotcha real v1.88) |
| 4 | Docs links | detecta `026-secret-transport.md` (gotcha real v1.87) |
| 5 | Go toolchain pin | sin pin → stdlib CVE riesgo (gotcha v1.87) |
| 6 | Build (default + offensive + mini) | matrix completa |
| 7 | golangci-lint strict | |
| 8 | `go test -race -short` | regresión race + test |
| 9 | gosec | issues de seguridad |
| 10 | govulncheck | CVEs stdlib + deps |
| 11 | `make context-check` | STATE.md size + invariants |
| 12 | Last 3 tags GPG-signed | regresión de firma |
| 13 | GitHub repo state | Code Scanning configured, workflow perms write |

### Exit codes

- `0` — todo verde.
- `1` — al menos un check falló (logs preservados en `/tmp/.audit-*`).
- `2` — error de invocación (flag inválido, etc.).

### Si un check falla

1. Lee `/tmp/.audit-*.<PID>` para el log completo.
2. Cross-check contra `memory/elsereno_operational_playbook.md`
   §Gotchas — probablemente está catalogado.
3. Si no está: arréglalo + añade entry nueva al playbook + añade
   chequeo al script si no estaba cubierto.

### Cuándo extender el script

Cuando descubras una nueva clase de problema que podría repetirse,
añade el chequeo a `scripts/audit.sh` siguiendo el patrón de
las 13 secciones existentes:

```bash
# ====================================================================
hdr "N. Mi nuevo check"
# ====================================================================
if <condición>; then
    ok "descripción del éxito"
else
    fail "descripción del fallo"
fi
```

Y actualiza la tabla "Qué chequea exactamente" arriba.

---

## Cómo evolucionar este runbook

Cuando aparezca un nuevo escenario operacional repetido:

1. Añade sección numerada nueva al índice.
2. Documenta con: síntoma → diagnóstico → fix → cuándo aplica.
3. Cross-link al MANUAL §10 si es troubleshooting puntual.
4. Si descubres un gotcha que merece atención de Claude:
   actualiza también
   `memory/elsereno_operational_playbook.md`.

Este doc es markdown vivo. Asume que será revisado al onboard
de cada admin nuevo.
