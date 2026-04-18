# Summary

<!-- 1–3 lines describing the change and its motivation. -->

## Phase

<!-- F0 / F1 / F2a / F2b / … -->

## Checklist

- [ ] `make ci` green locally (lint, build ×3, test-race, test-cover,
      test-fuzz smoke, sec with go-licenses, context-check).
- [ ] `.context/pitfalls.md` reviewed against this change.
- [ ] `.context/STATE.md` updated if a phase milestone moves.
- [ ] `.context/CHANGELOG.md` one-line entry added.
- [ ] If a new anti-pattern was discovered, added to `pitfalls.md` using
      `templates/pitfall.md`.
- [ ] If a non-obvious design decision was made, added an ADR via
      `templates/adr.md`.
- [ ] Conventional Commits; every commit is DCO-signed (`-s`).

## Notes

<!-- Anything the reviewer should know — trade-offs, follow-ups, open
     questions. -->
