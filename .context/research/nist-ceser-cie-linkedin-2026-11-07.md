---
status: implemented 2026-11-07
date: 2026-11-07
source: LinkedIn, post de DOE CESER compartido por NIST (activity 7524567795628445696, 06-11-2026 20:26 UTC), enlace corto lnkd.in/p/ecnNvQda
---

# Post de DOE CESER sobre la SP 800-82r4 IPD: qué aplica a ElSereno

## Conclusión

El post no trae una guía nueva: remite a la **SP 800-82 Rev. 4 Initial
Public Draft** (21-9-2026, comentarios hasta el 30-11-2026), que ElSereno
ya mapeaba (Tablas 13, 15 y 16 del Apéndice C.2.2). Lo nuevo para el repo
son dos referencias que el borrador y el post ponen en el centro y que
`internal/standards` no tenía:

1. **NIST CSF 2.0**: la IPD está "reestructurada en torno a" CSF 2.0
   (página de anuncio en csrc.nist.gov). Hecho: catálogo `csf2`.
2. **Cyber-Informed Engineering (DOE/INL)**: lo que el post promueve.
   Hecho: catálogo `cie`.
3. **Zero trust**: la IPD lo aplica a OT. No se construye catálogo aparte
   (no hay un conjunto de IDs que un escáner pueda evidenciar sin
   inventarse un mapeo); su parte observable por red queda en PR.AA-03 y
   PR.IR-01.

## Método y límites

- Post leído por WebFetch (resumen, no texto literal). Fecha sacada del
  ID de la actividad (UTC). Los dos enlaces del post se resolvieron:
  uno lleva a un artículo de industrialcyber.co (403, no leído) y otro a
  `energy.gov/ceser/cyber-informed-engineering`.
- **Lo que dice el post y no la fuente primaria:** que la guía de NIST
  "anima" a métodos de ingeniería como CIE. La página de NIST de la IPD
  no nombra CIE ni "consequence-driven"; consta en `doe-cie.md` así.
- CSF 2.0: IDs y textos copiados del PDF CSWP 29 (nvlpubs.nist.gov).
- CIE: los 12 principios copiados del *CIE Implementation Guide*
  INL/RPT-23-74072 v1.0, 7-8-2023 (OSTI 1995796), tabla de principios y
  preguntas clave.
- El mapeo protocolo → subcategoría/principio es lectura de ElSereno, ni
  NIST ni DOE/INL lo han revisado.

## Qué se hizo

| Pieza | Dónde |
|---|---|
| Catálogo CSF 2.0 (PR.AA-03, PR.AA-05, PR.DS-02, PR.PS-01, PR.IR-01) | `internal/standards/csf2.go` |
| Catálogo CIE (principios 1, 2, 3, 4, 5, 7) | `internal/standards/cie.go` |
| Claves `csf2` y `cie` en `standards --standard` | `sp80082r4.go`, `cmd_standards.go` |
| Tests que fijan IDs/textos contra las fuentes | `TestCSF2Subcategories`, `TestCIEPrinciples` |
| Docs | `docs/standards/nist-csf-2.0.md`, `docs/standards/doe-cie.md`, nota en `nist-sp800-82r4.md` |
| Ejemplos con salida real | EXAMPLES §9 y bloque TriStation, `docs/protocols/tristation.md`, MANUAL §7.21, README, cheatsheet |

## Lo que no se hizo, y por qué

- Principios CIE 6, 8-12: procesos, personas y registros de diseño, no
  observables por red. El 8 (Digital Asset Awareness) recibe la salida de
  `discover`, pero un equipo encontrado no prueba el fallo sin el
  inventario del cliente.
- Un comentario del post pregunta qué pasos de CIE sirven en plantas
  heredadas que no se pueden rediseñar: respondido como sección "Legacy
  plants" en `doe-cie.md` (cerrar el camino, quitar servicios, llave del
  SIS en RUN), sin funcionalidad nueva.
- Las salidas CEF `cs3` y syslog `standard` crecen (hasta 13 referencias
  en TriStation). Sin truncado hoy; si un SIEM corta el campo, valorar
  un modo `--standard` por salida.
