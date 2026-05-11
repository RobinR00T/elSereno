# ElSereno — integraciones con SIEM y observabilidad

Recetas concretas para mandar los findings de ElSereno a los
sistemas externos típicos. Cada sección tiene **el pipeline
mínimo viable** + un par de notas de operación.

> El binario ElSereno **no se integra directamente** con
> ningún SIEM/observability stack: emite NDJSON v1 estable
> y deja la decisión de transporte al operador. Es
> intencional — minimiza acoplamiento, mantiene el binario
> stateless, evita vendor lock-in.

---

## Índice

1. [Patrón general: file → forwarder](#patrón-general)
2. [Splunk](#splunk)
3. [Elastic Stack (Elasticsearch / Kibana)](#elastic-stack)
4. [Loki + Grafana](#loki--grafana)
5. [Prometheus (metrics-style)](#prometheus-metrics-style)
6. [Syslog / Graylog](#syslog--graylog)
7. [OpenTelemetry (traces + metrics)](#opentelemetry)
8. [Webhook genérico](#webhook-genérico)
9. [STIX 2.1 (threat intel)](#stix-21)
10. [MISP](#misp)
11. [Slack / chat](#slack--chat)
12. [Anti-patterns conocidos](#anti-patterns)

---

## Patrón general

```
┌──────────────┐    NDJSON v1    ┌──────────────┐  push  ┌──────────┐
│ elsereno scan│ ───────────────►│ forwarder    │ ──────►│  SIEM    │
└──────────────┘   (stdout / file)│ (filebeat,   │        └──────────┘
                                  │ logstash,    │
                                  │ vector,      │
                                  │ promtail, …)│
                                  └──────────────┘
```

Tres principios:

1. **Nunca encadenes elsereno → curl al SIEM directamente**.
   Un forward que retrasa o falla bloquea el scan. Usa
   siempre un forwarder que tail-ea archivo o lee de
   stdin con buffer.
2. **Rota el output**. Un `findings.ndjson` de 10 GB es
   un footgun para `jq`. Usa `--output-file` con
   timestamp (`findings-$(date +%Y%m%dT%H%M).ndjson`) +
   un `logrotate`.
3. **Mapea el campo `severity`** del finding al
   severity-system de tu SIEM (`info` / `low` / `medium` /
   `high` / `critical`). El score numérico (`score`) es
   útil para sorting, pero los SIEM raramente lo
   consumen directamente.

---

## Splunk

### Vía Universal Forwarder (recomendado)

`/opt/splunkforwarder/etc/system/local/inputs.conf`:

```ini
[monitor:///var/log/elsereno/findings-*.ndjson]
sourcetype = elsereno_finding_v1
index      = ics_exposure
disabled   = false
```

`/opt/splunkforwarder/etc/system/local/props.conf`:

```ini
[elsereno_finding_v1]
TIME_PREFIX     = "ts":"
TIME_FORMAT     = %Y-%m-%dT%H:%M:%S.%6NZ
SHOULD_LINEMERGE= false
KV_MODE         = json
TRUNCATE        = 0
```

Tras restart del forwarder, busca en Splunk:

```spl
index=ics_exposure sourcetype=elsereno_finding_v1
| stats count by plugin, severity
```

### Splunk HEC (HTTP Event Collector)

Si no puedes desplegar forwarder, usa HEC + un sidecar:

```bash
#!/usr/bin/env bash
# elsereno → HEC, batched 100 events
HEC_URL="https://splunk.example.com:8088/services/collector"
HEC_TOKEN="00000000-0000-0000-0000-000000000000"

elsereno scan ... \
  | jq -c '{event: ., sourcetype: "elsereno_finding_v1", index: "ics_exposure"}' \
  | split -l 100 - /tmp/batch-

for f in /tmp/batch-*; do
  jq -s '.' "$f" > /tmp/payload.json
  curl -s "$HEC_URL" -H "Authorization: Splunk $HEC_TOKEN" \
       -H "Content-Type: application/json" \
       --data @/tmp/payload.json
  rm /tmp/payload.json "$f"
done
```

> El token HEC va en header (no argv) — PITF-032 satisfecho.

---

## Elastic Stack

### Vía Filebeat

`filebeat.yml`:

```yaml
filebeat.inputs:
  - type: filestream
    id: elsereno
    paths:
      - /var/log/elsereno/findings-*.ndjson
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
    fields:
      sourcetype: elsereno_finding_v1
    fields_under_root: true

processors:
  - drop_fields:
      fields: ["agent", "ecs", "host", "log"]
      ignore_missing: true
  - timestamp:
      field: ts
      layouts:
        - "2006-01-02T15:04:05.999999Z"
      test:
        - "2026-05-11T12:34:56.123456Z"

output.elasticsearch:
  hosts: ["https://es.example.com:9200"]
  api_key: "${ELASTIC_API_KEY}"
  index:   "elsereno-findings-%{+yyyy.MM.dd}"
```

### Index template

```bash
curl -X PUT "https://es.example.com:9200/_index_template/elsereno-findings" \
     -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
     -H "Content-Type: application/json" \
     -d '{
       "index_patterns": ["elsereno-findings-*"],
       "template": {
         "settings": { "number_of_shards": 1, "number_of_replicas": 1 },
         "mappings": {
           "properties": {
             "ts":       { "type": "date" },
             "score":    { "type": "float" },
             "severity": { "type": "keyword" },
             "plugin":   { "type": "keyword" },
             "target": {
               "properties": {
                 "host": { "type": "ip" },
                 "port": { "type": "integer" }
               }
             },
             "run_id":   { "type": "keyword" }
           }
         }
       }
     }'
```

### Kibana dashboards

Visualización mínima útil:

- **Findings por hora** (line chart, group by `severity`).
- **Top plugins** (data table, terms agg sobre `plugin`).
- **Heatmap host × port** (terms agg `target.host` × `target.port`).
- **Score histogram** (histogram agg sobre `score`).

---

## Loki + Grafana

### Vía Promtail

`promtail.yaml`:

```yaml
scrape_configs:
  - job_name: elsereno
    static_configs:
      - targets: [localhost]
        labels:
          job: elsereno
          __path__: /var/log/elsereno/findings-*.ndjson
    pipeline_stages:
      - json:
          expressions:
            ts:       ts
            plugin:   plugin
            severity: severity
            host:     target.host
            port:     target.port
            score:    score
      - timestamp:
          source: ts
          format: RFC3339Nano
      - labels:
          plugin:
          severity:
```

Grafana queries (LogQL):

```logql
# Conteo por severity:
sum by (severity) (count_over_time({job="elsereno"} | json | __error__="" [5m]))

# Findings critical/high recientes:
{job="elsereno"} | json | severity =~ "critical|high"

# Score promedio por plugin:
avg by (plugin) (
  count_over_time({job="elsereno"} | json | unwrap score [10m])
)
```

---

## Prometheus (metrics-style)

ElSereno **no expone `/metrics`** Prometheus directamente
(scope intencional — es un scanner, no un service). Para
métricas derivadas, dos opciones:

### Opción A — `mtail` parseando NDJSON

```bash
# /etc/mtail/elsereno.mtail
counter elsereno_findings_total by plugin, severity
counter elsereno_targets_scanned_total
histogram elsereno_score_dist by plugin

/"plugin":"(?P<plugin>[^"]+)".*"severity":"(?P<severity>[^"]+)"/ {
    elsereno_findings_total[$plugin][$severity]++
}
/"target":\{"host":/ { elsereno_targets_scanned_total++ }
/"score":(?P<score>[0-9.]+),"plugin":"(?P<plugin>[^"]+)"/ {
    elsereno_score_dist[$plugin] = $score
}
```

```bash
mtail --logs '/var/log/elsereno/findings-*.ndjson' --progs /etc/mtail/
# Prometheus scrapes :3903/metrics
```

### Opción B — exporter custom (Python sketch)

```python
#!/usr/bin/env python3
# exporter.py - tail NDJSON + expose Prometheus metrics.
import json, time
from prometheus_client import Counter, Histogram, start_http_server

findings = Counter('elsereno_findings_total', 'findings', ['plugin', 'severity'])
score_h  = Histogram('elsereno_score', 'score dist', ['plugin'])

start_http_server(9101)
with open('/var/log/elsereno/findings-current.ndjson') as f:
    while True:
        line = f.readline()
        if not line: time.sleep(1); continue
        try:
            r = json.loads(line)
            findings.labels(r['plugin'], r['severity']).inc()
            score_h.labels(r['plugin']).observe(r['score'])
        except Exception: pass
```

### Alertas útiles (PromQL)

```yaml
# critical findings in last 1h
- alert: NewCriticalIcsFinding
  expr: increase(elsereno_findings_total{severity="critical"}[1h]) > 0
  for: 1m
  annotations:
    summary: "{{ $value }} critical ICS findings in 1h"

# scanner stopped emitting (no targets seen in 30m)
- alert: ElserenoQuiet
  expr: rate(elsereno_targets_scanned_total[30m]) == 0
  for: 30m
```

---

## Syslog / Graylog

### rsyslog

```bash
# /etc/rsyslog.d/elsereno.conf
$InputFileName /var/log/elsereno/findings-current.ndjson
$InputFileTag elsereno:
$InputFileStateFile elsereno-state
$InputFileSeverity info
$InputFileFacility local6
$InputRunFileMonitor

local6.*    @@graylog.example.com:514;RSYSLOG_SyslogProtocol23Format
```

### Graylog extractor (GROK)

Mejor: deja que Graylog parsee directamente con un GROK
sobre el JSON entero o (mejor) con la pipeline rule de
JSON → fields.

---

## OpenTelemetry

El binario **sí emite telemetry OTel** cuando `OTEL_EXPORTER_OTLP_ENDPOINT`
está configurado:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otel-collector.example.com:4317"
export OTEL_SERVICE_NAME="elsereno"
elsereno serve ...
```

Cubre traces del scan-orch (queue → run → emit) + métricas
de worker pool / queue depth. Spans:

- `scan.submit` (cuando llega un job).
- `scan.run` (durante worker execution).
- `plugin.probe` (un span por target).

Conecta a Tempo / Jaeger / Datadog APM via OTel
collector estándar.

---

## Webhook genérico

Para sistemas custom (ITSM, ticketing, etc.):

```bash
#!/usr/bin/env bash
# Webhook firmado HMAC-SHA256.
SECRET="$(cat /etc/elsereno/webhook.secret)"   # 0600
URL="https://itsm.example.com/api/incidents"

elsereno scan --input list:fleet.txt \
  | jq -c 'select(.severity == "critical" or .severity == "high")' \
  | while read -r line; do
      sig=$(echo -n "$line" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')
      curl -X POST "$URL" \
           -H "X-Signature-SHA256: $sig" \
           -H "Content-Type: application/json" \
           -d "$line"
    done
```

> El `SECRET` viene de archivo 0600 (PITF-032). En el
> request va en header como hash de HMAC, no en query
> string (no leak en logs nginx).

---

## STIX 2.1

`elsereno scan --output-format stix` (planeado/en construcción
por versión — comprueba `elsereno scan --help` para tu build).
Emite bundles STIX 2.1 con:

- `indicator` para cada finding con score ≥ medium.
- `observed-data` con timestamp + target.
- `relationship` linking findings de un mismo run.

Feed directo a MISP / OpenCTI / ThreatBus:

```bash
elsereno scan --input list:fleet.txt --output-format stix \
  > /tmp/findings.stix.json
curl -X POST https://misp.example.com/events/restSearch \
    -H "Authorization: $MISP_API_KEY" \
    -H "Accept: application/json" \
    -d @/tmp/findings.stix.json
```

---

## MISP

Pipeline básico (sin STIX intermediate — directly to MISP
event):

```bash
#!/usr/bin/env bash
KEY=$(cat /etc/elsereno/misp.key)
EVENT_ID=12345

elsereno scan --input list:fleet.txt \
  | jq -c 'select(.severity == "critical")' \
  | while read -r f; do
      target=$(echo "$f" | jq -r '.target.host')
      curl -X POST "https://misp.example.com/attributes/add/$EVENT_ID" \
           -H "Authorization: $KEY" -H "Accept: application/json" \
           -d "{\"type\":\"ip-dst\",\"value\":\"$target\",\"category\":\"Network activity\"}"
    done
```

Estructura un MISP event por scan run (`run_id` del finding
mapea a `event_uuid`).

---

## Slack / chat

Notificaciones de findings críticos:

```bash
#!/usr/bin/env bash
WEBHOOK="$(cat /etc/elsereno/slack-webhook.url)"

elsereno scan --input list:fleet.txt \
  | jq -c 'select(.severity == "critical")' \
  | while read -r f; do
      host=$(echo "$f" | jq -r '.target.host')
      plugin=$(echo "$f" | jq -r '.plugin')
      curl -X POST "$WEBHOOK" -H 'Content-type: application/json' \
           -d "{\"text\":\":rotating_light: ICS critical: $plugin on $host\"}"
    done
```

> Slack webhook URL es un secreto — archivo 0600.

Recommendation: **batch + threshold**, no notification por
cada finding. Tu canal de Slack se va a llenar.

---

## Anti-patterns

| Patrón | Por qué no | Alternativa |
|---|---|---|
| `elsereno scan ... \| curl ... HEC` directamente | Si curl es lento/falla, scan bloquea | File + forwarder |
| `--output-format json` (un objeto gigante) | OOM en runs grandes | NDJSON línea-por-línea |
| Webhook a cada finding | Throttle del SIEM, ruido en Slack | Batch + threshold filter |
| API key en argv del cron job | Visible en `ps -ef` | Archivo 0600 + leer dentro del script |
| Forwarder leyendo desde stdout + script | Buffer truncate, race con rotación | Tail file con state-tracking |
| Re-emitir findings con un `cat` cada hora | Duplicados infinitos en SIEM | Forwarder con state file (cursor) |

---

## Mantenimiento del pipeline

Checklist trimestral:

- [ ] Verifica que el forwarder está al día con los archivos
      actuales (no se ha desincronizado tras una rotación).
- [ ] `elsereno audit verify-file` exit-0.
- [ ] Confirma que las API keys no expiran (Shodan/Censys/etc).
- [ ] Revisa el espacio en disco de `findings-*.ndjson`;
      ajusta logrotate si crece.
- [ ] Re-test del restore desde backup (ver
      [`MANUAL.md §20`](MANUAL.md#20-backup--disaster-recovery)).

---

## Más

- [`MANUAL.md`](MANUAL.md) §14 — schema completo del finding.
- [`MANUAL.md`](MANUAL.md) §15 — HTTP API reference.
- [`SECURITY.md`](SECURITY.md) — modelo de seguridad para
  el threat-modeller de tu SOC.
