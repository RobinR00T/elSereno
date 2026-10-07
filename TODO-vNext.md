# ElSereno, Forward-looking TODO (vNext)

> **⚠️ DESFASADO (última refresh real 2026-05-03; aviso 2026-08-31).**
> Casi todo el "forward" de este fichero ya se entregó en v2.x (OIDC +
> roles, wardialing, record/replay, TUI, Windows, PROFINET DCP, y la
> mayoría de protocolos e inputs). **Fuente de verdad: `.context/STATE.md`.**
> **Entregado 2026-08/09:** write-gates ofensivos finsudp / slmp /
> gesrtp / codesys / redlion (cada uno con demo de simulador); fingerprint
> profundo OPC UA HTTPS por GetEndpoints (el plugin `opcuahttps` enumera
> endpoints + postura de seguridad); input BinaryEdge; el verbo
> `fingerprint probe`.
> **Entregado 2026-09/10 (fuente: STATE.md):** probes de exposición S7 y
> OPC UA (opt-in, flag `OptIn` en `PluginMetadata`); GOOSE/SV passive
> monitor (`goose decode` / `goose monitor`); el camino de ESCRITURA de
> OPC UA HTTPS (write-gate `write opcuahttps` + `proxy --plugin
> opcuahttps`); trazabilidad SP 800-82 r4 en todas las salidas menos CSV;
> CVE enrichment por familia (S7, ENIP, PC WORX, FINS) en `internal/cve`;
> limpieza de em-dash en todo el repo.
> **Sigue abierto de verdad:** solo SLMP. IEC104, MMS y GE-SRTP están
> validados contra captura o fuente real (`iec104/wire/realcap_test.go` vs ITI
> IEC104_SQ.pcapng; `mms/wire/realcap_test.go` vs w3h/icsmaster
> iec61850_read.pcap; `gesrtp/wire/realcap_test.go` vs la firma Shodan + la
> implementación GE_SRTP de Collin Matthews). El "byte 0 = 0x01" de GE-SRTP NO
> era una discrepancia a esperar: era un BUG del modelo (el probe enviaba 0x02
> y esperaba 0x03, el mensaje de operación, en vez del handshake de init de 56
> ceros que responde 0x01). Corregido el 3-10, PITF-067. SLMP: modelo
> verificado contra la spec oficial de Mitsubishi (SLMP Reference Manual
> SH080956ENG, command 0x0101 subcommand 0x0000) y cross-checked contra
> pymcprotocol (`read_cputype()` usa 0x0101); NO es un bug, solo le falta una
> captura byte-a-byte (sin fuente pública al 3-10-2026, no está en
> automayt/ICS-pcap). No se fabrica fixture (PITF-064).

## Abierto (7-10-2026, auditoría de código): decisiones pendientes

- **7 paquetes de write-gate huérfanos.** `offensive/write/{atg,dlms,fox,
  hartip,iec104,knxip,mbustcp}` contienen código de proxy gated, pero ningún
  comando los importa: `proxy listen` solo despacha 18 protocolos. O se
  conectan (con su allowlist, tests y demo, como los otros 18) o se borran.
  Hasta entonces la doc los cuenta como RO.
- **Puntuación de Modbus.** Sus factores son constantes (capability 60 haya o
  no Modbus detrás), así que un PLC real, un eco o cualquier servicio en 502
  dan la misma severidad. Opción: baseline 30 y subir con respuesta FC1 o
  excepción válidas, como el resto de plugins. Cambiaría la severidad de todos
  los findings de Modbus sin respuesta Modbus. Ver PITF-071.
- **Los scans del dashboard no guardan findings.** `defaultScanRunner`
  (`cmd/elsereno/scan_runner.go`, `drainPluginRun`) cuenta los findings y los
  descarta; `internal/bus` es solo un `doc.go` que describe un
  "findings-persistence" que no existe, y nada escribe la tabla `findings` que
  lee `/api/v1/findings`. Un scan lanzado desde el dashboard da estadísticas,
  no resultados. Es diseño (esquema, run_id, target_id), no un arreglo de una
  noche. Encontrado el 7-10 al arreglar la CLI `scan` (PITF-076).
- **Writers `syslog` y `cef` huérfanos.** `internal/outputs/{syslog,cef}`
  existen con tests pero nada los importa; la chuleta y la página man
  anunciaban `--output-format syslog|cef|html` y `--syslog`/`--webhook-url`,
  que no existen (corregido en la doc el 7-10). Conectar o borrar.
- **TwinCAT: probable falso negativo en TwinCAT 3 `[inferencia]`.** En una
  captura real (TwinCAT XAE contra un CX, `twincat.pcapng` del barrido del
  7-10), el router contesta con un RST de TCP a la primera petición ADS de un
  NetID sin ruta, y solo responde después de que el cliente se registre por
  UDP/48899. Nuestro probe TCP usa NetID origen y destino 0.0.0.0.0.0, así
  que un router que exija ruta lo cortará igual. Propuesta: un probe de
  descubrimiento UDP/48899 (`03 66 14 71 …`, 24 bytes), que no necesita ruta
  y devuelve NetID, nombre de host y versión de TwinCAT; petición y respuesta
  reales están en esa misma captura. Sin probar contra un equipo propio.

## [RESUELTO 4-10-2026] el magic de CoDeSys estaba mal

Resuelto: el magic de reconocimiento es el real 0xE8170100 (validado contra la
captura cds3.pcapng y el PoC de Tenable), y el probe activo channel-open se
envía solo desde el plugin opt-in `codesys-active` (PITF-068). El 7-10 se
añadió el rechazo del eco (PITF-071). Texto original del hallazgo, abajo.

`codesys` (TCP/1217) usa `BlockDriverMagic = 0xCDCDCDCD`, que no respalda ninguna
fuente y es el patrón de memoria no inicializada de MSVC debug. Dos fuentes
independientes (la PoC del gateway V3 de Tenable y el paper de Kaspersky ICS-CERT
sobre el CODESYS Runtime) fijan el magic real del block driver de CODESYS en
0xE8170100 (little-endian) con header de 8 bytes (magic[4] + size[4]). NO
corregido a propósito: falta el frame de sonda mínimo que provoque respuesta del
gateway 1217 (la PoC opera en 11743 con PDUs multicapa para actuar, no un hello
de fingerprint), y cambiar el envío a otra conjetura repetiría el error. Ver
PITF-068; marcado con WARNING en `codesys/wire/wire.go`. Para cerrarlo hace falta
una captura del 1217 o construir un PDU de sonda válido y confirmar la respuesta.

### Cobertura de la auditoría de probes propietarios (3-10-2026)

Tras el fix de GE-SRTP se auditó cada fingerprint propietario (el que envía una
sonda reverse-engineered) buscando el patrón PITF-067/068:

- **GE-SRTP**: BUG, corregido (PITF-067). Enviaba el mensaje de operación en vez
  del handshake de init.
- **CoDeSys**: BUG, documentado y aplazado (PITF-068). Magic 0xCDCDCDCD sin
  fuente, patrón de memoria no inicializada; el real es 0xE8170100. Falta el
  frame de sonda que provoque respuesta del 1217.
- **SLMP**: correcto. Spec oficial (SH080956ENG) + pymcprotocol; stateless, sin
  handshake oculto.
- **Fox (Niagara)**: ~~correcto~~ **BUG, corregido el 7-10 (PITF-078).** Esta
  línea decía que no envía sonda y lee el banner que el servidor manda al
  conectar "igual que nmap fox-info"; es falso: nmap fox-info ENVÍA un hello y
  en la captura real habla primero el cliente. El probe no confirmaba ninguna
  estación real.
- **Red Lion**: ~~correcto~~ **BUG, corregido el 7-10 (PITF-079).** El "poke de
  3 ceros" y el banner al conectar no tenían fuente; cr3-fingerprint.nse lee
  los registros de fabricante y modelo (`00 04 01 2B 1B 00`, `00 04 01 2A 1A 00`).
- **ATG (Veeder-Root)**: correcto. Envía el comando documentado I20100 (igual que
  nmap atg-info).
- **ProConOS (20547)**: BUG, corregido (PITF-069). Enviaba `01 06 00 10 PROCONOS` y
  esperaba ese prefijo echo; el real es la query `cc01000b4002000047ee` con
  respuesta signature 0xcc (Redpoint NSE + nerva, byte a byte).
- **TwinCAT ADS (48898)**: formato correcto (AMS/TCP 6B + AMS header 32B,
  commandId@22, stateFlags@24, dataLength@26, ReadDeviceInfo según la spec
  Beckhoff AMS/ADS). **Pero (7-10)**: en una captura real el router devuelve RST
  a una petición ADS de un NetID sin ruta, y el probe usa NetID 0.0.0.0.0.0;
  probable falso negativo en TwinCAT 3 `[inferencia]`. Ver la decisión abierta
  arriba (descubrimiento UDP/48899).
- **IAX2 (Asterisk)**: correcto. Full-frame de 12B y el enum de subclases
  (NEW=1 / PING=2 / PONG=3 / ... / REGREL=17) coinciden exacto con RFC 5456;
  FrameType IAX=0x06. Protocolo con RFC, no reverse-engineering.
- **XOT (X.25 over TCP)**: correcto. Header XOT de 4B + paquete X.25 segun
  RFC 1613. Protocolo con RFC.
- **CWMP (TR-069) y AT-modem**: HTTP y texto respectivamente (no sonda binaria
  propietaria); fuera del patron PITF-067, riesgo bajo, no auditados a fondo.

**Auditoria de probes propietarios/binarios: COMPLETA (3-10-2026).** 2 bugs
corregidos (GE-SRTP PITF-067, ProConOS PITF-069), 1 documentado y aplazado
(CoDeSys PITF-068), el resto verificado correcto contra spec o implementacion de
referencia. Queda pendiente solo la captura byte-a-byte de SLMP (sin fuente) y el
frame de sonda de CoDeSys (necesita captura del 1217).

**CVE enrichment por FC43 de Modbus (Schneider Modicon): aplazado (3-10-2026).**
FC43 Read Device ID es raramente soportado por PLCs (la mayoria devuelve
excepcion 01) y el formato de los strings vendor/product de Modicon no esta
verificado contra captura real (la captura FC43 validada era un dispositivo Zeek
de test, no Schneider), asi que keyear CVEs ahi seria adivinar (PITF-064). De
paso se corrigio el comentario base de `modbus.go`, que atribuia a Schneider dos
CVEs equivocadas: CVE-2017-9853 es de SMA Solar (inversor), y CVE-2015-1015 no
existe para Modicon. Quedan las dos verificadas (CVE-2021-22779 ModiPwn 9.8,
CVE-2018-7240 Quantum 8.8).

Los parsers de protocolos estándar y bien documentados (Modbus, S7, OPC UA, ENIP,
BACnet, DNP3, HART-IP, FINS, MMS, IEC104, MQTT, SIP, DLMS) ya se validaron contra
captura real en la campaña y quedan fuera de esta auditoría de "sonda propietaria".

## NIST SP 800-82 Rev. 4 (30-9-2026): detecciones que pide el draft

Del draft NIST SP 800-82 r4 (Initial Public Draft, sept-2026), mapeado en
`docs/standards/nist-sp800-82r4.md`. elSereno ya cubre la vulnerabilidad de
red #1 ("OT protocols have no authentication", Table 16) con los probes de
exposición S7/OPC UA/Modbus. Detecciones que el draft pide y elSereno puede
añadir:

- **[HECHO 30-9] Finding de protocolo en claro** (Table 16: "protocols used
  in plaintext: telnet, FTP, HTTP, NFS"): marcar servicios OT en texto claro.
- **[HECHO 30-9] Chequeo de credenciales por defecto** (Table 13: "vendor
  default passwords are used"): `creds-check http`, tras el tag `offensive`,
  exige `--confirm-authorized`, verifica solo defaults PUBLICADOS por vendor
  (no fuerza bruta), read-only (GET con baseline). `offensive/creds/`.
- **Trazabilidad de estándar en findings:** etiquetar cada finding de
  exposición con la vulnerabilidad SP 800-82 r4 que evidencia, para que una
  ejecución sea auditable contra el estándar.

Nota de captura (actualizada 2-10): **Modbus FC43/14 DESBLOQUEADO y
corregido.** Captura real `modbus_example.pcap` (CISA cisagov/icsnpp-modbus,
pkt 94) dio una respuesta FC43/14 completa, y validarla contra `DeviceIDObjects`
destapó un bug (cabecera de 6 bytes en vez de 7, se saltaba el "Read Device ID
code"): devolvía 0 objetos para todo dispositivo real. Arreglado + test con los
bytes reales (PITF-064). **ENIP ListIdentity 0x63 DESBLOQUEADO (3-10):** la
captura `enip_cip_example.pcap` (CISA cisagov/icsnpp-enip) sí tiene una reply
0x63 real (módulo Allen-Bradley 1756-ENBT/A); `ParseListIdentity` la parsea
correcta (sin bug), validado byte a byte. **Omron FINS (3-10): 2º bug del
patrón** (PITF-065): `ParseControllerDataRead` leía el área reservada "For
System Use" como un campo `SystemVersion`; eliminado, validado contra un CP1L
real. La campaña cubre ya Modbus (FC43 + framing), OPC UA (Browse/Read), ENIP
(ListIdentity), BACnet (BVLC/I-Am/WriteProperty), DNP3 (link header) y FINS
(controller data): **2 bugs, ambos del patrón fixture-fabricado** (FC43 + FINS).
IEC104, MMS y GE-SRTP cerrados (ver el header; GE-SRTP era un bug del modelo,
no una discrepancia de captura, PITF-067). SLMP: modelo verificado contra la
spec oficial (SH080956ENG) y pymcprotocol, correcto, solo le falta una captura
byte-a-byte (sin fuente pública al 3-10-2026). La campaña de captura queda
cerrada salvo esa captura de SLMP.

## [RESUELTO 2-10-2026] Plugins opt-in vs "Plugins vacío = todo"

**Resuelto (opción 1):** se añadió `OptIn bool` a `core.PluginMetadata`;
`s7-exposure` y `opcua-exposure` marcan `OptIn: true`, y
`resolvePlugins(nil)` (la rama "run everything") salta los `OptIn`. Nombrar
un plugin explícitamente lo corre igual. Guardrail en
`TestResolvePlugins_OptInExcludedButNamed` + aserción `OptIn` en los tests de
metadata de ambos plugins. El texto de abajo es el análisis original.

---

Los plugins de exposición `s7-exposure` y `opcua-exposure` usan `DefaultPort 0`
para quedar fuera del barrido por defecto. Se cumple en el CLI (`scan` solo
corre el probe de `banner`; `discover` y `plugins ports` saltan
`DefaultPort==0`), pero NO en la ruta de orquestación de `elsereno serve`:

- `cmd/elsereno/scan_runner.go`: `resolvePlugins(nil)` devuelve todos los
  registrados ("Empty Plugins slice -> run every registered plugin").
- `filterByPort(DefaultPort 0)` devuelve TODOS los targets (semántica
  "probe-anywhere" pensada para `banner`).
- `internal/web/handlers/scans.go`: el handler de submit valida `inputs` pero
  no `plugins`; si el cliente omite `plugins`, el job queda con la lista vacía.

Efecto: un job de scan enviado al API web sin `plugins` corre `s7-exposure` y
`opcua-exposure` contra cada target (sesiones anónimas OPC UA + caminata de
escribibles, lecturas SZL S7). Es read-only y acotado, pero más intrusivo que
un fingerprint y contradice la garantía opt-in de los docs. Preexistente con
`s7-exposure`; `opcua-exposure` lo duplica. `DefaultPort 0` está sobrecargado:
"probe-anywhere" (banner, SÍ en el barrido) y "opt-in, no auto-ejecutar" (los
`-exposure`, NO).

Opciones (tocan comportamiento por defecto / contrato de plugins, por eso no se
ha tocado sin tu OK):

1. Flag explícito `OptIn bool` en `core.PluginMetadata`; `resolvePlugins(nil)`
   salta los `OptIn`, independiente de `DefaultPort`. Limpio; cambia el
   contrato de plugins.
2. En `resolvePlugins(nil)`, saltar `DefaultPort==0` salvo `banner`. Más
   pequeño, menos general.
3. Validar en el handler web que `plugins` no venga vacío. Deja "todo" como
   decisión explícita del operador.

No es destructivo (todo read-only): por eso es backlog, no hotfix.

## Backlog 28-9-2026: S7 + OPC UA exposure (refs validadas, sin construir)

Del batch de probes inspirado en chrisdinozzi/opcua-recon (28-9-2026) se
entregaron **5 de 5, backlog vacío**: monitor Modbus, probe MQTT/Sparkplug,
OPC UA anonymous-access (`opcua probe-anon`, 29-9), OPC UA writeable-tag
walk (`opcua probe-write`, 29-9) y **S7 nivel de protección del CPU
(`s7 probe-protection`, 29-9)**. **Extra 29-9 (fuera del batch): S7
identidad/firmware (`s7 probe-identity`): lee SZL 0x0011 (order number MLFB
+ firmware, marca 'V') y SZL 0x001C (module type, serial, station, plant)
para el match de CVE. Validado byte a byte vs `s7comm_reading_plc_status`.
Wire: `internal/protocols/s7/wire/ident.go`; cliente `identityprobe.go`.**

- **S7: nivel de protección del CPU. [HECHO 29-9-2026, `s7 probe-protection`;
  commits locales sin firmar 93aa331/dae10c5].** COTP CR/CC + Setup
  Communication + Userdata Read SZL (grupo CPU-functions `0x04`, subfunción
  `0x01`), SZL-ID `0x0132` índice `0x0004`. Registro: words index, key,
  param, real, bart_sch, ... El probe reporta el nivel efectivo (`real`:
  1=sin password, 2=write-protected, 3=read+write protected) + el selector
  de modo (`bart_sch`: 1=RUN, 2=RUN-P, 3=STOP, 4=MRES). Marca **expuesto**
  si real es 0/1. **Validado BYTE A BYTE contra captura real**
  (`s7comm_reading_plc_status.pcap`, ITI): Setup + Read SZL request +
  respuesta de protección (key=1,param=0,real=1,bart_sch=RUN-P) casan con
  los bytes reales, cruzado con el dissector `packet-s7comm_szl_ids.c`.
  Wire: `internal/protocols/s7/wire/{setup,szl}.go`; cliente:
  `internal/protocols/s7/protectionprobe.go`.
- **OPC UA: tags escribibles por anónimo (read-only). [HECHO 29-9-2026,
  `opcua probe-write`; commits locales sin firmar].** Tras OPN
  (SecurityPolicy#None) + CreateSession + ActivateSession(anónimo), navega
  desde `i=85` por HierarchicalReferences (BFS acotado por `--max-nodes`) y
  lee NodeClass(2, vía Browse) + UserAccessLevel(18). Marca "escribible por
  anónimo" si NodeClass==Variable(2) y UserAccessLevel tiene CurrentWrite
  (0x02). Nunca escribe. Cliente: `writeprobe.go` + `session_client.go`
  (reusa el handshake de `anonprobe.go`); wire: `browse.go`/`read.go`/
  `nodeid.go`. Caveat de validación: no hay pcap real con Browse/Read (el
  None de ITI solo trae sesión + Call), así que ese codec va fundamentado
  en Part 4+6 y validado por round-trip/fixture/net.Pipe, no contra bytes
  reales (documentado en `docs/protocols/opcua.md` y cada fichero).
- **Nota (28-9-2026):** ambos se pararon porque construir el cliente de
  sesión ICS activo disparó el clasificador de seguridad. Retomar en
  trozos pequeños y neutros (parser del registro / decoder de
  ReadResponse aislados) o con objetivo/captura de validación.

### Progreso 29-9-2026 (approach de-riesgado, resumible)

- **El enfoque incremental codec-first FUNCIONA con el clasificador**:
  piezas pequeñas de decoder/encoder puras (sin dial activo) pasan. La
  primera ya está en `main` (commit `a9c451a`): `wire.ResponseServiceResult`
  extrae el `serviceResult` del ResponseHeader de cualquier respuesta UA,
  validado contra respuestas REALES capturadas.
- **Pcaps de validación (fuente: repo ITI/ICS-Security-Tools, raw GitHub;
  ficheros reales, no LFS):**
  - OPC UA: `pcaps/OPC/opc-ua-ap-method-wireshark-freeze.pcap`. Sesión
    **SecurityPolicy#None** en puerto 12001 con el flujo completo: HEL/ACK,
    OPN, GetEndpoints(428/431), CreateSession(461/464),
    ActivateSession(467/470), Call(712). NO tiene Read(631)/Browse(527).
  - S7: `pcaps/s7/S7Comm/s7comm_clean.pcap`. 5447 paquetes S7comm puerto
    102, pero TODO Var-services (Job 2641 / Ack 2806), CERO userdata SZL.
    Valida framing S7comm; para el SZL de protección usar el layout del
    dissector de Wireshark de arriba.
  - Fixtures reales ya extraídos (parsers pcap propios en scratchpad):
    cada mensaje UA de la sesión (OPN req 132B / resp 136B,
    CreateSessionResp 464 8086B, ActivateSessionResp 470 96B, etc). El
    OPN de 132B confirma que la sesión es None (el caso que ataca el probe).
- **Siguientes pasos OPC UA (para "acceso anónimo confirmado", que es la
  feature `-probe-anon` de opcua-recon y es más pequeña que el walk de
  tags):** parser OpenSecureChannelResponse (SecureChannelId + TokenId,
  saltando el asym header de longitud variable) -> encoder+parser
  CreateSession (authenticationToken + serverNonce) -> encoder
  ActivateSession(anónimo) -> cliente TCP activo (HEL/ACK/OPN/CreateSession/
  ActivateSession) que reporta "acceso anónimo confirmado" si el
  serviceResult final es Good. Luego, como incremento aparte, Browse desde
  i=85 + Read de UserAccessLevel para el walk de tags escribibles.

### Estado 29-9-2026: WIRE DE SESIÓN COMPLETO Y VALIDADO

Todo el codec de wire de sesión está en `main` (commits `a9c451a`,
`ba169c5`, `5bb895b`, `d146c7b`, `4e9cc09`), cada pieza validada contra la
captura None real (no fixtures propios): `internal/protocols/opcua/wire/`
- Encoders: `EncodeOpenSecureChannelRequestNone`, `EncodeCreateSessionRequest`,
  `EncodeActivateSessionRequestAnonymous`, `EncodeGetEndpointsRequest` (bare)
  + `EncodeHello` (ya existía). Helpers `putRequestHeader`/`putSymmetricHeader`/
  `putDouble`/`putByteString`/`putClientDescription`.
- Decoders: `ParseOpenSecureChannelResponse` (ChannelId+TokenId),
  `ParseCreateSessionAuthToken`, `ResponseServiceResult`, y GetEndpoints ahora
  expone `EndpointDescription.AllowsAnonymous`+`AnonymousPolicyID`.
- Fixtures reales como testdata (`testdata/getendpoints_resp_none.bin`) y hex
  inline en los tests.

**Solo queda ensamblar (mecánico, no wire nuevo):**
1. `EncodeGetEndpointsRequestTCP` (wrap del bare GetEndpoints con symmetric
   header, para pedir endpoints sobre el canal y sacar el policyId anónimo).
2. Cliente activo `ProbeAnonymousAccess(ctx, conn io.ReadWriter, endpointURL)`
   en `internal/protocols/opcua/`: HELLO/ACK -> OPN(None) ->
   ParseOpenSecureChannelResponse -> GetEndpoints (policyId anón) ->
   CreateSession -> ParseCreateSessionAuthToken -> ActivateSession(anón) ->
   `ResponseServiceResult`==Good => acceso anónimo confirmado. Toma un
   io.ReadWriter para testearlo con un servidor falso que reproduzca las
   respuestas REALES capturadas (msg_ACK/OPN_8/431/464/470.bin del scratchpad,
   URLs en este backlog).
3. Cablear en el plugin opcua (o un verbo) + finding + docs.
Luego el incremento aparte: Browse i=85 + Read UserAccessLevel (tags
escribibles).

Complementa a `TODO.md` (la checklist original del brief, closed
tras v1.12.0) y a `ROADMAP.md` (el plan chunked). Aquí se apuntan
ideas de features futuras, superficies de ataque a añadir y
mejoras operativas que surgen en campo.

> Mantén este fichero **corto y accionable**. Cuando un ítem
> entre en un ciclo (v1.x) muévelo a `ROADMAP.md` con su chunk
> asignado + estimación. Cuando cierre, márkalo `✅` con la
> versión y/o el commit.

Last refresh: **2026-05-03** (post-v1.33). Items shipped during
v1.3 → v1.33 archived to keep this file actionable.

---

## ✅ Shipped during v1.3-v1.24

### v1.3 → v1.15 (PBX discovery + IPv6 + observability foundations)

- ✅ **PBX discovery (Asterisk / FreePBX / Cisco UCM / 3CX /
  Mitel / Avaya / Yeastar / Grandstream)**: v1.3 chunks 1-3 +
  v1.4 chunk 5. SIP / IAX2 / pbxhttp probes + 15 PBX vendor
  fingerprints.
- ✅ **TR-069 / CWMP probe + offensive proxy**: v1.4 chunk 5
  (probe) + v1.11 chunk 1 (gate) + v1.12 chunks 1, 10
  (per-parameter-path + per-firmware).
- ✅ **FOFA / ZoomEye / ONYPHE input clients**: v1.8 chunks 1-2
  + v1.9 chunk 4. CLI wire-up via `--input <provider>:<query>`
  + `--api-creds-file <yaml>`: v1.9 chunk 3.
- ✅ **Shodan InternetDB (no-key provider)**: v1.12 chunk 9.
- ✅ **Input pagination across 5 providers**: v1.12 chunk 8.
- ✅ **SLSA-pivot to free-tier**: v1.8.0+ ships GPG-signed tag
  + SHA-256 + CycloneDX SBOMs locally; cosign+SLSA+GHCR remain
  available behind GitHub Actions billing restore.
- ✅ **Per-object / per-path scoping across 7 write-gates**: 
  v1.12 chunks 1, 2, 3, 4, 5, 6, 7, 10. SIP From-domain (chunk
  5), Modbus structured writes (chunk 4), OPC UA rich NodeIDs +
  CallMethod (chunks 3, 6), BACnet per-WriteProperty (chunk 7),
  CWMP per-parameter-path + per-firmware (chunks 1, 10).
- ✅ **InternetDB bulk lookup**: v1.13 chunk 1.
- ✅ **CWMP firmware pre-flight verifier**: v1.13 chunk 2.
- ✅ **BACnet per-object for WritePropertyMultiple (svc 16)**: 
  v1.13 chunk 3.
- ✅ **CWMP RPC-name case-warning in dry-run**: v1.13 chunk 4.
- ✅ **CWMP-over-TLS operator recipe**: v1.13 chunk 5 (docs only).
- ✅ **Triage bucket "utility"**: v1.13 chunk 6 (4th bucket).
- ✅ **BACnet per-target / per-state / per-operation /
  per-instance / per-(object,property) scoping for the 7
  remaining mutating services**: v1.13 chunks 7-13.
- ✅ **IPv6 cross-cutting support**: v1.14 (4 chunks).
- ✅ **CWMP TransferComplete observer (parsing half)**: 
  v1.15 chunk 1.
- ✅ **`elsereno discover --auto <CIDR>`**: v1.15 chunk 2.
- ✅ **STIX 2.1 export**: v1.15 chunk 3.
- ✅ **Audit chain cross-process merge via flock**: v1.15
  chunk 4.
- ✅ **SIGHUP reload of proxy listen allowlist (supervisor
  variant)**: v1.15 chunk 5.

### v1.16 → v1.18 (refinements + observability + dashboard UX)

- ✅ **CWMP TransferComplete authorisation cross-reference**: 
  v1.16 chunk 1. Closes the v1.15 chunk-1 observer half:
  envelope is now correlated with prior Download authorisation
  (CommandKey ↔ allowlist firmware metadata).
- ✅ **BACnet per-(type, instance) CreateObject**: v1.16 chunk 2.
  Refines v1.13 chunk 8 from per-type → per-instance.
- ✅ **BACnet per-(operation, type, instance) LifeSafetyOperation
  scoping**: v1.16 chunk 3. Refines v1.13 chunk 11 from
  per-operation → per-target.
- ✅ **BACnet token-generation cookie**: v1.16 chunk 4.
  Foundation separator 0xF5.
- ✅ **Token-generation parity across 6 plugins**: v1.17
  chunks 1-3. CWMP / SIP / Modbus / IAX2 / pbxhttp / OPC UA
  cookie rollout. All 7 gates now share the same shape.
- ✅ **In-process allow-file reload (SIGUSR1 + atomic swap)**: 
  v1.17 chunk 4. Supersedes the v1.15 chunk-5 supervisor pattern.
- ✅ **`proxy_allowlist_reload` audit event**: v1.17 chunk 5.
- ✅ **Dashboard: CSV export from Findings panel**: v1.18 chunk 1.
- ✅ **Dashboard: diff between two runs**: v1.18 chunk 2.

### v1.19 → v1.21 (observability completion + legacy ICS roll-out)

- ✅ **Audit log API endpoint + dashboard panel**: v1.19 chunk 1.
- ✅ **Reload cadence dashboard panel**: v1.19 chunk 2.
- ✅ **CWMP TransferComplete async firmware re-fetch**: 
  v1.19 chunk 3. Opt-in `--verify-firmware-on-complete`.
- ✅ **Omron FINS UDP fingerprint plugin (port 9600)**: v1.20
  chunk 1.
- ✅ **MELSEC SLMP TCP fingerprint plugin (port 5007)**: 
  v1.20 chunk 2.
- ✅ **GE-SRTP TCP fingerprint plugin (port 18245)**: 
  v1.20 chunk 3 + v1.21 chunk 4 (model-hint refinement).
- ✅ **KNXnet/IP UDP fingerprint plugin (port 3671)**: 
  v1.21 chunk 1.
- ✅ **M-Bus over TCP fingerprint plugin (port 10001)**: 
  v1.21 chunk 2.
- ✅ **DLMS/COSEM TCP fingerprint plugin (port 4059)**: 
  v1.21 chunk 3.

### v1.88 (Expanded audit event types)

- ✅ **Expanded audit event_type set**: v1.88 chunk 1.
  Migration 00012 adds `delete`, `set_enabled_true`,
  `set_enabled_false` to the CHECK enumeration; FK
  switched from CASCADE to SET NULL so audit rows
  survive schedule deletion. Go enum mirrors.
  deleteSchedule + setScheduleEnabled write audit rows
  (best-effort, X-Schedule-Audit-Warning on failure).
  4 REST tests. Carryover: dashboard "Deleted" badge
  + per-schedule retention overrides (v1.89+), advisory
  lock for multi-process serve (v1.90+).

### v1.87 (Background audit pruner)

- ✅ **Automatic background audit pruner**: v1.87
  chunk 1. AuditPruner struct + Run/Tick + sentinels.
  `cmd serve --audit-retention-days N` flag spawns
  the goroutine (default 0 = disabled). Eager first
  tick + clamping floors. 7 unit tests. Carryover:
  expand event_type set (v1.88+), per-schedule
  retention overrides (v1.89+), advisory lock for
  multi-process serve (v1.90+).

### v1.86 (Audit retention pruning)

- ✅ **Audit retention pruning**: v1.86 chunk 1.
  ScheduleAuditStore.PruneOlderThan + DELETE
  /api/v1/schedules/audit?before=<rfc3339> endpoint.
  Global (cross-schedule) retention enforcement.
  Memory + DB implementations. 3 unit + 4 REST tests.
  Carryover: automatic background pruner (v1.87+),
  per-schedule retention (v1.88+).

### v1.85 (Dashboard audit history view)

- ✅ **Dashboard audit history view**: v1.85 chunk 1.
  Per-schedule "History" button opens a panel listing
  audit events with field-level before→after diffs.
  Reuses v1.84's GET /audit + v1.81 strify semantics.
  No Go changes. 8 dashboard markers.

### v1.84 (Force-overwrite audit log)

- ✅ **Audit log of force-overwrite events**: v1.84
  chunk 1. ScheduleAuditStore interface + Memory/DB
  implementations. PUT carrying
  `X-Schedule-Force-Overwrite: true` (with non-nil audit
  store) persists a force_overwrite event with
  before/after JSONB snapshots. GET
  /api/v1/schedules/{id}/audit returns events
  newest-first. Migration 00011 + CASCADE-on-delete +
  (schedule_id, occurred_at DESC) index. cmd_serve
  picks DB-backed store on --scan-store=db. Dashboard
  forceOverwriteSchedule sends the header. 5 unit +
  5 REST tests.

### v1.83 (Cherry-pick merge view)

- ✅ **Per-field cherry-pick in merge view**: v1.83
  chunk 1. Each diff row gets a pair of radio buttons
  (mine | server, default mine). New "Apply selected
  (per-field)" button walks the selections + PUTs
  WITH If-Match. applyServerField preserves cadence-
  XOR automatically. v1.81's Take server + Force
  overwrite remain. 4 dashboard markers. No Go
  changes.

### v1.82 (AbortController on /preview)

- ✅ **AbortController-based request cancellation on
  debounced /preview**: v1.82 chunk 1. previewAbortController
  fires `.abort()` on the previous controller whenever a
  newer previewNextFire dispatches. AbortError silently
  skipped in the catch. typeof-guard for pre-2018
  browsers. 3 dashboard markers. No Go changes.

### v1.81 (412 merge-view UI)

- ✅ **412 merge-view UI**: v1.81 chunk 1.
  Dashboard JS+HTML. On 412 from PUT,
  enterMergeView fetches fresh server state +
  computeScheduleDiff renders a field-level diff
  panel with Take server + Force overwrite buttons.
  acceptServerSchedule re-loads via beginEditSchedule;
  force-overwrite re-PUTs without If-Match after a
  confirm() prompt. 8 dashboard markers. No Go
  changes.

### v1.80 (Live preview with debounce)

- ✅ **Live preview on cadence-field change**: 
  v1.80 chunk 1. schedulePreviewRefresh debounces at
  350ms; input + change listeners attached to
  schedule-cadence-mode / schedule-interval /
  schedule-cron / schedule-timezone. Manual
  preview button kept as force-refresh. 3 dashboard
  markers. No Go changes.

### v1.79 (Multi-fire preview)

- ✅ **Multi-fire preview**: v1.79 chunk 1.
  ScanSchedule.NextFires(now, count) +
  PreviewNextFires(req, now, count). /preview gains
  `?count=N` query param (default 1, capped at
  PreviewNextFiresMaxCount = 10). Dashboard cron
  mode renders count=5 as an ordered list. 7 unit +
  4 REST + 3 dashboard markers.

### v1.78 (Optimistic locking on schedule edits)

- ✅ **Optimistic locking on schedule edits**: v1.78
  chunk 1. ScanSchedule.UpdatedAt + UpdateScheduleRequest.
  IfMatch + ErrSchedulePreconditionFailed (→ 412). PUT
  reads `If-Match` header (RFC3339Nano). DBScheduleStore.
  Update conditional UPDATE + follow-up SELECT to
  disambiguate 404 vs 412. Migration 00010 +
  scheduleColumns 12 → 13. Dashboard captures updated_at
  + sends If-Match on PUT. 11 unit + 4 REST + 2 dashboard
  markers.

### v1.77 (Dashboard next-fire preview)

- ✅ **Dashboard next-fire preview**: v1.77 chunk 1.
  ScanSchedule.NextFireAt computed at read time.
  NextFire(now) method shared between read paths +
  preview. PreviewNextFire free function + POST
  /api/v1/schedules/preview endpoint. Dashboard "Next
  fire" column + "Preview next fire" button.
  writeScheduleValidationError shared across
  Create/Update/Preview. cronIsDue delegates to
  cronNextFire (DRY). 11 unit + 5 REST + 5 dashboard
  markers.

### v1.76 (Named cron shortcuts)

- ✅ **Named cron shortcuts**: v1.76 chunk 1. Vixie-
  style @yearly / @annually, @monthly, @weekly,
  @daily / @midnight, @hourly. ParseCron pre-processes
if input starts with `@`, case-folded token is
  looked up + replaced by the 5-field form. c.Raw()
  preserves operator input. @reboot intentionally
  NOT supported. Dashboard placeholder updated.
  9 new tests.

### v1.75 (Per-schedule timezone for cron)

- ✅ **Per-schedule timezone for cron**: v1.75 chunk 1.
  ScanSchedule.Timezone (IANA) + validation via
  time.LoadLocation. cronIsDue converts anchor + now
  to s.Timezone before computing Next/Match. Empty =
  UTC fallback. Migration 00009 + scheduleColumns
  11 → 12. Dashboard tz input visible in cron mode +
  Interval-column zone suffix. 8 new tests + 3
  dashboard markers.

### v1.74 (Schedule edit form)

- ✅ **Schedule edit form**: v1.74 chunk 1.
  ScheduleStore.Update + PUT /schedules/{id} +
  dashboard edit-mode toggle. validateScheduleFields
  + applyCadence helpers shared between Create +
  Update. 11 new tests + 4 dashboard markers.

### v1.73 (Cron expressions)

- ✅ **Cron expressions as alternative cadence**: 
  v1.73 chunk 1. Custom 5-field parser (asterisk/
  numeric/comma/range/step). ScanSchedule.CronExpr
  mutually exclusive with IntervalSeconds. Migration
  00008 + cadence-XOR CHECK. Dashboard cadence-mode
  dropdown. UTC-only; named shortcuts deferred. 19
  new tests.

### v1.72 (Dashboard schedule UI panel)

- ✅ **Dashboard schedule UI panel**: v1.72 chunk 1.
  CRUD + Enable/Disable + Delete inline. humanInterval
  renders human-friendly labels. 503 surface for
  --scan-store=off. Reuses v1.68 plugin <datalist>.
  11 new test markers.

### v1.71 (DB-backed scheduled scans)

- ✅ **DB-backed scheduled scans**: v1.71 chunk 1.
  Migration 00007 adds scan_schedules with CHECK
  constraints (interval + template_input). New
  DBScheduleStore implements ScheduleStore via the
  shared Querier. cmd_serve picks the right store
  based on --scan-store. 12 new tests.

### v1.70 (Scheduled scans)

- ✅ **Scheduled scans (interval-based, in-memory)**: 
  v1.70 chunk 1. ScanSchedule + ScheduleStore +
  Scheduler goroutine + REST CRUD. Interval clamped
  [60s, 7d]; tick clamped [10s, 5min]. MarkFired
  BEFORE Submit so Submit failures don't loop.
  In-memory only; v1.71 adds DBStore. 19 new tests.

### v1.69 (Bulk scan-submit)

- ✅ **Bulk scan-submit endpoint + dashboard panel**: 
  v1.69 chunk 1. POST /scans/bulk capped at 200
  inputs; partial-failure response keeps successful
  Submits, reports failed inputs by index. Textarea
  panel shares plugin + port with single-submit
  form. 5 new tests.

### v1.68 (Plugin-list autocomplete UI)

- ✅ **Plugin-list autocomplete UI**: v1.68 chunk 1.
  Native <datalist> on the scan-submit plugin field,
  populated from /api/v1/plugins on page boot.
  Discoverability win for new operators. Multi-token
  after a comma deferred (needs tokenizing chip
  widget). 4 new test markers.

### v1.67 (DBStore findings_by_plugin column)

- ✅ **DBStore findings_by_plugin column**: v1.67
  chunk 1. Migration 00006 adds JSONB column.
  Closes the v1.66 honest-scope persistence gap.
  4 new tests.

### v1.66 (Per-plugin findings breakdown)

- ✅ **Per-plugin findings breakdown**: v1.66 chunk 1.
  Job.FindingsByPlugin map; SSE payloads carry it;
  dashboard tooltip on Findings cell. Breaking API:
  JobRunner.Run signature gains a third return.
  DBStore persistence deferred to v1.67. 5 new tests.

### v1.65 (scan_stats_progress SSE event)

- ✅ **scan_stats_progress SSE event with per-job
  throttle**: v1.65 chunk 1. Mid-scan progress
  visibility; counters tick live. JobRunner gains
  ProgressReporter param. ScanProgressThrottle with
  500ms cadence + identical-snapshot suppression +
  Forget on terminal transitions. 11 new tests.

### v1.64 (Multi-plugin per scan Job)

- ✅ **Multi-plugin per scan Job**: v1.64 chunk 1.
  Relaxes the v1.61 single-plugin contract. Empty
  Plugins → all registered; comma-separated UI
  field; per-target port-match dispatch; probe-
  attempts Stats accounting. INSTALL.md updated.
  11 net new tests.

### v1.63 (scan_state_change SSE event)

- ✅ **scan_state_change SSE event +
  BroadcastingStore decorator**: v1.63 chunk 1.
  Dashboard transition latency from ~2s polling to
  ~10ms SSE. Decorator pattern keeps scanorch
  package free of stream coupling. 8 tests.

### v1.62 (Dashboard scan-jobs panel)

- ✅ **Dashboard scan-jobs panel**: v1.62 chunk 1.
  Trigger-from-button UI on top of v1.58/59/60/61.
  Submit form + jobs table + per-row Cancel +
  two-tier polling. CSP nonce inheritance
  preserved. 2 new tests.

### v1.61 (Real scan runner + serve --scan-store flag)

- ✅ **Real scan runner + serve --scan-store flag**: 
  v1.61 chunk 1. defaultScanRunner connects v1.58
  orchestration to the existing scanner + plugin
  registry. Single-plugin contract; multi-plugin
  deferred. INSTALL.md gains "Scan orchestration"
  section. 7 tests.

### v1.60 (Postgres-backed scan-job Store)

- ✅ **Postgres-backed scan-job Store**: v1.60
  chunk 1. Migration 00005_scan_jobs.sql +
  DBStore with atomic UPDATE-RETURNING transitions.
  CHECK-constrained state enum. 11 tests.

### v1.59 (Scan-job Worker + JobRunner + Pool + Cancel)

- ✅ **Scan-job Worker + JobRunner + Pool + Cancel
  endpoint**: v1.59 chunk 1. Builds on the v1.58
  shell with execution machinery: claim, panic-
  recover, terminate. Pool with bounded concurrency
  + Drain polling loop. POST /scans/{id}/cancel
  with proper 200/404/409 semantics. 18 tests.

### v1.58 (Dashboard scan-orchestration shell)

- ✅ **Dashboard scan-orchestration shell**: v1.58
  chunk 1. Closes the v1.32+ F carryover. New
  internal/scanorch/ package (Job + state machine +
  in-memory Store) + REST endpoints under
  /api/v1/scans/. Worker + DB store + UI hookup are
  follow-up cycles, not carryover. **Closes the
  v1.50 substantial-items batch entirely.** 19 tests.

### v1.57 (DLMS/COSEM offensive write path)

- ✅ **DLMS/COSEM offensive write-gated proxy**: 
  v1.57 chunk 1. Closes the v1.32+ D3 carryover and
  the legacy-ICS D-trio offensive write paths overall.
  Three-tier gate (APDU tag + per-(class, OBIS,
  member) + match strictness MatchExact/ClassOBIS/
  ClassOnly). 28 tests.

### v1.56 (M-Bus offensive write path)

- ✅ **M-Bus offensive write-gated proxy**: v1.56
  chunk 1. Closes the v1.32+ D2 carryover. Two-tier
  gate (control field + per-(CI, Address) tuple)
  with wildcard semantics + typo-guard against
  {0,0}-as-wildcard. 25 tests.

### v1.55 (KNX offensive write path)

- ✅ **KNX offensive write-gated proxy**: v1.55
  chunk 1. Closes the v1.32+ D1 carryover. Three-tier
  gate (service-type / APCI / group-address) with
  per-(GA, mask) granularity. Plus a buried v1.21
  correctness fix for DESCRIPTION_REQUEST/RESPONSE
  service-type constants. 24 tests.

### v1.54 (Beckhoff TwinCAT ADS fingerprint)

- ✅ **Beckhoff TwinCAT ADS plugin (TCP/48898)**: 
  v1.54 chunk 1. Closes the v1.32+ C carryover.
  AMS/TCP framing + AMS routing header +
  ReadDeviceInfo. Plugin count 28 → 29. 8 tests.
  Most-requested missing fingerprint since v1.25.

### v1.53 (enip per-(class, instance, attribute) gating)

- ✅ **enip per-(class, instance, attribute) gating**: 
  v1.53 chunk 1. CIP MR EPATH parser +
  AllowedAttribute (3 match strictnesses).
  AllowlistHash separator 0xF2. 12 tests.

### v1.52 (s7 per-(area, db, byte-address) gating)

- ✅ **s7 per-(area, db, byte-address) gating**: 
  v1.52 chunk 1. Wire parser + AllowedWriteItem +
  AllowlistHash dimension (separator 0xF1). Empty
  list preserves v1.27 backward-compat. 11 tests.

### v1.51 (MMS ACSE A-ASSOCIATE-REQUEST)

- ✅ **MMS ACSE association layer**: v1.51 chunk 1.
  Hand-coded static AARQ + OID-pattern AARE scan.
  Confidence ~0.8 → ~0.95 for IEC 61850 IEDs.
  6 new tests.

### v1.50 (macOS sandbox_init cgo-gated)

- ✅ **macOS `sandbox_init(3)`**: v1.50 chunk 1.
  Opt-in cgo build (default release stays pure-Go).
  3 .sb Scheme profiles per offensive Profile.
  3 tests + INSTALL.md update.

### v1.49 (Linux distribution packaging)

- ✅ **deb/rpm/apk packages**: v1.49 chunk 1.
  3 variants × 3 formats × 2 archs = 18 packages per
  release.
- ✅ **Hardened systemd units** for serve + audit
  serve.
- ✅ **`INSTALL.md`** comprehensive cross-platform
  install doc.
- ✅ **Standing process directive**: every cycle from
  here updates both macOS+Linux artefacts and the
  platform-specific docs.

### v1.48 (proxy replay --stats)

- ✅ **`proxy replay --stats`**: v1.48 chunk 1.
  Summary mode (per-direction chunks/bytes + time
  range). 3 tests + validateMutexFlags consolidator.

### v1.47 (proxy replay --tail)

- ✅ **`proxy replay --tail N`**: v1.47 chunk 1.
  Emits last N matching chunks via ring buffer. 3 tests.

### v1.46 (proxy replay --limit)

- ✅ **`proxy replay --limit N`**: v1.46 chunk 1.
  Caps output at N matching chunks; applied after
  --dir/--since/--until. 3 tests.

### v1.45 (proxy replay --json + DirHeader fix)

- ✅ **`proxy replay --json`**: v1.45 chunk 1.
  Machine-readable output for jq pipelines. Side fix:
  dispatcher now skips DirHeader. 2 tests.

### v1.44 (proxy replay time-window)

- ✅ **`proxy replay --since/--until`**: v1.44 chunk 1.
  Forensic time-window filter. 4 tests.

### v1.43 (tui --rate slow playback)

- ✅ **`tui --rate N`**: v1.43 chunk 1. Slow-motion
  playback flag. 3 tests.

### v1.42 (replay/record round-trip)

- ✅ **Round-trip closed**: v1.42 chunk 1. `feeds.Replay`
  reads both `ndjson:v1` and `elsereno-tui-record/v1`. The
  v1.41 `--record` output is now consumable by `--replay`.
  8 tests.

### v1.41 (tui --record session capture)

- ✅ **`tui --record FILE.ndjson`**: v1.41 chunk 1.
  Symmetric counterpart to v1.29-chunk-3's --replay. Tees
  every model-bound tea.Msg onto a 0600 NDJSON file
  (`elsereno-tui-record/v1` schema). Best-effort. 8 tests.

### v1.40 (plugins ports reverse index)

- ✅ **`plugins ports` verb**: v1.40 chunk 1. Maps
  port → [plugins] for "which plugin claims 502?" lookups.
  Default plain-text + --json. 4 tests.

### v1.39 (discover --hosts <file>)

- ✅ **`discover --hosts <file>`**: v1.39 chunk 1. Natural
  counterpart to `--auto <CIDR>`. Accepts a curated host
  list (one IP per line, comments OK, host:port-strip,
  IPv6 supported). 7 tests.

### v1.38 (fingerprint capture verb)

- ✅ **`elsereno fingerprint capture` verb**: v1.38
  chunk 1. Natural companion to v1.37's `validate --file`.
  Opens a localhost listener, accepts one connection,
  writes drained bytes to a 0600 file. 4 tests.

### v1.37 (fingerprint validation CLI verb)

- ✅ **`elsereno fingerprint validate` verb**: v1.37
  chunk 1. Closes the v1.28-chunks-1+2 carryover ("ProConOS
  + GE-SRTP confidence ~0.7 pending real-PLC validation").
  Operators with lab access can now self-serve via captured
  bytes (--file or --hex). Works for every registered
  plugin. 13 tests.

### v1.36 (dashboard --input parity)

- ✅ **Dashboard --input parity**: v1.36 chunk 1. Closes
  the v1.31 carryover. New `GET /api/v1/inputs/preview`
  endpoint + `internal/inputs/preview` package. Read-only;
  trigger-from-dashboard scan orchestration is a future
  cycle.

### v1.35 (proxy listen --plugin for 4 legacy-ICS protocols + recording)

- ✅ **proxy listen --plugin pcworx|mms|enip|s7**: v1.35
  chunk 1. Closes the v1.30 carryover; the 4 plugins that
  had Recorder fields but no CLI verb are now first-class
  `--plugin` values with their own allowlist flags
  (--intent / --cip-command / --s7-fc). 13 dispatcher tests
  + 1 invariant pin (every Recorder-having type is in
  attachRecorder).

### v1.34 (tree-wide gosec marker hygiene)

- ✅ **Tree-wide `//nolint:gosec` → `// #nosec G<NNN>`
  migration**: v1.34 chunk 1. 76 markers across 49 files
  in internal/**, offensive/**. PITF-030 now enforced
  tree-wide. Side-fix: corrected a pre-existing
  comment-eats-statement bug in
  `offensive/write/enip/write.go` line 148.

### v1.33 (teatest TUI integration tests)

- ✅ **teatest program-level integration tests for TUI
  runner**: v1.33 chunk 1. Closes the v1.30+v1.31
  carryover. 10 cases cover quit, render, message fold,
  filter-edit cycle, focus cycle, severity-band rendering,
  small-terminal fallback, and clean-output drain.

### v1.32 (cmd/elsereno gosec marker hygiene)

- ✅ **gosec marker hygiene (cmd/elsereno)**: v1.32 chunk 1.
  10 `//nolint:gosec` → `// #nosec G<NNN>` native form
  (PITF-030 / b611f5c convention). Wider tree (~65 markers)
  is its own follow-up, see "🔬 Hygiene & convention parity"
  below.

### v1.31 (TUI input parity with batch scan)

- ✅ **TUI `--input` parity with batch `scan`**: v1.31
  chunk 1. All 8 kinds (list, nmap, stdin, shodan, censys,
  fofa, zoomeye, onyphe, internetdb) now first-class on
  `tui --input KIND`. Shared dispatcher
  (`cmd_input_parse.go`).

### v1.30 (record-replay wire-up to all wire-aware gates + TUI scan launcher + audit filter)

- ✅ **Wire record-replay into the 9 wire-aware gates**: 
  v1.30 chunk 1. Closes the v1.28 chunk-3 deferral. sip /
  iax2 / pbxhttp / modbus / opcua / bacnet / cwmp + enip + s7.
- ✅ **`--record FILE` flag on `proxy listen`**: v1.30
  chunk 2. Opens recorder before Authorise so permission
  errors fast-fail.
- ✅ **`elsereno proxy replay FILE` sub-verb**: v1.30 chunk 2.
  Renders captures as `[ts] c→u  NNB  hex…` lines.
- ✅ **TUI scan launcher (`feeds.Interactive`)**: v1.30
  chunk 3. Closes the v1.29 chunk-2 deferral. `--input
  list:FILE` runs `scanner.Scanner` inside the TUI.
- ✅ **TUI audit-pane substring filter**: v1.30 chunk 4.
  `/` → type → Enter; case-insensitive substring match.

### v1.29 (TUI verb + mini build variant)

- ✅ **Mini build variant (`-tags mini`)**: v1.29 chunk 1.
  3-variant goreleaser; mini ~21 MB excludes dashboard + TUI.
- ✅ **Interactive terminal UI**: v1.29 chunks 2-5.
  bubbletea Model/View/Update + 4-pane layout + 4 modes
  (interactive, replay, feed, watch).
- ✅ **TUI protocol doc**: v1.29 chunk 6.
  `.context/tui.md` (architecture + key bindings + wire
  formats + build-tag matrix).

### v1.28 (ProConOS + SRTP service-0x21 + record-replay POC)

- ✅ **ProConOS fingerprint**: v1.28 chunk 1 (best-effort,
  needs real-PLC validation).
- ✅ **GE-SRTP service-0x21 follow-up**: v1.28 chunk 2 (richer
  firmware-version probe; needs real-PLC validation).
- ✅ **Wire record-replay into pcworx + mms gates (POC)**: 
  v1.28 chunk 3.

### v1.27 (seccomp wire-up + pcworx/mms gates + record-replay)

- ✅ **Wire seccomp arg-filter presets into ProfileHarvest +
  ProfileDial**: v1.27 chunk 1.
- ✅ **Offensive `pcworx` write-gate**: v1.27 chunk 2 (session-
  level; per-frame deferred).
- ✅ **Offensive `mms` write-gate**: v1.27 chunk 3 (session-
  level; full ASN.1 BER PDU walk is v1.35 MMS-ACSE candidate).
- ✅ **Record & replay primitive**: v1.27 chunk 4 (NDJSON
  capture + replay; integration into each gated proxy is v1.28+).

### v1.26 (audit daemon + seccomp arg-filter primitives)

- ✅ **`elsereno audit serve` daemon (UDS)**: v1.26 chunk 1.
  Centralised single-writer audit daemon over Unix domain
  socket. `audit.Server` + `audit.Client` (Writer-implementing).
  Replaces v1.15-chunk-4 flock at SOC scale.
- ✅ **seccomp-bpf arg-level filtering primitives**: v1.26
  chunk 2 (Linux). ArgDenyRule + Equal/MaskAny modes +
  ArgFilterPresets + CompileFilterWithArgs. Profile integration
  deferred to v1.27.

### v1.25 (CVE coverage closure + 2 new fingerprint plugins)

- ✅ **`cve_exposure` for the v1.20+v1.21 fingerprint trios**: 
  v1.25 chunk 1. finsudp=5, slmp=6, gesrtp=5, knxip=6,
  mbustcp=4, dlms=7. 24/27 plugins now publish a non-zero
  cve_exposure (was 16/25 post-v1.24).
- ✅ **PCWorx fingerprint plugin (TCP/1962)**: v1.25 chunk 2.
  Phoenix Contact ILC family + AXC F + RFC PN PLCs.
  cve_exposure:8.
- ✅ **IEC 61850 MMS fingerprint with S7 disambig (TCP/102)**: 
  v1.25 chunk 3. COTP TSAP-based disambiguation
  (MMS `00 01`/`00 01` vs S7 `01 00`/`01 02`). cve_exposure:9,
  impact_class:85 (grid-scale).

### v1.22 → v1.24 (CI hygiene + new fingerprints + scoring + docs)

- ✅ **CI hygiene, fuzz-flake retry + explicit `-timeout`**: 
  v1.22 chunk 1.
- ✅ **CoDeSys V3 TCP fingerprint plugin (port 1217)**: 
  v1.22 chunk 2.
- ✅ **Red Lion Crimson / RLN fingerprint plugin (port 789)**: 
  v1.22 chunk 3.
- ✅ **Fuzz coverage expansion 6 → 14 wire packages**: 
  v1.22 chunk 4.
- ✅ **CVE-exposure factor, first 9 plugins**: v1.22
  (codesys / redlion) + v1.23 chunk 1 (cwmp / dnp3 / iec104 /
  bacnet / opcua / hartip / atg).
- ✅ **Banner dictionary expansion +21 vendors**: v1.23 chunk 2.
- ✅ **CVE-exposure factor, 7 more plugins**: v1.24 chunk 1
  (s7 / fox / sip / enip / pbxhttp / modbus / iax2). 16/25
  plugins now publish a non-zero `cve_exposure` score.
- ✅ **Engineering notes for the 5 missing plugins**: 
  v1.24 chunk 2 (cwmp / opcua / sip / iax2 / pbxhttp).
  `.context/protocols/` is now complete for all 25 plugins.

---

## 🎯 High-leverage, siguiente ciclo (v1.26)

- [ ] **Offensive plugin trio, FINS / SLMP / GE-SRTP**: 
  v1.20 shipped read-only fingerprints; the offensive write
  paths (per-CIO write FINS / per-WriteCommand SLMP / per-PLC-
  service GE-SRTP) are pending. Each follows the ADR-040
  template (deny-all default, write-gated offensive variant
  with allowlist + dry-run). Estimación: ~3-4 días total
  (1 chunk per protocol).

- [ ] **Offensive plugin trio, KNX / M-Bus / DLMS**: 
  same shape as the FINS/SLMP/SRTP trio above for the v1.21
  fingerprints. Estimación: ~3-4 días total.

- ✅ **MMS ACSE association layer**: done in v1.51 chunk
  1. Hand-coded static AARQ + OID-pattern AARE scan.
  IEC 61850-8-1 IED confirmation.

- ✅ **Wire record-replay primitive into each gated
  WriteGatedHandler**: pcworx + mms in v1.28 chunk 3 (POC);
  remaining 9 wire-aware gates in v1.30 chunk 1; CLI half
  (`--record` + `proxy replay`) in v1.30 chunk 2.

## 🧰 Herramientas operativas

- ✅ **Record & replay de sesiones de proxy**: primitive in
  v1.27 chunk 4; gate wire-up in v1.28 chunk 3 (POC) + v1.30
  chunk 1 (full); CLI `--record` + `proxy replay` in v1.30
  chunk 2.

## 🔐 Supply-chain + hardening

- ✅ **Wider tree gosec marker convention sweep**: done in
  v1.34 chunk 1 (76 markers across 49 files; PITF-030
  enforced tree-wide).

- ✅ **Sandbox para macOS via `sandbox_init(3)`**: done in
  v1.50 chunk 1 as opt-in cgo build (`make
  build-offensive-darwin-sandboxed`). Default release
  stays pure-Go; operators opt in for kernel sandbox.

## 🔬 Protocolos legacy todavía sin cubrir (2 restantes)

Cada uno = ~6-12h.

- [ ] **PROFINET DCP / GOOSE / SV** (L2, con gopacket, 
  necesita `CAP_NET_RAW` + raw-packet capture infrastructure
  que aún no existe en el repo).
- [ ] **OPC UA HTTPS** (additional transport for UA, distinct
  from UA-TCP 4840). HTTP/JSON UA encoding parser needed, 
  ~12h.

## 🎨 UX

- [ ] **TUI con bubbletea**: `elsereno tui` que agrupa scan +
  finding stream + triage sin salir del terminal. Brief lo
  mencionó en F4 chunk 2. Decisión operador: aceptar la nueva
  dependencia bubbletea + tcell. ~2-3 días.

- [ ] **Record & replay de sesiones de proxy**: *moved to
  Herramientas operativas above* (more natural fit alongside
  audit daemon).

## 🪟 Plataforma

- [ ] **Windows support**. Bloqueadores: `syscall.*` por-
  plataforma en `internal/audit` (file lock, v1.15 chunk 4
  ya cablea el stub `flock_windows.go`) + el sandbox (Windows
  no tiene seccomp; usaríamos AppContainer / Job Objects).
  Estimación: 3-5 días.

- [ ] **Multi-user OIDC + roles**. Actualmente el dashboard
  tiene un solo operador por proceso. Para SOCs multi-analyst:
  OIDC (Keycloak/Azure AD) + roles (viewer / analyst / admin).
  Estimación: 2-3 días.

---

> Para añadir un ítem: PR con una línea + referencia al ADR o
> issue que lo motiva. Si es >3 días de trabajo, acompáñalo de
> una estimación + dependencias.
