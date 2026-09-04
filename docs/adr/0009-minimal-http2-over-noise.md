# ADR-0009: Cliente HTTP/2 mínimo sobre el túnel Noise ts2021

- Estado: **aceptado** (código implementado y funcionando, ver h2.c y sesión 2026-08-24)
- Fecha: 2026-08-23

## Contexto

La sesión del 2026-08-24 quedó bloqueada: el protocolo "funcionaba" end-to-end
en hardware (handshake Noise OK, EarlyNoise OK, RegisterRequest enviado,
respuesta recibida) pero **el nodo nunca aparecía en
https://login.tailscale.com/admin/machines**. La hipótesis de la sesión era que
el control plane exige HTTP/2 dentro del túnel Noise y que nuestros registros
JSON crudos eran ignorados.

Esta sesión verificó la hipótesis con fuente primaria y con experimentos
empíricos contra producción (prototipo Python en `/tmp` — no versionado),
validado primero offline contra un servidor local que usa los paquetes reales
`tailscale.com/control/controlbase` y `golang.org/x/net/http2`:

1. **Fuente primaria (cliente Go)**: `control/ts2021/client.go` crea un
   `http.Transport` con `Protocols.SetUnencryptedHTTP2(true)` cuyo
   `DialTLSContext` devuelve la conexión Noise. Todo request de registro y
   netmap es entonces HTTP/2 (con conocimiento previo, sin ALPN) dentro del
   túnel. `control/tsp/register.go` / `map.go` confirman: `POST
   /machine/register`, `POST /machine/map`, header `Ts-Lb`,
   `Content-Type: application/json`.

2. **Fuente primaria (servidor)**: `golang.org/x/net/http2@v0.58.0`
   `serverConn.readPreface()` lee exactamente 24 bytes (`PRI *
   HTTP/2.0\r\n\r\nSM\r\n\r\n`) y ante cualquier mismatch cierra la conexión
   sin responder ("bogus greeting"). El servidor local real lo confirmó con
   nuestra carga: `bogus greeting "ping-from-pythonPRI * HT"`.

3. **Experimento contra producción, réplica exacta del flujo del ESP32** (JSON
   crudo como registro Noise tras consumir EarlyNoise): el servidor respondió
   **un único registro de 45 bytes** cuyo plaintext es
   `00 00 24 04 00 00000000 | 05 0010 0000 03 0000 00fa 06 0010 0140 01 0000 10 00 04 0010 0000 09 0000 0001`
   — es decir un **frame SETTINGS HTTP/2** (len=36, type=0x04) — seguido de
   EOF. No hubo ningún RegisterResponse.

4. **Corolario que desmonta la evidencia previa**: el "RegisterResponse
   `{"MachineAuthorized":false}` (45 bytes)" reportado en la sesión anterior
   era ese mismo frame SETTINGS de 45 bytes. El parser C no encontró campos
   JSON en binario y dejó la struct en cero → `machine_authorized=false` → log
   engañoso "machine not yet authorized, waiting...". El MapResponse "0 peers"
   fue la misma clase de misparse sobre datos de cierre de conexión.

5. **Experimento contra producción con HTTP/2 mínimo** (preface + SETTINGS +
   HEADERS/DATA HPACK literal-sin-indexing): **registro completo exitoso**.
   `RegisterResponse` legítimo (565 bytes: User/Login/NodeKeyExpired/
   MachineAuthorized/AuthURL/Error) y `MapResponse` con nodo persistido e IP
   de tailnet asignada (valor en documentación privada, ADR-0010). El nodo
   aparece en el admin.

6. **Formato de MapResponse**: body = secuencia de frames `[u32 LE length]
   [payload]` (`control/tsp/map.go`, tipo `framedReader`). El payload es
   **zstd solo si el MapRequest pide `"Compress":"zstd"`**; omitiendo el campo,
   producción respondió `[len][JSON crudo]` (verificado empíricamente). El
   cliente Go siempre pide zstd; nosotros podemos omitirlo.

## Decisión

### D1. Implementar un cliente HTTP/2 mínimo propio (`proto/h2.c/.h`)

Subset exactamente suficiente para register/map contra el control plane:

- Conexión: client preface (24 B) + SETTINGS vacío; esperar SETTINGS del
  servidor y responder ACK.
- Un stream secuencial por request (`stream_id` impar creciente).
- Request: HEADERS (flag END_HEADERS) + DATA (flag END_STREAM).
- HPACK de salida: *literal without indexing*, sin Huffman, usando índices de
  tabla estática para `:method POST` (3), `:scheme https` (7), `:authority`
  (1), `:path` (4), `content-type` (31); nombres literales para `ts-lb`.
- Respuesta: acumular DATA del stream hasta END_STREAM. Frames soportados:
  DATA, HEADERS, SETTINGS (+ACK), WINDOW_UPDATE (ignorado), PING (→PONG),
  GOAWAY (→error explícito). CONTINUATION o cualquier frame inesperado →
  error fail-closed.
- Validación mínima de respuesta HTTP: el bloque HEADERS debe empezar (tras
  saltar cualquier *dynamic table size update* HPACK, RFC 7541 §4.2) con el
  byte `0x88` (HPACK indexed field estático = `:status 200`); cualquier otra
  codificación/status → error. No se decodifica el resto de los headers.
  - **Ampliación 2026-09-03 (hardware)**: el encoder HPACK Go del control
    plane Tailscale emite hoy un *dynamic table size update* (`0x21`, size 1)
    ANTES del `:status 200` indexado en cada bloque de respuesta. La versión
    previa exigía `0x88` como byte 0 y rompía /machine/register con
    `TSNODE_ERR_NETWORK` (verificado en hardware). El fix salta los size
    updates iniciales antes de validar el `:status`; si el `:status` posterior
    no es el indexado 200, sigue fallando fail-closed.

**No vendorizamos nghttp2.** Razones: nuestro subset evita tablas dinámicas
HPACK, Huffman, flow control adaptativo, push, CONTINUATION y multiplexing;
nghttp2 arrastra toda esa superficie más su port a FreeRTOS. El subset cabe en
~500 líneas auditables con tests host-side y corpus de fuzz. Riesgo aceptado:
si Tailscale exigiera features fuera del subset (p.ej. HPACK dinámico en sus
respuestas), el cliente falla ruidosamente (fail-closed) y se reabre este ADR;
nunca se degrada silenciosamente. **Estado 2026-09-03**: el "HPACK dinámico en
sus respuestas" que este ADR anticipaba como riesgo apareció (size updates); se
manejó siendo tolerante solo al size update inicial sin decodificar tablas
dinámicas, y se documenta arriba. Si el servidor pasara a indexar headers en
tabla dinámica (referencias `1xxx` a índices no-estáticos), se reabre este ADR.

### D2. MapRequest sin compresión

El MapRequest omite `"Compress"`. Respuestas esperadas: frames
`[u32 LE length][JSON]`. Parser dedicado en `proto/tsnode_map.c` que valida
longitud total vs prefijo y **detecta el magic zstd (`28 B5 2F FD`) para
fallar con error explícito** si el servidor algún día comprime sin que se
pidiera. Sin dependencia zstd en el ESP32 (RAM/CPU/flash significativas).

### D3. Límites fijos en compile-time (AGENTS.md §4)

- Payload máximo por frame h2 aceptado: 16384 B (default spec; nunca
  advertiseamos más).
- Acumulador rx estático: 16 KiB + overhead de framing.
- Respuesta de register: buffer del caller, 4 KiB típico.
- Respuesta de map: buffer estático de 32 KiB (netmaps pequeños por ACLs de
  tag; ADR-0008 ya preveía presupuesto ajustable por medición).
- Bodies tx ≤ 16 KiB (register/map ~300–500 B reales).
- Todo memcpy precedido de validación de longitud; longitudes declaradas por
  el peer jamás usadas para indexar sin cap previo.

### D4. Inyección de I/O para testeabilidad host-side

`h2.c` no conoce sockets ni la capa Noise directamente: recibe dos callbacks
(`send_bytes`, `recv_record`) + contexto opaco. En firmware se cablean a
`ts2021_record_send`/`ts2021_record_recv`; en tests host a colas en memoria.
Cero heap, cero headers de plataforma (ADR-0006).

## Alternativas consideradas

- **Vendorizar nghttp2**: descartado (D1). Sería la elección si apareciera la
  necesidad de h2 completo; hoy es peso muerto auditable.
- **HTTP/1.1 dentro del túnel**: descartado empíricamente — el control plane
  no habla nada distinto de h2 post-Noise.
- **Pedir `Compress:"zstd"` y vendorizar zstd**: máxima fidelidad con el
  cliente oficial, pero decompressor completo en ESP32 por una optimización
  que no necesitamos con netmaps chicos. Re-evaluar si los netmaps crecen
  (medición, no intuición).
- **Reusar el stack TCP+TLS del sistema con h2**: no existe tal stack en
  ESP-IDF; el túnel ya es confiable y ordenado (la capa de registros Noise da
  stream semantics sobre TCP).

## Consecuencias de seguridad

- **Nueva superficie de parsing hostil** (frames h2 entrantes, prefijo de
  framing de map): reglas §2.2 completas — validación antes de tocar buffers,
  caps compile-time, fail-closed ante lo desconocido. Fuzzing del parser de
  frames exigido en `tests/unit/test_h2.c` (casos: frames partidos entre
  registros, longitudes mentirosas, GOAWAY, oversize).
- **No cambia el modelo de amenaza físico** (§2.1): no hay claves nuevas ni
  almacenamiento nuevo.
- La validación `:status == 200` vía byte `0x88` evita depender de decodificar
  HPACK comprimido del servidor (menos superficie); un MITM activo dentro del
  túnel sigue siendo imposible sin las claves (Noise IK autentica ambas puntas),
  así que esta simplificación no abre bypass de autenticación.
- El header `ts-lb` expone la node key pública al load balancer (igual que el
  cliente oficial); dato público por diseño.

## Consecuencias de estabilidad

- Buffers estáticos nuevos (~48 KiB .bss entre acumulador h2 y buffer map):
  medición de heap high-water en la sesión de integración per ADR-0008 D6.
- Lecturas bloqueantes acotadas por los timeouts existentes de la capa de
  registros (10 s por lectura); el feed del task watchdog no cambia.
- Fail-closed ante cualquier frame/secuencia fuera del subset: reconexión por
  backoff existente, sin estados intermedios corruptos.
