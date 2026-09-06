# Project Goals — tailnet-esp32-node

Este archivo define los objetivos medibles del proyecto. El loop agent itera hasta que TODOS los goals estén completos.

## Goals (orden de prioridad)

### GOAL-1: Disco crypto compatible con Tailscale
**Estado**: COMPLETED ✅ (validado en hardware 2026-09-05: disco PING/PONG fluyendo y ruta directa usada para el handshake WG)
**Criterio de éxito**: El ESP32 puede recibir y descifrar PONGs de otros nodos Tailscale.
**Estado técnico**: Reemplazado el cifrado incorrecto (ChaCha20-Poly1305) por el NaCl crypto_box
(XSalsa20-Poly1305 + HSalsa20) que Tailscale usa. `nacl_box.c` cross-validado byte-a-byte
contra TweetNaCl (reference implementation) y contra el formato de Go secretbox. PONG_LEN
corregido a 32 (GOAL-2, buffer overflow).
**2026-09-05 (ciclo 1)**: Nuevo `tests/unit/test_disco.c` destapó un bug crítico de
comparación constant-time en `disco.c`: `ct_memcmp` (retorna igualdad, no orden) se
comparaba con `== 0` en los dos call sites, o sea **invertido** — `find_peer_by_disco_key`
nunca matcheaba ("disco from unknown peer" para todo peer legítimo) y un PONG con txid
incorrecto confirmaba ruta directa. Renombrado a `ct_equal` y corregido; esto era causa
raíz probable de no ver PONG ni sesión WG en hardware. Además: NULL-deref en
`get_peer_endpoint` (validado), `PING_MIN_LEN` corregido a 46 (era 44), y el handshake WG
ahora usa la ruta directa confirmada por disco (ADR-0018). Tests host 7/7 PASS
(22 checks nuevos en disco), ASan/UBSan limpio, build PASS, cppcheck limpio.
**Pendiente**: prueba en hardware real (recibir un PONG de un peer Tailscale con NAT directo viable).
**Archivos clave**: `components/tsnode/src/crypto/nacl_box.{c,h}`, `third_party/salsa20poly1305/`,
`components/tsnode/src/disco/disco.c`, `tests/unit/test_nacl_box.c`, `tests/unit/test_disco.c`, `docs/adr/0018-wg-handshake-disco-direct-path.md`
**Acceptance test**: Send PING to a Tailscale peer, receive and decrypt PONG response.

### GOAL-2: PONG buffer fix
**Estado**: COMPLETED
**Criterio de éxito**: `TSNODE_DISCO_PONG_LEN` = 32 bytes (no 30). Sin buffer overflow.
**Estado técnico**: `disco.h` ahora define PONG_LEN = 32 (12 txid + 16 ip + 2 port, verificado
contra disco_test.go de Tailscale). El código que escribía `pong_plain[31]` ya calza en el buffer.
**Archivos clave**: `components/tsnode/src/disco/disco.h`

### GOAL-3: Endpoint reporting con IP pública
**Estado**: COMPLETED ✅ (validado en hardware 2026-09-06)
**Criterio de éxito**: MapRequest incluye endpoint público (STUN-descubierto), no IP local WiFi (192.168.x.x).
**Estado técnico**: Nuevo getter `tsnode_disco_get_stun_endpoint()` en disco; `apply_stun_endpoint_to_config()`
en `tsnode_client.c` reemplaza la IP local por la pública STUN al inicio de cada `do_map_poll()`. Build PASS,
tests unitarios PASS, cppcheck limpio.
**Evidencia de hardware (2026-09-06, corrida larga GOAL-6)**: el log serial muestra
`poll: stun=199.38.181.93:3478 n_peers=4` en **ambos** MapRequest del poll loop (2/2), con
`STUN TX -> 199.38.181.93:3478` antes de cada uno. El endpoint STUN público se reporta en
el 1er y 2do poll — no la IP LAN WiFi.
**Archivos clave**: `components/tsnode/src/proto/tsnode_client.c`, `components/tsnode/src/disco/disco.{c,h}`

### GOAL-4: Logging perfecto
**Estado**: COMPLETED (logging hardened; validación visual en hardware pendiente)
**Criterio de éxito**: Sin truncamiento de strings, sin caracteres raros en serial output, timestamps correctos.
**Estado técnico**: Buffer de `default_log()` subido de 256→512 B con detección de truncación no silenciosa
(aviso WARN si un mensaje excede el buffer). Timestamps correctos (ESP-IDF `esp_log_write`). Console filtra
no-imprimibles. Build PASS, tests PASS, cppcheck limpio.
**Archivos clave**: `components/tsnode/src/port/esp_idf/tsnode_port_esp_idf.c`

### GOAL-5: Ping end-to-end
**Estado**: COMPLETED ✅ — validado en hardware real (2026-09-05)
**Criterio de éxito**: Desde la tailnet, hacer `ping 100.x.x.x` y recibir respuesta.
**Evidencia de hardware**: `tailscale ping --verbose <ip-tailnet>` → `pong from <hostname> via <ip-lan>:51820`; kernel `ping` con replies (RTT ~10ms en régimen); `tailscale status` → `active; direct <ip-lan>:51820`. Serial ESP32: `WG RX init #1` → `WG response sent` → `WG ICMP echo reply #N` (ambos roles: nuestro init y el rekey del notebook). Sesión WG activada por keepalive (ADR-0019): transport data vacío tras `ESTABLISHED` y cada 10s de idle, lo que destrabó el flujo de datos (antes sesiones mudas).
**Estado técnico**: `wg/icmp_echo.{c,h}` transforma echo request→reply in-place (ADR-0016). `tsnode_client.c` re-encapsula el reply por el túnel. Fijados además: `create_response` con `keygen()` clampeado (mbedTLS rechaza escalares con bit 255 → `-0x4c80` intermitente) y clamp completo RFC 7748 en el wrapper X25519 (ADR-0019). El handshake prefiere la ruta directa confirmada por disco (ADR-0018).
**Archivos clave**: `components/tsnode/src/wg/icmp_echo.{c,h}`, `components/tsnode/src/proto/tsnode_client.c`, `components/tsnode/src/wg/wg.c`, `components/tsnode/src/port/esp_idf/x25519_wrapper.c`, `docs/adr/0016-icmp-echo-responder.md`, `docs/adr/0019-wg-session-keepalive-and-mbedtls-x25519-clamp.md`

### GOAL-6: Conexión estable (99.9% uptime)
**Estado**: COMPLETED ✅ — validado en hardware real (2026-09-06, corrida de 85 min)
**Criterio de éxito**: El dispositivo permanece conectado mientras esté encendido (USB). Reconnect < 10s.
**Evidencia de hardware (2026-09-06)**: corrida continua de **85 minutos** (una sola conexión:
1 handshake Noise, 1 transición `state -> 5` online) con **0 disconnects, 0 reconnects, 0 errores
de red** durante todo el período; el firmware anterior ciclaba cada ~90-300s
(timeout→re-POST→NETWORK→reconnect). El long-poll de `/machine/map` generó **444 timeouts de idle
de la capa de registros, todos absorbidos** por el keepalive inline de ADR-0020 (un PING HTTP/2
por cada silencio de 10s) con **443 registros de 17 bytes** (frames PING/ACK h2) recibidos del
control plane; el mapping NAT nunca venció. Plano de datos verificado durante la corrida con
`tailscale ping -> pong directo vía <ip-lan>:51820` en los hitos de 15, 30 y 60 min
(1326 WG keepalives de sesión emitidos, 86 disco PING / 12 PONG). Reconnect: 0 ocurrencias en la
corrida (el camino de reconexión usa backoff base de 5s, dentro del `reconnect < 10s`).
**Estado técnico**: Causa raíz del ciclo era el long-poll bloqueante de `/machine/map`: el cliente
quedaba hasta 300s con **cero tráfico saliente** y el binding NAT/firewall moría (~90s de idle) sin
detectarse hasta el timeout. Fix (ADR-0020): `h2_ping_send()` + `h2_post_keepalive()` — durante el
long-poll, cada timeout de la capa de registros (recv timeout reducido de 300s a `H2_LONGPOLL_PING_S=10s`)
dispara un PING fire-and-forget y se sigue esperando; contador de silencio
(`H2_LONGPOLL_MAX_SILENT_PINGS=10`) aborta con NETWORK si el par no responde NINGÚN frame (detección
fail-closed de half-open ≤100s). Tests host: 3 casos nuevos (keepalive sobrevive timeouts,
límite de silencio fail-closed, `h2_post` histórico sigue fail-closed), 31/31 PASS; build PASS
(-Werror); cppcheck limpio.
**Nota resuelta (2026-09-06, ADR-0021)**: la nota cosmética de "offline / last seen" por
`Stream:false` quedó superada por el stream de `/machine/map` (GOAL-8): el nodo ahora recibe
deltas/keepalives y debería figurar "active" en `tailscale status` (validar en hardware).
**Archivos clave**: `components/tsnode/src/proto/h2.{c,h}` (h2_ping_send, h2_post_keepalive), `components/tsnode/src/proto/tsnode_client.c` (do_map_poll + keepalive poll loop + keepalive WG), `tests/unit/test_h2.c`, `docs/adr/0020-h2-longpoll-ping-keepalive.md`, `docs/adr/0019-wg-session-keepalive-and-mbedtls-x25519-clamp.md`

### GOAL-8: Streaming de /machine/map + autostart (ADR-0021)
**Estado**: COMPLETED ✅ (código + tests + build; validación en hardware pendiente)
**Criterio de éxito**: El nodo mantiene un stream long-lived de `/machine/map` (deltas y
keepalives), figura "active" en `tailscale status`, y arranca solo al boot con registro único
(no re-registra en cada reboot).
**Estado técnico**: `h2_post_stream()` (POST one-shot + callback por frame DATA + PING inline
+ fail-closed ≤100s); splitter de mensajes `[u32 LE len][payload]` con techo fijo 32 KiB;
`tsnode_map_apply_response()` (netmap completo / `PeersChanged` upsert / `PeersRemoved` /
`OnlineChange` / KeepAlive no-op); `tsnode_wg_peer_remove()` + `tsnode_disco_remove_peer()`
para limpieza del data plane. `regdone` en NVS hace el registro una sola vez; auth key
opcional en `tsnode_client_config_t` (tras el primer registro se borra de NVS).
`main/autostart.{c,h}`: WiFi (30s) → cliente → ONLINE (90s) → wipe de auth key.
Build IDF PASS (-Werror), cppcheck limpio, tests host 45/45 en test_h2.
**Pendiente**: flashear y validar en hardware (estado "active" en consola, deltas aplicadas,
`tsconnect` post-reboot sin auth key).
**Archivos clave**: `components/tsnode/src/proto/h2.{c,h}`, `components/tsnode/src/proto/tsnode_map.{c,h}`, `components/tsnode/src/proto/tsnode_client.{c,h}`, `components/tsnode/src/wg/wg.{c,h}`, `components/tsnode/src/disco/disco.{c,h}`, `main/autostart.{c,h}`, `main/prov_store.{c,h}`, `main/main.c`, `main/console.c`, `tests/unit/test_h2.c`, `docs/adr/0021-map-streaming-and-autostart.md`, `docs/sessions/2026-09-06-map-streaming-autostart.md`

### GOAL-7: Flash encryption en Release mode
**Estado**: BUILD READY (config completa, build Release exitoso, pendiente flasheo en hardware)
**Criterio de éxito**: Build Release con flash encryption activa, probado en hardware.
**Estado técnico**: Particion table custom `partitions.csv` creada con `nvs_keys` (8K, encrypted flag).
Offset de partition table subido a 0xB000 (bootloader con flash encryption ocupa 0x90b0, excede el default 0x8000).
Build Release con `sdkconfig.defaults;sdkconfig.prod` exitoso: flash encryption Release, NVS encryption
flash-enc-based, UART ROM DL mode limitado. Todos los tests unitarios PASS. Pendiente: flashear en hardware,
verificar eFuse FLASH_CRYPT_CNT quemado, primer boot cifra in-place (sin corte de alimentación).
**Archivos clave**: `partitions.csv`, `sdkconfig.prod`, `sdkconfig.defaults` (offset 0xB000)

## Flujo del Loop

```
Para cada GOAL en orden de prioridad:
  1. INVESTIGAR: Leer código, tests, logs, sesiones previas
  2. PLANIFICAR: Crear ADR si es decisión de arquitectura, definir fix
  3. CODIFICAR: Implementar fix
  4. VALIDAR: Ejecutar tests, compilar, probar en hardware si aplica
  5. DOCUMENTAR: Actualizar sesión, marcar goal como completado
  6. SI FALLA: Volver a paso 1 con nueva información
```

## Métricas de éxito

- **Build**: `idf.py build` exitoso sin warnings
- **Tests**: Todos los tests unitarios pasan (make -C tests/unit test)
- **Hardware**: Node aparece en `tailscale status` como "active"
- **Connectivity**: `ping 100.x.x.x` responde desde otro nodo de la tailnet
- **Stability**: Device stay connected > 1 hora sin disconnects
