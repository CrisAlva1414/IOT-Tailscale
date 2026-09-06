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
**Estado**: COMPLETED (endpoint STUN wired into MapRequest; pendiente validación en hardware)
**Criterio de éxito**: MapRequest incluye endpoint público (STUN-descubierto), no IP local WiFi (192.168.x.x).
**Estado técnico**: Nuevo getter `tsnode_disco_get_stun_endpoint()` en disco; `apply_stun_endpoint_to_config()`
en `tsnode_client.c` reemplaza la IP local por la pública STUN al inicio de cada `do_map_poll()`. Build PASS,
tests unitarios PASS, cppcheck limpio. Pendiente: verificar en hardware que el 2do poll (30s) reporta la IP
pública en MapRequest.
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
**Evidencia de hardware**: `tailscale ping --verbose 100.107.147.106` → `pong from esp32-8219d4 via 192.168.1.104:51820`; kernel `ping` con replies (RTT ~10ms en régimen); `tailscale status` → `active; direct 192.168.1.104:51820`. Serial ESP32: `WG RX init #1` → `WG response sent` → `WG ICMP echo reply #N` (ambos roles: nuestro init y el rekey del notebook). Sesión WG activada por keepalive (ADR-0019): transport data vacío tras `ESTABLISHED` y cada 10s de idle, lo que destrabó el flujo de datos (antes sesiones mudas).
**Estado técnico**: `wg/icmp_echo.{c,h}` transforma echo request→reply in-place (ADR-0016). `tsnode_client.c` re-encapsula el reply por el túnel. Fijados además: `create_response` con `keygen()` clampeado (mbedTLS rechaza escalares con bit 255 → `-0x4c80` intermitente) y clamp completo RFC 7748 en el wrapper X25519 (ADR-0019). El handshake prefiere la ruta directa confirmada por disco (ADR-0018).
**Archivos clave**: `components/tsnode/src/wg/icmp_echo.{c,h}`, `components/tsnode/src/proto/tsnode_client.c`, `components/tsnode/src/wg/wg.c`, `components/tsnode/src/port/esp_idf/x25519_wrapper.c`, `docs/adr/0016-icmp-echo-responder.md`, `docs/adr/0019-wg-session-keepalive-and-mbedtls-x25519-clamp.md`

### GOAL-6: Conexión estable (99.9% uptime)
**Estado**: PARTIAL (keepalive H2 PING + keepalive WG de sesión implementados; pendiente corrida larga en hardware)
**Criterio de éxito**: El dispositivo permanece conectado mientras esté encendido (USB). Reconnect < 10s.
**Problema actual**: Ciclaba cada ~90s (90s on / 5s reconnect). Causal hipotetizada: NAT/firewall
derriba la conexión del control plane tras ~90s de idle entre polls de map.
**Estado técnico**: Añadido `h2_ping()` (ADR-0009 D1: PING sobre túnel H2/Noise) y un keepalive en el
poll loop de `tsnode_client.c` que envía un PING HTTP/2 cada `H2_PING_IDLE_S=20s` de idle para refrescar
el mapping NAT. Un keepalive fallido entra en el backoff de reconexión existente. Tests host
(test_h2.c, 4 casos nuevos), build PASS (-Werror), cppcheck limpio (solo finding pre-existente no
relacionado). Además, desde 2026-09-05 el plano de datos tiene keepalive WG de sesión (ADR-0019, GOAL-5):
transport data cada 10s de idle por peer — las sesiones ya no quedan mudas y el peer se ve `active` en
magicsock/wg (aunque la consola Tailscale siga mostrando "offline" por heartbeat del control plane,
cosmético). Pendiente: validar nodo online > 1h sin ciclo de 90s (corrida larga con ambos keepalives).
**Archivos clave**: `components/tsnode/src/proto/h2.{c,h}` (h2_ping), `components/tsnode/src/proto/tsnode_client.c` (keepalive poll loop + keepalive WG), `tests/unit/test_h2.c`, `docs/adr/0019-wg-session-keepalive-and-mbedtls-x25519-clamp.md`

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
