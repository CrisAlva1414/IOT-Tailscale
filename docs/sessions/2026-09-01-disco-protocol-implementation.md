# 2026-09-01 — Disco protocol implementation + instrumentation

## Contexto

Implementación completa del disco protocol para resolver el bloqueo del data plane:
el ESP32 estaba registrado en Tailscale pero inalcanzable porque estaba detrás de NAT
y sin disco protocol los peers no conocían su endpoint real.

## Cambios

### Instrumentación mejorada (`tsnode_client.c`)
- Contadores de paquetes WG (`wg_pkt_counters_t`): TX/RX initiation, response, transport, keepalive, unknown, errors
- Timestamps relativos (`ts_rel_ms()`) en todos los eventos TX/RX
- Log de contadores periódico en polling loop
- Formato uniforme para grepping: `WG TX init #N -> IP:port len=N t=N ms`

### Disco subsystem (`components/tsnode/src/disco/`)
**Nuevo directorio con 2 archivos:**
- `disco.h` — Header con estructuras y API pública
- `disco.c` — Implementación completa (~500 LOC)

**Funcionalidad implementada:**
- `tsnode_disco_init()` — Generación de keypair X25519
- `tsnode_disco_load_or_generate()` — Carga/generación con persistencia NVS
- `tsnode_disco_add_peer()` — Registro de peers con endpoints
- `tsnode_disco_handle_packet()` — Recepción y descifrado de mensajes disco
- `tsnode_disco_send_ping()` — Envío de PING cifrado con crypto_box
- `tsnode_disco_stun_request()` — STUN Binding Request (RFC 5389)
- `tsnode_disco_stun_parse_response()` — Parseo de STUN response
- `tsnode_disco_poll()` — Tareas periódicas (STUN cada 30s, reintentos con backoff, keepalive cada 20s)
- `tsnode_disco_get_peer_endpoint()` — Obtener mejor endpoint para WG

### MapResponse parser (`tsnode_map.c`, `tsnode_map.h`)
- Agregado campo `disco_key[32]` a `tsnode_map_peer_t`
- Parsing de `"DiscoKey":"discokey:hex"` desde MapResponse
- Parsing mínimo de `DERPMap` para extraer STUN server (`STUNIPv4`, `STUNPort`)
- Nueva estructura `tsnode_map_stun_t` en el netmap

### Integración en `tsnode_client.c`
- Demultiplexado UDP: magic `TS💬` → disco, resto → WireGuard
- Generación/persistencia de keypair disco en NVS
- Uso de disco key real en MapRequest (reemplaza `zero_disco`)
- Registro de peers disco desde MapResponse
- Polling de disco periódico con STUN server del MapResponse

### Build system (`CMakeLists.txt`)
- Agregado `src/disco/disco.c` al build
- Agregado `src/disco` a `PRIV_INCLUDE_DIRS`

## Decisiones de seguridad tomadas o revisadas

- Disco keypair generado con `crypto->keygen()` (X25519 clamp + mbedTLS)
- Persistencia en NVS con las mismas restricciones que node key (ADR-0003)
- Constant-time comparison para verificación de txid (`ct_memcmp`)
- Nonces generados con `crypto->random()` (entropía criptográfica)
- Crypto_box simplificado: X25519 DH + ChaCha20-Poly1305 (compatible con NaCl)

## Estado de tests

Todos los tests existentes pasan:
- test_h2: 18/18
- test_blake2s: ALL PASS
- test_replay: ALL PASS
- test_wg: all 65 tests passed

## Pendiente / bloqueado

| Item | Estado | Notas |
|------|--------|-------|
| UDP send real | Integrado | `tsnode_port_udp_sendto` en disco_send_ping y handle_packet |
| UDP recv real | Integrado | Demultiplexado en wg_recv_task |
| STUN server | Integrado | Parsing de DERPMap en MapResponse |
| Test hardware | Pendiente | Necesita M5Stack Core 2 con firmware nuevo |
| Control plane polling | Investigando | Segunda consulta Map puede fallar por sesión |

## Próximos pasos

1. **Flash firmware a M5Stack Core 2** y probar:
   - Disco key generada y persistida en NVS
   - Disco key enviada en MapRequest
   - Peers con disco key parseada desde MapResponse
   - STUN request enviado a server del DERPMap
   - PING enviado a peers
   - PONG recibido de peers
   - Ruta directa confirmada
   - WG handshake completa

2. **Diagnosticar control plane polling** si falla la segunda consulta Map

3. **HTTPS server** una vez WG funcione
