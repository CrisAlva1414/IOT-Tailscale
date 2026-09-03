# 2026-09-03 — Control plane stabilization: reconnection loop + socket fixes

## Contexto

El nodo ESP32 aparecía online en el dashboard de Tailscale por ~3 minutos y luego
desaparecía sin posibilidad de reconexión. Investigación a fondo con 4 agentes
paralelos reveló causas raíz en el código.

## Problema principal (síntoma observable)

El `client_task` moría silenciosamente cuando la conexión TCP al control plane
se caía (timeout NAT/firewall después de ~90s de idle). Sin loop de reconexión,
sin feedback al usuario, sin posibilidad de recuperación.

## Causas raíz encontradas

### Bloque 1 — "Offline a los ~3 min"
- **1a**: `client_task` sin loop de reconexión. `do_connect()` falla una vez →
  `ERROR` + `task_delete_self()`. 3 errores de `do_map_poll` → cierra conexión,
  muere. El comentario decía "reconnecting" pero no reconectaba.
- **1b**: `tsnode_port_socket_read` ignoraba `timeout_ms` para TCP plano
  (`mbedtls_net_recv` sin timeout) → bloqueo infinito en conexión muerta.
- **1c**: Sin keepalive TCP/Noise → NAT/firewall derribaba la conexión idle.

### Bloque 2 — "EADDRINUSE 51820"
- **2a**: Socket UDP 51820 se filtraba en TODOS los paths de error de
  `do_connect()` y en `vTaskDelete()` (no cierra fds).
- **2b**: Sin `SO_REUSEADDR` → rebind falla con EADDRINUSE.

### Bloque 3 — "Nodo inalcanzable" (no resuelto en esta sesión)
- **3a**: Endpoint reportado es IP local WiFi (`192.168.x.x`), no la pública.
- **3b**: STUN descubierto nunca se usa en MapRequest.
- **3c**: STUN server field `"STUNIPv4"` no existe en MapResponse real.

### Bloque 4 — "Disco incompatible" (no resuelto en esta sesión)
- **4a (CRÍTICO)**: Crypto ChaCha20-Poly1305+nonce12B vs XSalsa20+nonce24B de
  Tailscale (NaCl crypto_box). Ningún PING/PONG se descifra.
- **4b (CRÍTICO)**: Buffer overflow en PONG (`TSNODE_DISCO_PONG_LEN=30`, debe
  ser 32). Escritura OOB en `pong_plain[30]`/`[31]`.
- **4c**: `ct_memcmp` sigue en uso para disco keys pese al fix documentado.
- **4d**: STUN txid no se guarda ni verifica.

## Cambios implementados (Fase A+B)

### tsnode_port_net_esp_idf.c
- **A2**: `SO_RCVTIMEO` en TCP socket tras `mbedtls_net_connect()` para que
  `mbedtls_net_recv` respete timeout y no bloquee para siempre.
- **A2extra**: `tsnode_port_socket_read` ahora aplica `SO_RCVTIMEO` por llamada
  para sockets no-TLS, usando el `timeout_ms` que antes ignoraba.
- **A3**: TCP keepalive en el socket TCP (idle=60s, intvl=10s, cnt=3) para
  prevenir que NAT/firewall derribe la conexión idle entre polls.
- **B2**: `SO_REUSEADDR` en el bind UDP para permitir rebinding inmediato
  si un socket viejo aún sostiene el puerto.

### tsnode_client.c
- **A1+B1**: `cleanup_session()` — nueva función que cierra conexión, UDP socket,
  resetea h2 pushback y estado disco entre intentos de reconexión.
- **A1**: `client_task()` reestructurado con loop de reconexión externo:
  ```
  while (state != IDLE):
    cleanup_session()
    do_connect() → poll loop → on failure: backoff + retry
  ```
  Backoff: 5s → 10s → 20s → 40s → 60s (cap). Sleeps en chunks de 1s
  para que `tsnode_client_stop()` sea responsivo.
- **B1**: Socket leak eliminado — `cleanup_session()` se llama en todos los
  paths de salida (error de connect, muerte del poll loop, stop externo).

## Verificación en hardware (M5Stack Core 2)

| Métrica | Antes | Después |
|---------|-------|---------|
| Primer MapResponse | OK | OK |
| Segundo poll (~30s) | Falla (timeout bloqueante) | OK |
| Tercer poll (~60s) | — | OK |
| Cuarto poll (~90s) | — | Falla (conexión TCP muere) |
| Recuperación | Task muere permanentemente | **Reconexión automática en 5s** |
| EADDRINUSE en reconnect | Sí (espera ~8s manual) | No (SO_REUSEADDR) |
| Estado visible | Sin feedback | Log: "reconnect in 5s" |

El nodo ahora se mantiene Online de forma intermitente (ciclo: ~90s online →
5s de reconexión → ~90s online). El control plane funciona. El data plane
(WireGuard) no se establece aún por los bugs de Fase C+D.

## Decisiones de seguridad

- TCP keepalive (60s) es conservador: prevenir drops de NAT sin gastar
  bandwidth excesivo en un IoT.
- SO_REUSEADDR es defensa en profundidad; no aumenta la superficie de
  ataque significativamente.
- El read timeout (10s) se mantiene del diseño original; no se acortó
  para no perder respuestas legítimas del control plane.

## Pendiente / próximo

| Item | Estado | Esfuerzo |
|------|--------|----------|
| **C1: Endpoint reporting** — reportar IP pública STUN en vez de local | Pendiente | MEDIO |
| **D1: XSalsa20-Poly1305** — crypto_box compatible con Tailscale | Pendiente | ALTO (~400 LOC) |
| **D2: PONG buffer** — `PONG_LEN=32`, quitar OOB | Pendiente | BAJO |
| **D3: ct_memcmp** — reemplazar por memcmp | Pendiente | BAJO |
| **D4: STUN txid** — guardar y verificar | Pendiente | BAJO |
| Control plane muere ~90s — investigar Stream=true o H2 PING | Pendiente | MEDIO |
| ADR para crypto NaCl | Pendiente | BAJO |

## Próxima sesión

1. Implementar `nacl_box` module (XSalsa20-Poly1305 + HSalsa20)
2. Fix endpoint reporting (C1)
3. Fix PONG buffer + ct_memcmp (D2+D3)
4. Flash y probar `tailscale ping` desde el notebook
