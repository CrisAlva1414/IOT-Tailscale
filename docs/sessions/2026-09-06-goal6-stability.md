# 2026-09-06 — GOAL-6 completado: conexión estable 85 min + GOAL-3 validado en hardware

## Contexto

GOAL-6 exige conexión estable del nodo (99.9% uptime, reconnect < 10s). El nodo ya
tenía keepalives entre polls de map (H2 PING 20s, ADR-0009) y de sesión WG (10s,
ADR-0019), pero en corridas largas el **control plane caía cada ~300s** con el ciclo
`map POST failed: 5` → re-POST → `map POST failed: 8` (NETWORK) → `reconnect in 5s`.
Evidencia serial previa (2026-09-06, antes del fix) lo confirmaba.

Causa raíz: el long-poll de `/machine/map` bloqueaba la tarea del cliente hasta 300s
con **cero tráfico saliente**; el binding NAT/firewall moría (~90s de idle) y la muerte
recién se detectaba en el timeout o al reintentar. GOAL-3 (endpoint público STUN en
MapRequest) estaba implementado pero sin validación en hardware.

## Cambios

- **ADR-0020** (`docs/adr/0020-h2-longpoll-ping-keepalive.md`): keepalive HTTP/2 PING
  **durante** el long-poll de `/machine/map`.
- `h2.c/h2.h`: nueva `h2_ping_send()` (PING fire-and-forget, stream 0) y
  `h2_post_keepalive()` (misma conversación que `h2_post()` pero cada timeout de la
  capa de registros envía un PING y continúa; contador de pings silenciosos
  `max_silent_pings` aborta con NETWORK si el par no responde NINGÚN frame —
  fail-closed). `h2_post()` quedó como wrapper con `max_silent_pings=0`
  (comportamiento histórico intacto).
- `tsnode_client.c` `do_map_poll()`: recv timeout del long-poll reducido de 300s a
  `H2_LONGPOLL_PING_S=10s` y POST vía `h2_post_keepalive(..., H2_LONGPOLL_MAX_SILENT_PINGS=10)`
  (detección de half-open ≤100s).
- `tests/unit/test_h2.c`: mock con inyección de timeouts (`tmo_before`/`tmo_repeats`);
  3 tests nuevos: keepalive sobrevive timeouts y devuelve la respuesta completa, límite
  de silencio fail-closed, y regresión `h2_post` con timeout → NETWORK sin PINGs.
  31/31 PASS.
- Sanitización ADR-0010 de IPs reales en docs versionados (PROJECT-GOALS GOAL-5,
  ADR-0017, sesión 2026-09-05) → placeholders `<ip-lan>`/`<ip-tailnet>`/`<hostname>`.
  El detalle operativo real sigue en `docs/private/`.

## Validación en hardware (corrida larga 85 min, 2026-09-06)

Conexión única continua **(1 handshake Noise, 1 `state -> 5` online)** durante
**85 minutos** con `tsconnect`:

- **0 disconnects / 0 reconnects / 0 errores de red** (`msg: map POST failed`,
  `connection lost`, `reconnect in`, `recv header read err=8`).
- 2 MapResponse polls (21520 bytes c/u) completados en la misma conexión.
- **444 timeouts de idle** de la capa de registros absorbidos por el keepalive
  (recv timeout del long-poll = 10s → PING → se sigue esperando), con **443
  registros de 17 bytes** recibidos (frames h2 PING/ACK del control plane) —
  el binding NAT nunca venció.
- Plano de datos verificado en hitos: `tailscale ping -> pong directo vía
  <ip-lan>:51820` a los 15, 30 y 60 min; 1326 WG keepalives de sesión emitidos;
  86 disco PING / 12 disco PONG.
- STUN (GOAL-3): `poll: stun=<stun-public>:3478 n_peers=4` en **ambos** MapRequest
  (2/2) — el endpoint público STUN se reporta, no la IP LAN.

Diferencia con el firmware anterior: el ciclo viejo era timeout~300s → re-POST →
NETWORK → reconnect cada ~300s (antes del fix, en la misma sesión, se observaron
`map POST failed: 5` y `recv header read err=8` en serie).

## Decisiones de seguridad tomadas o revisadas

- ADR-0020 mantiene el modelo de §2: los PINGs viajan dentro del túnel ts2021
  cifrado; la detección de conexión muerta es fail-closed (≤100s de silencio →
  NETWORK) y el contador no penaliza un par sano (RFC 7540 §6.7 obliga al ACK).
- Se revisó el riesgo de desync de la capa de registros ante un timeout a mitad de
  registro (bytes parciales descartados por `ts2021_record_recv`): el peer entrega
  registros completos en ráfagas cortas; un corte >10s a mitad de registro no se
  observó en 444 ciclos y, si ocurriera, el fallo de decrypt derivaría en NETWORK
  (fail-closed, reconexión) — sin superficie de corrupción silenciosa.

## Pendiente / bloqueado

- Nada bloqueado. Observación conocida y aceptada (cosmética, ya documentada en
  GOAL-6 y GOAL-5): la consola Tailscale muestra el nodo "offline / last seen"
  porque el MapRequest usa `Stream:false` (deltas no parseables, ver estado de
  GOAL-6). No afecta el criterio de GOAL-6 (conexión + data plane medidos en el nodo).
- Corrida de >24h como prueba de envejecimiento (opcional, futura sesión).
- GOAL-7 (flash encryption Release) sigue pendiente de flasheo en hardware — out of
  scope de esta sesión.