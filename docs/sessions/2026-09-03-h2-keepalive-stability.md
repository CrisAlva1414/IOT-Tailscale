# 2026-09-03 — H2 PING keepalive para estabilidad del control plane (GOAL-6)

## Contexto

GOAL-6 (conexión estable, 99.9% uptime) seguía en PARTIAL. El síntoma observado en
hardware (sesión de estabilización del control plane) es un ciclo de ~90s online /
~5s reconectando. La causal hipotetizada por esa sesión: NAT/firewall derriba la
conexión TCP del control plane tras ~90s de idle entre polls de map. El TCP keepalive
lwIP añadido antes (idle=60s) no alcanzaba: como los polls ocurren cada 30s, la
conexión nunca está "idle" los 60s completos, así que el keepalive TCP nunca dispara
antes de que el NAT derribe el flujo.

## Cambios

- **`components/tsnode/src/proto/h2.{c,h}`**: nueva API `h2_ping()`. Envía un frame
  PING HTTP/2 (stream 0) con payload opaco fijo de 8 bytes y espera el ACK del par
  (el ACK repite el payload). Responde PONG a PINGs entrantes del server y procesa
  SETTINGS/WINDOW_UPDATE/PRIORITY; fail-closed (NETWORK) ante GOAWAY/DATA fuera de
  stream/frames desconocidos. Esto está dentro del subset H2 documentado por
  ADR-0009 D1 ("PING (→PONG)").
- **`components/tsnode/src/proto/tsnode_client.c`**: keepalive en el poll loop. El
  sleep idle entre polls ahora corre en chunks de 1s y, cada `H2_PING_IDLE_S = 20s`
  de idle, envía `h2_ping()`. Si el keepalive falla, entra en el backoff de
  reconexión existente (se cuenta como error de poll; 3 fallos → reconnect).
- **`tests/unit/test_h2.c`**: 4 casos nuevos — ACK del keepalive, PING entrante del
  server respondido con PONG antes del ACK propio, EOF sin ACK → NETWORK, y h2_ping
  sobre conexión no iniciada → INVALID_ARG.

## Decisiones de seguridad tomadas o revisadas

- El payload del PING es opaco y **no criptográfico** (RFC 7540 permite cualquier 8
  bytes): solo identifica el ACK a nuestro PING. No revela secretos; viaja dentro del
  túnel Noise autenticado (IK), por lo que no añade superficie fuera del túnel.
- `h2_ping` mantiene el subset fail-closed de h2: cualquier frame fuera de lo
  soportado → err → reconexión. No degrada silenciosamente.
- El keepalive no envía secretos ni claves; solo un frame de control H2 estándar.
- No cambia el almacenamiento de claves ni el modelo de amenaza físico (§2.1).

## Pendiente / bloqueado

- **Validación en hardware (bloqueante para marcar GOAL-6 COMPLETED)**: flash en el
  ESP32, observar en `tailscale status` / dashboard si el nodo se mantiene online > 1h
  sin el ciclo de ~90s. El valor `H2_PING_IDLE_S=20` se calibra con esa medición: si
  el NAt timeout fuera menor a ~90s, puede requerirse bajar a 10s; si el problema no
  es NAT sino del lado server o del parseo h2, los logs de "h2 keepalive ping failed"
  lo van a revelar y se reabre el diagnóstico (p.ej. investigar `Stream=true`).
- Reconnect < 10s ya se cumple (5s de backoff base).

## Próxima sesión

1. Flashear y probar en hardware con ruta directa.
2. Correlacionar `tailscale status` con los logs de keepalive para confirmar la
   hipótesis NAT y calibrar `H2_PING_IDLE_S`.
