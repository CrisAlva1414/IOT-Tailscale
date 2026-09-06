# 2026-09-05 — GOAL-5 completado: ping end-to-end validado en hardware

## Contexto

GOAL-5 pedía `ping 100.x.x.x` desde la tailnet con respuesta del ESP32.
El data plane WireGuard ya establecía sesiones pero no fluía tráfico real
(sesiones "ESTABLISHED" mudas) y el path de responder fallaba
intermitentemente. Esta sesión cerró ambos bugs y validó el ping
end-to-end en hardware real (notebook → esp32-8219d4).

## Cambios

- `components/tsnode/src/proto/tsnode_client.c` — keepalive de sesión WG:
  `wg_send_keepalive()`, contador `tx_keepalive`, `s_wg_last_tx_ms[]`,
  envía un transport data vacío (32 B) justo después de `ESTABLISHED` y
  cada 10 s de idle por peer (`WG_KEEPALIVE_IDLE_MS`). Se integró en la
  tarea de retransmisión (`wg_retransmit_pending`).
- `components/tsnode/src/wg/wg.c` — `tsnode_wg_create_response` usa
  `cr->keygen()` (escalar clampeado) en vez de `random()+pubkey()`.
- `components/tsnode/src/port/esp_idf/x25519_wrapper.c` — clamp RFC 7748
  completo: bit 255 en 0 (faltaba; mbedTLS rechaza escalares bitlen 256
  con `BAD_INPUT_DATA -0x4c80`), defensivo también en `shared()`.
- `components/tsnode/src/port/tsnode_port.h` (+ impl en
  `tsnode_port_esp_idf.c`) — API de mutex del device WG (ADR-0011) para
  serializar la tarea UDP y la tarea del cliente.
- `docs/adr/0019-wg-session-keepalive-and-mbedtls-x25519-clamp.md` — ADR
  nuevo con el porqué de ambos fixes.

## Decisiones de seguridad tomadas o revisadas

- El keepalive WG es un transporte autenticado de 32 B: solo peers con
  sesión válida lo disparan; no abre superficie (ver ADR-0019).
- El clamp del escalar X25519 es conforme a RFC 7748 §5 (X25519 clampea
  su escalar por definición); mbedTLS era más estricto que la spec.
  Determinista, idempotente, no degrada el secreto compartido.
- Se detectó y reporta (no como bug del proyecto sino de operación) que el
  rekey del notebook podía fallar con "no UDP or DERP addr" en intervalos
  de churn de endpoint de magicsock; es transitorio y se autorecubre.

## Validación en hardware (resumen de evidencia serial del ESP32)

- Sesión vía nuestro init + respuesta del notebook:
  `WG RX resp #1 from 192.168.1.100:41641 len=92` → `ESTABLISHED peer=0`
  → keepalive inmediato → `WG ICMP echo reply #1..#3` (pings reales).
- Path de responder (rekey natural del notebook, ~120 s):
  `WG RX init #1 from 192.168.1.100:41641 len=148` →
  `WG response sent` (sin `-0x4c80`) → pong en `tailscale ping`
  (1.581 s primer paquete) → RTT kernel `ping` ~10 ms en régimen.
- Keepalives bidireccionales: `WG RX keepalive #2 peer=0` del notebook y
  `WG TX keepalive #N peer=0` nuestros cada 10 s.
- `tailscale status`: `esp32-8219d4 ... active; direct 192.168.1.104:51820`
  (el `offline, last seen 1h` es el heartbeat del control plane, cosmético).

## Pendiente / bloqueado

- Pendiente: GOAL-6 (estabilidad >1 h sin ciclos de 90 s) requiere una
  corrida larga con el keepalive H2 (ya implementado) + los nuevos
  keepalives WG de esta sesión. Correr `status` periódicamente y medir.
- Cosmético: `tailscale status` muestra el nodo como "offline, last seen"
  por heartbeat del control plane aunque el plano de datos esté activo;
  revisar la cadencia/estado del long-poll de map si se quiere el nodo
  "online" en la consola.
- Operativo: el rekey del notebook depende de que magicsock tenga
  endpoint confirmado; no requiere acción de nuestro lado.