# 2026-09-06 — map-streaming-autostart

## Contexto

Continuar ADR-0021 (aceptado esta sesión): migrar el cliente del long-poll
de `/machine/map` (ADR-0020, `Stream:false`) al stream long-lived
(`Stream:true` con deltas y keepalives), y agregar autostart del cliente al
boot con registro único (flag `regdone`) y consumo/borrado de la auth key de
un solo uso. Esto resuelve además la nota cosmética de GOAL-6 (nodo
"offline / last seen" en la consola por usar `Stream:false`).

## Cambios

- `components/tsnode/src/proto/tsnode_map.{c,h}`:
  - Splitter de stream `tsnode_map_stream_t` (`init/feed/next`) con techo
    fijo `TSNODE_MAP_STREAM_BUF=32768`. Fix de bug real detectado por test:
    `next()` entregaba puntero a `st->buf+4` y el `memmove` de consumo
    destruía el contenido; ahora entrega sin mover y consume en la próxima
    llamada (campo `pending`).
  - `tsnode_map_apply_response()`: netmap completo (replace), deltas
    `PeersChanged` (upsert), `PeersRemoved` (array `nodekey:`), `OnlineChange`
    (flag), KeepAlive (no-op). Devuelve `removed[][32]`/`n_removed`.
  - `tsnode_map_build_request()` agrega `"KeepAlive":true` solo cuando
    `stream==true` (ADR-0021 2a).
- `components/tsnode/src/proto/h2.{c,h}`: nueva `h2_post_stream()` (POST
  one-shot + callback `on_data` por frame DATA + PING inline + fail-closed
  por silencio ≤100s, mismo espíritu que ADR-0020).
- `components/tsnode/src/wg/wg.{c,h}`: `tsnode_wg_peer_remove()` (wipe del
  slot, índices NO se reordenan — los arrays lógicos del cliente están
  alineados por slot).
- `components/tsnode/src/disco/disco.{c,h}`: `tsnode_disco_remove_peer()`
  (shift compacto, idempotente).
- `components/tsnode/src/proto/tsnode_client.{c,h}`:
  - Identidad: `load_identity(mach, node, &regdone)`; `mark_registered()`;
    `forget_identity()` borra también `regdone`. El registro solo ocurre sin
    `regdone`; con `regdone` se salta (auth key ya consumida). `auth_key`
    ahora OPCIONAL en `tsnode_client_config_t` (NULL = autenticar por node
    key persistida).
  - Stream: `do_map_poll()` reemplazado por `do_map_stream()`; netmap vivo en
    estáticos `s_netmap` + `s_map_stream` (32 KiB fuera de stack); handler de
    mensajes aplica deltas, re-aplica WG/disco, y `PeersRemoved` limpia el
    data plane (wg_peer_remove + disco_remove_peer + arrays de endpoint).
  - `tsnode_client_start()` ya no exige auth key; sin key y sin identidad
    registrada → `TSNODE_ERR_PROVISIONING` claro en `do_connect()`.
- `main/prov_store.{c,h}`: `prov_store_wipe_tskey()` (borra solo la auth key;
  wifi e identidad intactas; idempotente).
- `main/autostart.{c,h}` (nuevo): `autostart_start()` en tarea de baja
  prioridad — espera WiFi (30s), arranca cliente, espera ONLINE (90s), y
  solo ahí borra la auth key (2c). No duplica si el cliente ya corre.
- `main/main.c`: llama `autostart_start()` tras `console_start()`.
- `main/console.c`: `tskey set` re-dispara autostart; `tsconnect` acepta
  ausencia de auth key (identidad registrada es suficiente, ADR-0021).
- `main/CMakeLists.txt`: registra `autostart.c`.
- `tests/unit/test_h2.c`: 14 tests nuevos (splitter mono/byte-a-byte/
  multi-mensaje/overflow declarado/overflow acumulador/zstd, apply
  full/upsert/update/removed/online/keepalive/args, KeepAlive solo en
  stream) → 45/45 PASS.
- `docs/adr/0021-map-streaming-and-autostart.md` (aceptado).

## Decisiones de seguridad tomadas o revisadas

- Splitter de stream trata el length declarado del par como input hostil:
  jamás indexa con él; techo fijo en compile time, rechazo `NETWORK`/`NO_MEMORY`.
- El fix del puntero del splitter evita un use-after-memmove (corrupción de
  mensajes entregados) — encontrado por los tests, no en campo.
- `PeersRemoved` limpia TODOS los rastros del peer en el data plane (WG,
  disco, endpoint lógico) — un peer removido no debe seguir recibiendo
  tráfico ni mantener estado.
- Auth key de un solo uso: se borra de NVS solo tras alcanzar ONLINE (nunca
  por timeout especulativo). Key nunca logueada.
- `regdone` marca el registro completado; jamás se re-registra con la misma
  identidad (evita consumir auth keys nuevas en cada reboot).

## Pendiente / bloqueado

- Prueba en hardware real del stream (verificar en `tailscale status` que el
  nodo queda "active" con deltas y que `tsconnect` post-reboot conecta sin
  auth key). Flashear build para validar.
- Más adelante: considerar `h2_post_keepalive()` como API obsoleta (solo la
  usan tests) y decidir si se mantiene documentada o se retira.