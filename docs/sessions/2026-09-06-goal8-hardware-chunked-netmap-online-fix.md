# 2026-09-06 — GOAL-8 validado en hardware: fix del netmap inicial en chunks (ONLINE + wipe de auth key)

## Contexto

GOAL-8 (ADR-0021: streaming de `/machine/map` con deltas + autostart + registro único) estaba
comiteado y con tests en verde, pero sin validar en hardware. Al flashear (`5e87ff7`) y dejar que
el autostart hiciera su ciclo, la consola del dispositivo mostraba el problema inverso al esperado:

- El **data plane funcionaba** perfecto: se agregaban peers a WG (`WG peer added` ×4, `n_peers=4`),
  disco respondía PING/PONG, `tailscale ping` y `ping` end-to-end OK, nodo figuraba activo/idle en
  la tailnet.
- Pero el autostart logueaba `sin ONLINE en 90s — la auth key se conserva`, la auth key seguía en
  NVS (`provision status` → `auth key: cargada`) y el estado del cliente quedaba en MAP_SYNC (4).

## Hallazgo (causa raíz)

Con `Stream:true`, el control plane moderno entrega el **netmap inicial en chunks, como deltas**
(`PeersChanged`), **sin** pasar por el `"Peers":[...]` full que manda en modo poll (Stream:false).
El handler `map_stream_handle_message()` solo marcaba `TSNODE_CLIENT_ONLINE` en el camino
`is_full` (`"Peers":[` detectado). Como el full nunca llega en streaming moderno, el cliente se
quedaba en MAP_SYNC para siempre: `s_stream_has_full` (ahora `s_stream_initialized`) nunca se
seteaba, y el wipe del tskey de 2c del ADR-0021 jamás se ejecutaba. El data plane no dependía de
esa transición (los deltas upsert ya agregaban peers), por eso el síntoma era "todo funciona salvo
el reporte de estado/autostart".

## Cambios

- `components/tsnode/src/proto/tsnode_client.c`:
  - `map_stream_handle_message()`: nuevo branch de **inicial en chunks** — si el netmap no estaba
    inicializado y el mensaje trae contenido real (peers actualizados o removidos, no solo
    `OnlineChange`/KeepAlive), marca `s_stream_initialized`, loguea `netmap (stream, deltas)` y
    pasa a `TSNODE_CLIENT_ONLINE`. Se conserva el path full (modo resync).
  - Renombre `s_stream_has_full` → `s_stream_initialized` (el flag ahora significa "netmap
    entregado", no solo "full visto") y comentario de la función actualizado.
- `tests/unit/test_h2.c`: nuevo `test_map_apply_chunked_initial_only` — fija el contrato del
  parser sobre netmap vacío: el primer `PeersChanged` chunk reporta `is_full=false` +
  `peers_updated=true` y aplica los peers (base del comportamiento de ONLINE del cliente).
  45/46 checks en test_h2 (un test nuevo).

## Validación (hardware, 2026-09-06)

Rebuild + flash al M5Stack y boot limpio:

- `netmap (stream, deltas): 4 peers` → `state -> 5` (ONLINE).
- `ONLINE — auth key de un solo uso borrada de NVS (ADR-0021 2c)`; `provision status` →
  `auth key: no cargada`.
- `tailscale status` → nodo `active; direct` con contadores de tráfico; `ping` 3/3 (0% pérdida),
  `tailscale ping` directo.
- Tests host 7/7 bins PASS; build IDF `-Werror` PASS; cppcheck exit 0.

## Decisiones de seguridad revisadas

- El fix **no cambia el modelo de amenaza**: la detección de "netmap entregado" requiere contenido
  real (upsert o remoción de peers), no cualquier mensaje del stream; un `OnlineChange` aislado o un
  KeepAlive no disparan ONLINE ni el wipe del tskey (no se borra la key a ciegas por un mensaje que
  no implica registro consumido).
- El wipe de la auth key de un solo uso (ADR-0021 2c) ahora **se ejecuta como fue diseñado**:
  reduce material reutilizable en reposo en el ciclo de boot/registro único.

## Pendiente / observaciones

- Observación menor (cosmética): `main/console.c` `status` muestra `tsnode: INITIALIZED` porque el
  estado app-level no se alimenta desde el camino de autostart. No afecta la tailnet ni el
  autostart. Y si querés, limpiar en otra sesión.
- GOAL-7 (flash encryption Release) sigue pendiente de flasheo deliberado en hardware (eFuse
  irreversible; decisión del operador).
- Corrida >24h (aging) sigue siendo una validación opcional futura.