# ADR-0021: Map streaming (Stream:true) y autostart del cliente

- Estado: aceptado
- Fecha: 2026-09-06

## Contexto

Dos decisiones de producto pendientes, confirmadas por el usuario en la sesión:

1. **Streaming de netmap.** El cliente usa hasta hoy MapRequest con
   `Stream:false` (polling, ADR-0009/ADR-0020): cada 30s re-POSTea
   `/machine/map`, recibe un netmap completo y lo re-aplica al data plane.
   Esto funciona (GOAL-6: 85 min sin disconnects) pero tiene costos:
   - la consola Tailscale muestra el nodo como "offline / last seen" porque
     el control plane solo recibe requests read-only puntuales con
     `Stream:false` (nota aceptada en GOAL-6);
   - cada poll re-baja el netmap completo (varios KB de JSON) cada 30s;
   - los cambios de peers se detectan con hasta 30s de latencia.
   El protocolo oficial (controlclient/direct.go) usa `Stream:true`:
   un único POST `/machine/map` cuyo response body permanece abierto,
   message-framed `[u32 LE length][payload]`, con el netmap completo como
   primer mensaje y luego deltas (`PeersChanged`/`PeersRemoved`/
   `OnlineChange`) más keepalives `{"KeepAlive":true}`.

2. **Autostart.** Hoy el cliente se arranca solo manualmente vía la consola
   serial (`tsconnect`). El usuario pidió que el nodo arranque solo al boot
   si ya tiene credenciales persistidas (Wi-Fi + auth key en NVS), sin
   consola. Esto además es lo que hace utilizable al nodo como dispositivo
   de campo: puede perder energía y reconectar sin intervención humana.

Se implementan en un solo ADR porque comparten una decisión de seguridad
(consumo de la auth key de un solo uso, §2.3 del AGENTS.md) y porque el
autostart depende de que el cliente pueda re-registrar un nodo existente —
que a su vez es lo que el stream de map formaliza (registrar una vez,
después solo makeRequest con identidad persistida).

## Decisión

### 2a. Streaming del netmap

- `tsnode_map_build_request` con `stream=true` agrega `"KeepAlive":true` al
  JSON del MapRequest solo en modo streaming (equivale a lo que hace
  controlclient/direct.go: `KeepAlive: true` en el request; sirve para que
  el server envíe keepalives periódicas por el stream). No se envía
  `"Compress":"zstd"`: no tenemos decompresor y el server ya nos responde
  JSON crudo (evidencia de GOAL-6, 85 min de JSON sin comprimir).
- `h2_post_stream()` nueva API sobre el cliente h2 existente: igual que
  `h2_post_keepalive()` (PING inline por cada timeout de recv de 10s,
  fail-closed tras `H2_LONGPOLL_MAX_SILENT_PINGS` silencios) pero los
  payloads de frames DATA se entregan a un callback del caller — no se
  acumulan en un buffer de respuesta único. El stream termina con
  `END_STREAM` (retorna `TSNODE_OK`) o falla fail-closed.
- Framing `[u32 LE length][payload]`: el splitter pasa de ser
  "parse one complete record" (`tsnode_map_parse_framed`) a una máquina de
  estados persistente (`tsnode_map_stream_t`) que acumula bytes a través de
  múltiples frames DATA y entrega mensajes completos uno a uno. Un mensaje
  cuyo length declarado excede `TSNODE_MAP_STREAM_BUF` (32 KiB) es un
  error de protocolo → fail-closed. Igual que antes: firma zstd →
  `TSNODE_ERR_NOT_IMPLEMENTED` (sería bug nuestro, ADR-0009 D2).
- `tsnode_map_apply_response()` procesa cada mensaje del stream:
  - **Netmap completo** (el primer mensaje, tiene `Peers` no vacía):
    mismo parseo que hoy (`tsnode_map_parse_response`), reemplazo total del
    netmap. Con él el estado pasa a `TSNODE_CLIENT_ONLINE`.
  - **`PeersChanged`**: upsert de peers (agrega o actualiza en el array),
    se re-aplica a WG + disco.
  - **`PeersRemoved`**: baja los peers del netmap, de WireGuard
    (`tsnode_wg_peer_remove`, nuevo) y de disco
    (`tsnode_disco_remove_peer`, nuevo). Las claves removidas se reportan
    al caller para la limpieza del data plane.
  - **`OnlineChange`**: actualiza `online` de los peers listados.
  - **`KeepAlive:true`**: no-op (el server la manda para mantener el
    stream vivo; despeja el contador de silencio en la capa h2).
  - Un mensaje que no sea nada de lo anterior (ej. cambio de DERPMap,
    PacketFilter, DNS) se ignora sin tocar el netmap — el subset v1 del
    data plane no depende de esos campos.
- `tsnode_client.c`: `do_map_poll()` (un request → un response, re-POST
  cada 30s) se reemplaza por `do_map_stream()` (un request → stream largo).
  El netmap vive en estáticos (`s_netmap` + `s_map_stream`), no en stack.
  Se eliminan los constantes y la lógica del ciclo de poll (jitter, backoff
  por Timeout, sleep con PING cada 20s): el stream one-shot con keepalive
  inline (ADR-0020) absorbe toda esa función.
- **Límite aceptado**: con `Version >= 68` y `Stream:true` el control plane
  trata el request como read-only (ignora Endpoints/Hostinfo para la
  persistencia de rutas). La ruta directa se mantiene por disco (el peer
  aprende nuestro endpoint real del source de nuestros PINGs, ADR-0018),
  y el STUN refresh sigue corriendo al re-establecer cada stream. La
  consola Tailscale puede mostrar nuestro endpoint público algo añejo —
  cosmético, igual que la nota de GOAL-6.

### 2b. Registro una sola vez + identidad persistida

- La identidad (machine key + node key) ya se persiste en NVS. Se agrega un
  flag `regdone` en el mismo namespace: se marca SOLO después de que
  `POST /machine/register` respondió exitosamente.
- En `do_connect()`: si la identidad cargada tiene `regdone`, se **salta el
  registro** (el nodo ya existe; re-registrar con otra auth key sería
  consumir una key de un solo uso innecesariamente y puede fallar). Sin
  `regdone` se registra con la auth key; sin auth key → error
  `TSNODE_ERR_PROVISIONING`.
- `tsnode_client_config_t.auth_key` pasa a ser **opcional** (NULL = usar
  identidad persistida).
- `tsnode_client_forget_identity()` borra también `regdone` (comportamiento
  actual: próximo connect registra nodo nuevo).

### 2c. Consumo de la auth key (seguridad §2.3)

- La auth key es de un solo uso y expira; el autostart la toma de NVS y la
  **borra apenas el nodo alcanza `TSNODE_CLIENT_ONLINE`** (primer netmap del
  stream). Antes de ONLINE la key sigue en NVS protegida por flash+NVS
  encryption (GOAL-7) y es reutilizable en el próximo boot si el arranque
  falló sin siquiera iniciar sesión (caso de recurso legítimo: el nodo no
  llegó a consumirla).
- Nueva API `prov_store_wipe_tskey()` (borra solo `ts_auth_key`, idempotente;
  `prov_store_wipe()` completo sigue existiendo para factory reset).

### 2d. Autostart

- Nuevo `main/autostart.{c,h}`: `autostart_start()` arranca una tarea de
  bajo prioridad que:
  1. Si no hay Wi-Fi + auth key en NVS → sale (el flujo de provisioning por
     consola queda intacto).
  2. Espera a que Wi-Fi conecte (techo 30s; `wifi_app_is_connected`).
  3. Construye el `tsnode_client_config_t` igual que `tsconnect_common()`
     (hostname de MAC, endpoint de la IP WiFi) y llama
     `tsnode_client_start()` si el cliente no está corriendo ya.
  4. Espera hasta `TSNODE_CLIENT_ONLINE` (techo 90s), y al alcanzarlo borra
     la auth key (`prov_store_wipe_tskey`) y termina.
  5. Si no llegó a ONLINE, termina sin borrar la key: el próximo boot
     reutiliza la key si sigue sin consumirse.
- `main.c` llama `autostart_start()` después de `console_start()`.
- La consola (`tskey set`) también dispara `autostart_start()` para el caso
  de provisioning en caliente con Wi-Fi ya conectada.
- Si el usuario arrancó el cliente manualmente, la tarea de autostart solo
  monitorea el estado (no duplica el start) y hace igual el wipe al llegar
  a ONLINE — el consumo de la key es responsabilidad de quien la escribió
  en NVS, no de quién arrancó el cliente.

## Alternativas consideradas

1. **Seguir con polling pero más rápido (p.ej. cada 10s)**: no resuelve la
   visibilidad "offline" en la consola Tailscale (requiere stream) y
   aumenta el tráfico y el consumo de cómputo sin necesidad.
2. **DERP como fallback**: fuera de alcance v1 (ADR-0002; sin ruta directa
   el nodo no conecta y lo reporta).
3. **OmitPeers:true / Stream:false para refrescar endpoints entre streams
   (patrón oficial de direct.go)**: requiere multiplexar DOS streams h2
   concurrentes (el de map abierto + uno puntual), que el h2 mínimo de
   ADR-0009 no soporta. Se postergan con la justificación del "límite
   aceptado" (2a): disco alcanza para el plano de datos y la consola solo
   muestra el endpoint con algo de retraso.
4. **Consumir la auth key sin esperar ONLINE**: prohibido — si el control
   plane tuviera un problema transitorio de red en los primeros segundos,
   el nodo quedaría con una key consumida a medias y sin identidad
   registrada, imposible de reparar sin re-provisioning físico.

## Consecuencias de seguridad

- La auth key (token de registro reutilizable en potencia) queda en NVS el
  menor tiempo posible y se borra al confirmar el registro vía el primer
  netmap. Ya no es necesario recordar borrarla manualmente.
- `regdone` evita re-registrar nodos existentes; combinado con identidad
  persistida, el nodo no porta ni usa auth keys en régimen — solo su node
  key (protegida por flash + NVS encryption, GOAL-7).
- El splitter de stream trata el length declarado por el par como input
  hostil: techo fijo en compile time (32 KiB), zero-copy apuntando al
  buffer estático; un length desbordado o un mensaje zstd son fail-closed.
- El watchdog del stream (10 PINGs silenciosos × 10s) es fail-closed ≤100s,
  idéntico a ADR-0020 — no se relaja la detección de half-open.
- `tsnode_wg_peer_remove`/`tsnode_disco_remove_peer` limpian claves y
  estado de sesión de peers que salieron de la tailnet (evita stale state
  y reduce superficie de ataque a peers desconocidos).
- Sin impacto en la amenaza física (§2.1): autostart no almacena nada
  nuevo; la auth key ya estaba en NVS y ahora se borra antes.

## Consecuencias de estabilidad

- Un stream vivo elimina el ciclo poll/re-POST de 30s: menos toques de
  red, menos posibilidades de errores transitorios, latencia de netmap
  < 1s. La reconexión por stream roto usa el mismo backoff externo base de
  5s (GOAL-6).
- El CPU footprint baja (no hay parseo de netmap completo cada 30s; solo
  deltas). En quiet period el stream recibe keepalive del server ~1/min,
  PING inline propio cada 10s y DATA burst solo ante cambios.
- Nuevas superficies de bug: splitter multi-frame (cubierto por tests de
  framing byte-a-byte), deltas (tests de upsert/remove/onlinechange),
  autostart (tarea acotada en stack y stack de 4 KiB, prioridad baja; la
  tarea se auto-borra y no interfiere con la consola).