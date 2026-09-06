# ADR-0020: Keepalive HTTP/2 PING durante el long-poll de /machine/map

- Estado: aceptado
- Fecha: 2026-09-06

## Contexto

GOAL-6 exige conexión estable con el control plane (>1h sin ciclos, reconnect
rápido). El nodo tiene dos keepalives previos (ADR-0009 D1 PING h2 de 20s en la
ventana de sleep entre polls; ADR-0019 keepalive WG de sesión de 10s para el
data plane). Ambos verificados en hardware: el data plane WG responde
`tailscale ping` directo por LAN.

Sin embargo, en corrida larga de hardware el **control plane sigue cayendo**:
el poll loop de `/machine/map` hace un long-poll que deja el stream HTTP/2
abierto esperando cambios de netmap. Hasta 2026-09-06 el cliente bloqueaba en
`h2_post` con un recv timeout de 300s y **cero tráfico saliente durante ese
long-poll** (el PING de 20s solo corre en la ventana de 30s entre polls, no
durante los hasta-300s bloqueados). Evidencia de hardware (serial, 2026-09-06):

```
recv timeout set to 300000 ms   <- long-poll, bloqueado SIN tráfico saliente
... 300s de silencio ...
recv header read err=5          <- timeout del long-poll
map long-poll idle timeout re-POSTing (backoff=0s, count=1)
recv timeout set to 300000 ms   <- re-POST
recv header read err=8          <- NETWORK: la conexión murió durante el silencio
map POST failed: 8
map poll connection lost (net) — reconnecting
reconnect in 5s
```

La secuencia (timeout → re-POST → NETWORK → reconnect) reemplazó el ciclo
original de 90s por un ciclo de ~300s: el mapping NAT/firewall se derriba por
idle durante el long-poll silencioso y solo se descubre al reintentar. El TCP
keepalive de 60s del socket (fix A3) no alcanzó a mantener el binding en la
red del banco de pruebas.

## Decisión

Enviar frames HTTP/2 `PING` (stream 0) **durante** el long-poll de `/machine/map`,
desde la misma tarea, sin concurrencia:

1. Nueva primitiva `h2_ping_send()` en `h2.c`: envía un frame PING keepalive
   (payload opaco fijo de 8 bytes, `0x74736e6f64655031`) sin esperar ACK. Es
   la mitad "enviar" del `h2_ping()` existente, que se refactoriza para
   reutilizarla (envía + espera ACK).
2. Nueva variante `h2_post_keepalive()` en `h2.c`: igual a `h2_post()` pero,
   cuando el recv de la capa de registros devuelve `TSNODE_ERR_TIMEOUT` (idle
   mayor al recv timeout configurado por el caller), envía un `h2_ping_send()`
   y continúa esperando la respuesta del long-poll. Un contador de pings
   consecutivos sin recibir NINGÚN frame acota la detección de conexiones
   muertas en half-open (NAT que traga paquetes sin RST): tras N pings sin
   ninguna recepción devuelve `TSNODE_ERR_NETWORK` (detección acotada ~100s).
3. `do_map_poll()` en `tsnode_client.c` configura el recv timeout del long-poll
   a `H2_LONGPOLL_PING_S = 10s` (antes 300s) con `ts2021_set_recv_timeout()`,
   llama `h2_post_keepalive()` en vez de `h2_post()`, y restaura 10s al salir.

Efectos esperados:

- Tráfico saliente autenticado (dentro del túnel ts2021/Noise) cada ≤10s durante
  el long-poll → el mapping NAT/firewall nunca vence (~90s observado); el
  control plane recibe actividad regular.
- El long-poll ya no "vence" a los 300s: se mantiene abierto hasta que el
  control plane envíe un cambio de netmap (comportamiento del cliente oficial),
  eliminando el ciclo timeout→re-POST.
- Muerte de conexión detectada por: (a) error de red en el envío del PING, o
  (b) contador de pings sin recepción. Reconnect en ≤5s (backoff base) tras la
  detección.

## Alternativas consideradas

1. **Bajar el recv timeout del long-poll a ~45s y re-POSTear caducado** (topología
   de re-POST ya existente). Se descartó: el re-POST abandona el stream previo; si
   el control plane responde después en el stream viejo, `handle_frame` falla con
   stream_id distinto (fail-closed) → reconexión espuria. Exigía RST_STREAM del
   stream abandonado y tracking de streams, más superficie.
2. **Tarea dedicada que envíe PINGs concurrentemente** con `h2_post`. Se descartó:
   el envío comparte el estado de la conexión ts2021 (tx_counter, socket) y
   requeriría mutex + manejo del ACK en la tarea bloqueada; riesgo de interleaving
   de frames y uso de stack adicional (8 KB de tarea) en el C3.
3. **No hacer nada** (confiar en TCP keepalive A3). Refutado por evidencia de
   hardware: el ciclo timeout→re-POST→NETWORK se observó en corrida real.

## Consecuencias de seguridad

- Los PINGs viajan dentro del túnel cifrado ts2021 con el nonce/contador de
  recepción controlado; no agregan superficie de parseo de input hostil nuevo
  (el frame PING ya era soportado por `handle_frame` en el recv path).
- La detección de conexión muerta por contador de silencio es fail-closed: si el
  control plane deja de responder (170s máx de silencio con `H2_LONGPOLL_PING_S=10`
  y `H2_LONGPOLL_MAX_SILENT_PINGS=10`... 100s), se cae y reconecta en vez de
  quedarse en half-open enviando datos al vacío. Sin este ADR el half-open
  autorrenovado por pings al vacío podría durar indefinidamente.
- El contador de pings sin recepción no penaliza un peer sano: el RFC 7540 §6.7
  obliga al par a ACKear cada PING; un control plane que cumple el spec reinicia
  el contador con cada ACK recibido.

## Consecuencias de estabilidad

- Elimina el ciclo de reconexión periódico (antes ~300s) que causaba resets de
  sesión del control plane en corridas largas.
- Costo de red: ~6 PINGs/min durante el long-poll, 64 B autenticados c/u
  (~23 KB/h) — despreciable en RAM/CPU/flash, y dato plano: el dispositivo ya
  emite keepalives WG de 10s por peer.
- Carga extra de CPU: un AEAD chacha20-poly1305 de 24 bytes cada 10s — ruido
  (<0.1% del presupuesto de crypto; ver ADR-0019 para la medición de timing).
- Si el control plane de Tailscale dejara de ACKear PINGs (comportamiento no
  estándar), el nodo reconectaría cada ~100s; observado hoy: el ACK llega
  (el test `test_h2_ping_gets_ack` y la ausencia de reconexiones largas lo
  respaldan). Se monitorea en GOAL-6.