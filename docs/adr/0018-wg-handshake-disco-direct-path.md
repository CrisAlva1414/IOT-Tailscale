# ADR-0018: El handshake WG usa la ruta directa confirmada por disco

- Estado: aceptado
- Fecha: 2026-09-05

## Contexto

ADR-0017 fijó que `update_wg_peers` usara `endpoints[0]` del MapResponse como
destino del handshake WG de arranque ("el primer endpoint, típicamente el
LAN-privado cuando existe"). En hardware esto resultó insuficiente:

- El parser conserva hasta 16 endpoints por peer; el orden que emite el control
  plane no siempre pone el LAN-privado primero (para los peers reales la IP
  pública aparece al inicio de la lista).
- Cuando disco confirma una ruta directa (recibe un PONG de una IP:port
  concreta), esa es la ruta **verificada** por un peer que respondió al PING
  autenticado. Seguir mandando el handshake WG a `endpoints[0]` puede fallar
  cuando ese endpoint es el público y el NAT local no tiene hairpin: el
  dispositivo recibe `RX init=0` y nunca establece sesión aunque exista una
  ruta LAN-LAN ya probada por disco.

## Decisión

- `tsnode_disco_peer_t` conserva la `direct_ip`/`direct_port` de la fuente del
  último PONG válido (txid coincidente con el `pending_txid` emitido por el
  PING del nodo). Se guardan al encajar el PONG, no confiando en el campo
  `ip16` del payload para el *destino* del handshake (ese campo describe al
  emisor; la fuente del datagrama UDP es la ruta realmente navegada).
- `update_wg_peers` selecciona el endpoint del handshake WG así:
  1. Si disco tiene ruta directa confirmada para ese peer (por WG key vía
     `tsnode_disco_find_peer_by_wg_key` + `tsnode_disco_get_peer_endpoint`),
     se usa esa IP:port.
  2. Si no, fallback al primer endpoint parseado del MapResponse
     (`endpoints[0]`), como en ADR-0017.
- `tsnode_disco_get_peer_endpoint` ahora devuelve primero `direct_ip:direct_port`
  y solo cae a `endpoints[0]` como fallback defensivo si `direct_path_ok` quedó
  seteado pero no hay ruta guardada (estado transitorio/imposible por
  construcción, pero no se asume).
- Se agrega logging diferenciado: `WG TX init -> <ip>:<port> (disco direct)`
  cuando se usa la ruta de disco.

## Alternativas consideradas

- **Seguir con `endpoints[0]`** (ADR-0017): insuficiente en hardware real por
  el orden de endpoints del control plane; ver contexto.
- **Reintentar el handshake contra todos los endpoints secuencialmente en el
  arranque síncrono**: descartado en ADR-0017 por presupuesto de tiempo real y
  duplicación de la lógica que disco ya cubre; el cambio de este ADR es
  ortogonal (usa el resultado asíncrono de disco cuando ya existe).
- **Actualizar `endpoints[0]` en disco al confirmar el PONG**: modifica datos
  del mapa reportados al control plane; la ruta directa no debe mezclarse con
  el endpoint declarado. Se prefiere un campo separado.

## Consecuencias de seguridad

- La ruta directa **solo** se acepta si el PONG descifra con la disco key del
  peer registrado (fail-closed en `nacl_box`) **y** el txid coincide con el
  emitido por este nodo (anti-replay de mensajes disco). Un endpoint falso no
  puede desviar el handshake WG sin la disco key del peer, y la autenticación
  final del par sigue recayendo en el handshake Noise/WireGuard contra la
  public key del peer provista por el control plane firmado (sin cambio en ese
  modelo, ADR-0017 §Consecuencias de seguridad).
- `src_ip`/`src_port` del PONG son input hostil como cualquier datagrama; solo
  se usan como destino de sendto, nunca para autenticar. El fallback a
  `endpoints[0]` parseda con `sscanf` estricto sigue intacto.
- Sin cambio en §2.1 (físico): no se persiste la ruta directa en NVS.

## Consecuencias de estabilidad

- Estado transitorio resuelto sin memoria dinámica: `direct_ip/direct_port`
  son campos fijos del struct de peer (acotado en compile time).
- Un PONG posterior de otra IP:port del mismo peer (p.ej. cambio de puerto NAT)
  actualiza la ruta directa; el handshake usa el último destino verificado.
- Remueve un modo de fallo silencioso observado en hardware (handshake a un
  endpoint público con NAT sin hairpin → sin sesión WG pese a ruta LAN
  disponible).