# ADR-0017: Multi-endpoint por peer (endpoints LAN-privados + públicos)

- Estado: aceptado
- Fecha: 2026-09-03

## Contexto

El parser de MapResponse (`tsnode_map_parse_response`) solo conservaba el
**primer** endpoint de cada peer (`tsnode_map_peer_t.endpoint_ip/endpoint_port`
eran campos únicos). Tailscale devuelve por peer una lista `"Endpoints":[...]`
que normalmente incluye:

1. El endpoint LAN-privado (p.ej. `<ip-lan>:41641`), útil si el ESP32 y el
   peer están en la misma LAN.
2. El endpoint público del router de cada lado (p.ej. `<ip-public>:41641`).

El comportamiento observado en hardware: el nodo enviaba `WG TX init` solo a la
IP pública del router y recibía `RX init=0` (sin hairpin NAT en ese NAT), por lo
que nunca se establecía sesión WireGuard directa aunque el peer estuviera en la
**misma LAN /24** que el ESP32. El endpoint LAN-privado, que permitiría conexión
directa, se descartaba en el parseo.

Las capas de disco (`tsnode_disco_add_peer`, `disco_ping_all`) ya soportaban
múltiples endpoints por peer (`TSNODE_DISCO_MAX_ENDPOINTS=4`); el cuello de
botella era el struct del mapa (1 solo endpoint) y el cableado en
`tsnode_client.c`.

## Decisión

- `tsnode_map_peer_t` ahora posee un array de hasta `TSNODE_MAP_MAX_ENDPOINTS
  (=4)` endpoints, con contador `n_endpoints`.
- `tsnode_map_parse_response` parsea **todos** los endpoints del JSON
  `"Endpoints":[...]` hasta el techo fijo `TSNODE_MAP_MAX_ENDPOINTS` (cap en
  compile time; los extras se descartan, ver §Consecuencias de estabilidad).
- `peer->online = (peer->n_endpoints > 0)`.
- `update_wg_peers` en `tsnode_client.c`:
  - Envía TODOS los endpoints parseados a `tsnode_disco_add_peer` para que disco
    los pruebe independientemente (así se alcanza el endpoint LAN-privado si hay
    conectividad directa).
  - Para el handshake WG de arranque usa `endpoints[0]` (primer endpoint del
    MapResponse, que en Tailscale es típicamente el LAN-privado cuando existe).
- Esta decisión **no** agrega reintento/balancing heurístico de endpoints en el
  handshake WG síncrono de arranque: el multi-endpoint efectivo lo hace la capa
  de disco (probe) por debajo, mientras que el arranque usa el que más
  probabilidad tiene de funcionar. Un balancing dinámico de endpoints dentro del
  hot path de handshake queda fuera de v1.

## Alternativas consideradas

- **Seguir con un solo endpoint** (status quo): era el diagnóstico del bug, se
  descarta porque pierde el endpoint LAN-privado.
- **Probar todos los endpoints secuencialmente en el sendto de handshake**
  dentro del arranque síncrono: más complejo de acotar en tiempo real y en un
  solo loop; disco ya cubre el descubrimiento asíncrono, así que no se duplica
  esa lógica en el path síncrono.
- **Estructura dinámica (heap) para endpoints**: se descarta por AGENTS.md §4
  (sin asignación dinámica no acotada en runtime crítico); el array fijo de 4 es
  suficiente y acotado en compile time.

## Consecuencias de seguridad

- El parser de red sigue tratando cada endpoint como input hostil: se valida con
  `sscanf` formato IPv4 estricto y se acota a `TSNODE_MAP_MAX_ENDPOINTS` **antes**
  de cualquier uso, sin confiar en la cantidad declarada por el peer.
- No se introduce trust implícito sobre el endpoint LAN: disco prueba candidatos
  pero la autenticación del peer sigue recayendo en el handshake Noise/WireGuard
  (la clave pública del peer proviene del control plane firmado, no del
  endpoint). Un endpoint falso no puede suplantar al peer sin la node key.
- La capa de disco ejerce tráfico de probe hacia múltiples endpoints de un peer
  legítimo; esto no expande la superficie de ataque remota más allá del peer ya
  autenticado.
- Sin cambio en el modelo de amenaza §2.1 (físico): no se almacenan nuevos
  secretos; los endpoints son datos públicos de configuración, no credenciales.

## Consecuencias de estabilidad

- El cap fijo `TSNODE_MAP_MAX_ENDPOINTS=4` evita consumo de memoria por
  cantidad arbitraria de endpoints declarados por el peer (acotado en compile
  time). Tamaño de `tsnode_map_peer_t` crece un poco (array de 4 pares
  ip[16]+port) pero es constante y conocido.
- El techo de 4 es suficiente para los escenarios reales de Tailscale
  (típicamente 1-2 endpoints por peer); si un peer trae más de 4, los sobrantes
  se descartan con log, sin afectar estabilidad.
- La carga de probe de disco ya existía; pasarle más endpoints solo aumenta
  candidatos dentro del mismo presupuesto de `TSNODE_DISCO_MAX_ENDPOINTS`, ya
  activo y testeado.
