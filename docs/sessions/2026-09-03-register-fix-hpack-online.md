# 2026-09-03 — Fix registro (HPACK table size update) + validación hardware data plane

## Contexto

Todos los goals de `docs/PROJECT-GOALS.md` estaban COMPLETED a nivel de
código/test, con la validación end-to-end en hardware pendiente. Arrancando el
loop sobre el dispositivo conectado (`/dev/ttyACM0`, M5Stack Core 2, target
`esp32`), se descubrió que el nodo **no llegaba a registrarse**: la versión
prevista iteraba igual a un error determinista `register POST failed: 8
(TSNODE_ERR_NETWORK)` tras el handshake Noise/HTTP/2 exitoso. Ese era el
problema más bloqueante de la ecuación: sin registro no hay MapResponse, y sin
MapResponse no hay peers, ni disco, ni data plane (GOAL-1/3/5/6 inalcanzables).

## Cambios

### 1. HPACK: dynamic table size update previo al `:status 200` (fix GOAL-1 autorregistro)

- **Causa raíz**: el encoder HPACK Go del control plane Tailscale emite un
  *dynamic table size update* (`0x21`, size 1) ANTES del `:status 200` indexado
  (`0x88`) al arrancar cada bloque HEADERS de respuesta. El parser H2 exigía
  `payload[0] == 0x88` como byte 0 (`H2_HPACK_STATUS_200`), por lo que
  rechazaba el bloque con `TSNODE_ERR_NETWORK` y el register nunca se
  completaba. Verificado byte a byte en hardware (RXHEX del registro 152/153 B).
- **Fix**: `h2.c` nueva `hpack_starts_with_status_200()` salta los *dynamic
  table size updates* iniciales (RFC 7541 §4.2, patrón `0b001xxxxx` con varint
  de 5/7 bits) y exige el `:status 200` indexado justo después. Cualquier otro
  encabezado antes del `:status` (o status ≠ 200) → fail-closed.
- **ADR-0009** ampliado: el ADR anticipaba explícitamente que "HPACK dinámico
  en las respuestas" reabriría este ADR; ocurrió, se maneja siendo tolerante
  solo al size update inicial sin decodificar tablas dinámicas.

### 2. Multi-endpoint + desync (commit de trabajo previo, ADR-0017)

- Se commitearon los cambios documentados en la sesión
  `2026-09-03-multi-endpoint-parser-fix.md` (ancla por nodekey, ventana por
  peer, cap 16): `disco.h`, `tsnode_map.{c,h}`, tests. Verificado en hardware:
  los peers reales traen 10-17 endpoints y el cap=4 previo perdía el endpoint
  LAN-privado (índices 8-15).

## Validación en hardware (M5Stack Core 2, `/dev/ttyACM0`)

| Hito | Resultado |
|------|-----------|
| Boot + WiFi (SSID `<ssid>`) | OK, IP `<ip-lan>` |
| Fetch /key | OK |
| Noise handshake (ts2021) | OK |
| HTTP/2 upgrade + SETTINGS | OK |
| **register POST** | **OK tras el fix** (antes: `register POST failed: 8`) |
| RegisterResponse | `MachineAuthorized:true`, sin error |
| MapResponse (21529 B) | OK, 4 peers, self `<ip-tailnet>` |
| Node state | **ONLINE** (`state -> 5`, poll loop + WG recv task) |
| Peer endpoints parseados | notebook 10, pc01 17 (cap=16 conserva LAN) |
| Disco PING → TODOS los endpoints | OK, incl. LAN `192.168.1.x:41641` |
| STUN Binding Request | TX a `<ip-stun>:3478` (RX pendiente de confirmar) |
| **Disco RX PONG** | **OK — direct path confirmed** (GOAL-1 aceptado en HW) |
| WG TX init | Enviados a 4 peers |
| Uptime | Supera el ciclo de ~90s previo; H2 keepalive activo |
| Reconnect | OK en 5s tras map POST timeout esporádico |

## Decisiones de seguridad tomadas o revisadas

- No se decodifica HPACK completo ni se mantiene tabla dinámica local: solo se
  saltan size updates (datos de control sin secretos) y se sigue exigiendo
  `:status 200` indexado. Superficie de parseo no aumenta (ADR-0009).
- El input sigue tratado como hostil: el helper acota el varint del size update
  y falla ante un bloque truncado/hostil.
- No cambia el almacenamiento de claves ni el modelo §2.1.

## Pendiente / bloqueado

- **GOAL-3 endpoint público**: STUN TX sale, pero RX/parseo del endpoint
  público en MapRequest aún por confirmar (requiere ver el 2º poll).
- **GOAL-6 estabilidad a largo plazo**: se superó el ciclo de 90s, pero hubo un
  `map POST failed: 5 (TIMEOUT)` esporádico tras varios minutos → el nodo
  reconectó en 5s. Falta confirmar si es esporádico o sistemático observando
  > 1h.
- **Parseo `Addresses` vs `AllowedIPs`**: el `tailscale_ip` se lee de
  `AllowedIPs`, pero los peers reales exponen su IP propia en `Addresses` y
  `AllowedIPs:null` (salvo peers que rutean subredes). Esto puede dejar
  `tailscale_ip` vacío / desplazado en el log de peers. No bloquea disco (que
  prueba endpoints por node key), pero es un bug de parser a corregir.
- Observar si la conexión se mantiene estable > 1h en la próxima sesión.