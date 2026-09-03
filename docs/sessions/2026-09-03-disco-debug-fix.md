# 2026-09-03 — Disco protocol debug and fix

## Contexto

Sesión de debug y fix del disco protocol implementado el 2026-09-01.
El dispositivo se registraba correctamente en la tailnet (IP `<ip-tailnet>`),
pero el data plane no funcionaba porque los peers no respondían a los
WireGuard handshake initiations.

## Cambios

### Fix: STUN parsing (`tsnode_map.c`)
- **Bug**: Parser buscaba `"STUNIPv4"` que no existe en el MapResponse de Tailscale
- **Fix**: Usar primer `"IPv4"` del DERPMap como STUN server (fallback a 3478)
- Tailscale no envía campo STUNIPv4 separado; los nodos DERP actúan como STUN

### Fix: STUN response detection (`tsnode_client.c`, `disco.c`)
- **Bug**: Respuestas STUN (Binding Success) no eran detectadas en el recv loop
- **Fix**: Agregado check de RFC 5389 magic cookie (0x2112A442) en byte 4-7
- Agregada función `tsnode_disco_is_stun_response()` al header
- Routing de STUN responses a `tsnode_disco_stun_parse_response()`

### Fix: ct_memcmp broken (`disco.c`)
- **Bug CRÍTICO**: `ct_memcmp()` (implementación constant-time) retornaba `true`
  para claves completamente diferentes. Prueba:
  `peer[0]=2d642a3b vs new=ed3231c8 cmp=-192` (memcmp != 0 pero ct_memcmp == true)
- **Fix**: Reemplazado con `memcmp()` estándar de libc (newlib en ESP-IDF)
- Causa probable: compilador Xtensa optimiza incorrectamente el volatile en ct_memcmp
- **Consecuencia**: Se pierde la property constant-time para esta comparación
  (disco key comparison no es timing-sensitive, aceptable para v1)

### Disco key parsing fix (`tsnode_map.c`)
- **Bug**: `strchr(dk, '"')` encontraba la comilla de `"DiscoKey"` en vez del valor
- **Fix**: Buscar `:` después de `"DiscoKey"`, skip whitespace, skip quote

## Resultado en hardware (M5Stack Core 2)

### Lo que SÍ funciona:
1. Disco key generada y persistida en NVS
2. Disco key enviada en MapRequest (`DiscoKey: cf60dafc...`)
3. Peers con disco key parseada desde MapResponse (4 peers, todos `disco=yes`)
4. Disco key del ESP32 visible en MapResponse del control plane
5. STUN Binding Request enviado a DERP server (`<ip-stun>:3478`)
6. Disco PING enviado a los 3 peers alcanzables
7. Polling periódico: STUN cada 30s, PING con reintentos

### Lo que NO funciona (limitación NAT conocida):
1. **STUN RX**: No se reciben respuestas STUN del servidor
   - Posible causa: servidor DESCPU/DERP no responde a STUN desde IPs no autorizadas
   - O: ESP32 detrás de NAT simétrico, respuesta va a puerto diferente
2. **Disco PONG**: No se reciben PONG de ningún peer
   - Los peers están detrás de su propio NAT (`<ip-public>`, etc.)
   - Sin hole punching simultáneo, los paquetes no llegan
3. **WG session**: No se establece (sin disco handshake = sin ruta directa)

### Log del ciclo completo (una corrida):
```
disco add: 0 peers          # peer 0 registrado
disco add: 1 peers          # peer 1 registrado (memcmp corregido)
disco add: 2 peers          # peer 2 registrado
disco add: 3 peers          # peer 3 registrado
poll: stun=<ip-stun>:3478 n_peers=4
STUN TX -> <ip-stun>:3478
disco TX PING -> <ip-peer-1>:<port>
disco TX PING -> <ip-peer-2>:<port>
disco TX PING -> <ip-peer-1>:<port2>
# (sin respuesta)
```

## Decisiones de seguridad revisadas

- El reemplazo de `ct_memcmp` con `memcmp` para la comparación de disco keys
  es aceptable: disco keys no son secretos (se intercambian públicamente),
  y la comparación no es timing-sensitive. Para production, se debe evaluar
  si el compilador Xtensa soporta volatile correctamente o implementar
  una alternativa constant-time verificada.

## Pendiente / bloqueado

| Item | Estado | Notas |
|------|--------|-------|
| Disco protocol funcional | Parcial | Envía PING pero no recibe PONG (NAT) |
| STUN public endpoint | Bloqueado | No se descubre IP pública del ESP32 |
| WG session | Bloqueado | Sin ruta directa = sin handshake |
| DERP relay | No implementado | ADR-0014 lo excluye de v1 |
| ct_memcmp fix | Completado | Reemplazado con memcmp |
| STUN parsing fix | Completado | IPv4 fallback funciona |
| Peer disco registration | Completado | 4/4 peers con disco=yes |

## Próximos pasos

1. **Evaluar si DERP relay es viable** para v1.5 (sin relay, el nodo no conecta
   si peers están detrás de NAT simétrico). Considerar ADR-0015.

2. **Verificar si los peers (Redmi, OrangePi) están configurados para responder
   disco PING** — necesitan Tailscale client corriendo con disco habilitado.

3. **Investigar STUN response**: capturar con tcpdump en la LAN para ver si
   el servidor responde y el paquete se pierde en el ESP32.

4. **Cleanup de debug logs** antes de merge a main.
