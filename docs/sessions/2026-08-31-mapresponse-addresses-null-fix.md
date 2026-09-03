# 2026-08-31 — MapResponse Addresses null — diagnóstico y fix

## Contexto

Sesión de debugging profundo del data plane WG. El nodo se registraba pero nunca recibía peers ni IP. El MapResponse mostraba `"Addresses":null` y 0 peers.

## Investigación

Se hizo un análisis cruzado entre:
1. Logs del admin console de Tailscale ( CREATE, LOGIN, APPROVE, DISABLE KEY_EXPIRY)
2. Código fuente oficial de Tailscale (`tailcfg/tailcfg.go` — RegisterRequest y MapRequest structs)
3. Repositorio de referencia (`alfs/tailscale-iot` — register_payload.cpp)
4. Código de tsnode (tsnode_map.c, tsnode_client.c, tsnode_register.c)

### Hallazgos clave

1. **RegisterRequest correcto**: No faltaba `MachineKey` (ese campo es de Headscale, no del protocolo oficial). El handshake Noise ya establece la identidad de máquina.

2. **MapRequest sin Endpoints**: El `tailcfg.MapRequest` requiere el campo `Endpoints` (IP:port UDP del WireGuard). Nuestro MapRequest solo enviaba Version, NodeKey, DiscoKey, Stream, Hostinfo.

3. **Hostinfo inconsistente**: Register enviaba `"OS":"linux"`, Map solo `"Hostname"`. Esta diferencia causaba el health warning "node OS changed since last connection".

4. **Resultado**: Con Endpoints + Hostinfo consistente, el MapResponse pasó de 532 bytes a 18,420 bytes, con 1 peer visible.

## Cambios realizados

### ADR-0012
- Documenta la causa raíz: campo `Endpoints` faltante en MapRequest
- Documenta la inconsistencia Hostinfo

### Archivos modificados
- `components/tsnode/src/proto/tsnode_map.h` — nueva firma con endpoint_ip/endpoint_port
- `components/tsnode/src/proto/tsnode_map.c` — agrega Endpoints al JSON, corrige Hostinfo
- `components/tsnode/src/proto/tsnode_client.h` — campos endpoint_ip/endpoint_port en config
- `components/tsnode/src/proto/tsnode_client.c` — pasa endpoints al MapRequest builder
- `main/tsnode_simple.c` — obtiene IP WiFi y la pasa como endpoint
- `main/console.c` — mismo patrón para comando tsconnect
- `docs/adr/0012-maprequest-endpoints-hostinfo.md` — ADR completo

### Nuevos comandos
- `tsstop` en console.c — permite detener el cliente sin reboot

## Decisiones de seguridad tomadas

- El endpoint UDP se envía en el MapRequest dentro del tunnel Noise (no en claro)
- Puerto WG fijo: 51820 (estándar WireGuard)
- IP del endpoint es la LAN IP del dispositivo (`<ip-lan>`) — en producción sería pública

## Verificación

- Build ESP-IDF: **PASS**
- Tests host: **100% PASS** (H2, blake2s, replay, wg)
- MapResponse: **18,420 bytes** con **1 peer** (NAS: `<ip-tailnet>`)
- State: **ONLINE**

## Pendiente / bloqueado

- **Parser self IP**: el `100.x.x.x` del nodo propio no se extrae correctamente
- **Parser peer endpoints**: ✅ FIXED — ahora muestra `<ip-public>:<port>`
- **WG initiation**: ✅ FIXED — ahora funciona con `cr->keygen()` (Curve25519 clamping via `mbedtls_ecp_gen_keypair`)
- **Noise handshake**: ✅ FULLY WORKING — todos los pasos OK
- **WG initiation sent**: ✅ `148 bytes → <ip-public>:<port>`
- **Map polling**: falla después de la primera respuesta (auth key consumida)
- **WG response + session**: pendiente — necesita auth key válida y peers online
- **ts2021.c refactor**: deferred
- **Flash encryption**: deferred
