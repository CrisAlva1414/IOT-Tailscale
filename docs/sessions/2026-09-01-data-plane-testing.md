# 2026-09-01 — Data plane WG testing + flash encryption configs

## Contexto

Sesión de testing en hardware (M5Stack Core 2) para verificar:
1. Fix del parser de MapResponse (Self.Addrs extraction)
2. Flujo completo de conexión a Tailscale
3. WireGuard data plane initialization

## Cambios

### MapResponse parser fix (`tsnode_map.c`)
- Nuevo helper `find_self_addrs()` para extraer IP del campo `Self.Addrs`
- Fallback a `AllowedIPs` cuando `Self.Addrs` no existe
- Strip de CIDR prefix (`/32`) de IPs extraídas
- 3 nuevos tests: `test_map_parse_self_addrs`, `test_map_parse_no_self_addrs`, `test_map_parse_peer_endpoint_multi`

### Flash encryption configs
- `sdkconfig.prod`: Flash encryption Release + NVS encryption (ADR-0003)
- `sdkconfig.dev`: Documenta opciones de desarrollo
- `sdkconfig.defaults`: Instrucciones de selección de perfil

## Testing en hardware (M5Stack Core 2)

### Setup
- WiFi: <ssid> (IP <ip-lan>)
- Auth key: temporal, consumida y borrada después de testing
- Firmware: commit b057b94

### Resultados

| Paso | Estado | Detalle |
|------|--------|---------|
| WiFi connect | ✅ | IP <ip-lan> |
| fetch_control_key | ✅ | controlplane.tailscale.com |
| Noise handshake | ✅ | IK pattern OK |
| HTTP/2 over Noise | ✅ | Tunnel establecido |
| Register | ✅ | `MachineAuthorized: true` |
| MapResponse parse | ✅ | `self=<ip-tailnet>` |
| Peers parsed | ✅ | 4 peers con IPs y endpoints |
| WG device init | ✅ | WireGuard device inicializado |
| WG peer add | ✅ | 4 peers agregados |
| WG initiation | ✅ | Handshakes enviados |
| Map polling | ✅ | Polling loop funcionando |

### Hallazgos clave

1. **Self.Addrs fix funciona**: El nodo ahora extrae correctamente su IP `<ip-tailnet>` del campo `Self.Addrs` del MapResponse
2. **4 peers parseados**: notebook, redmi, orangepi, pc01 (IPs omitidas por privacidad)
3. **WG initiations enviados**: A los 4 peers con sus endpoints UDP correctos
4. **Auth key consumida y borrada**: NVS limpio después de testing

### Lo que falta para WG end-to-end

Los WG initiations se enviaron pero no se recibieron responses porque:
- Los peers (notebook, redmi, orangepi, pc01) necesitan tener WireGuard corriendo
- El NAT traversal puede no ser directo (peers detrás de NAT)
- Falta implementar DERP relay para cuando no hay ruta directa (v1 limitation documentada)

## Decisiones de seguridad tomadas o revisadas

- Auth key temporal usada y borrada del NVS después de testing
- Credenciales WiFi borradas después de testing
- No se commitearon ni loguearon secrets

## Pendiente / bloqueado

| Item | Esfuerzo | Bloqueado por |
|------|----------|---------------|
| **Disco protocol** | ALTO (~500 LOC) | NAT traversal — sin esto WG handshake no completa |
| **HTTPS server** | MEDIO | Requiere WG handshake funcionando |
| **SD card sync** | MEDIO | Requiere HTTPS server |
| **Flash encryption** | BAJO | Configs listas, falta probar en hardware |
| **DERP relay** | MUY ALTO | Fuera de alcance v1 |

**Bloqueador #1**: El ESP32 está detrás de NAT. Sin disco protocol, los peers no pueden responder al WG initiation. El usuario tiene la solución — pendiente de implementar.

**Estado del nodo en Tailscale**: Registrado, autorizado, IP `<ip-tailnet>` asignada, pero **inalcanzable** (no completa WG handshake).
