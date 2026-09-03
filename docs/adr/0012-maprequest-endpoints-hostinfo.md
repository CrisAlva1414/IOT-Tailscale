# ADR-0012: MapRequest Endpoints y consistencia de Hostinfo

- Estado: **aceptado**
- Fecha: 2026-08-31

## Contexto

El nodo se registraba correctamente (CREATE, LOGIN, APPROVE en logs del control plane) pero el MapResponse devolvía `"Addresses":null` y 0 peers. El device nunca llegaba a estado ONLINE ni recibía peers con IPs.

Investigación cruzada:
- Logs del admin console de Tailscale
- Código fuente oficial (`tailcfg/tailcfg.go`)
- Repositorio de referencia (`alfs/tailscale-iot`)
- Comparación RegisterRequest vs MapRequest

## Causa raíz

**El MapRequest no enviaba el campo `Endpoints`** — la dirección UDP pública (IP:port) donde el nodo escucha WireGuard.

En el protocolo Tailscale (`tailcfg.MapRequest`):
```go
Endpoints []netip.AddrPort `json:",omitempty"` // magicsock UDP endpoints
```

Sin este campo, el control plane:
1. Registra el nodo exitosamente (MachineAuthorized: true)
2. Pero no puede marcarlo "online" porque no sabe dónde alcanzarlo
3. Devuelve MapResponse con `Addresses:null` y 0 peers

## Cambio implementado

### MapRequest (`tsnode_map.c`)
- Nuevo parámetro `endpoint_ip` + `endpoint_port` en `tsnode_map_build_request()`
- Agrega `"Endpoints":["<ip-lan>:51820"]` al JSON del MapRequest

### Hostinfo consistente (`tsnode_map.c`)
- MapRequest ahora envía `"Hostinfo":{"OS":"linux","Hostname":"..."}`
- Antes solo envía `"Hostname"`, sin OS
- Esta inconsistencia causaba el health warning "node OS changed since last connection"

### Client config (`tsnode_client.h`)
- Nuevos campos `endpoint_ip` y `endpoint_port` en `tsnode_client_config_t`

### App layer (`tsnode_simple.c`, `console.c`)
- Obtienen la IP WiFi del sistema y la pasan al cliente
- Puerto WG fijo: 51820

## Resultado

| Métrica | Antes | Después |
|---------|-------|---------|
| MapResponse bytes | 532 | **18,420** |
| Peers en netmap | 0 | **1** (NAS: `<ip-tailnet>`) |
| Self Addresses | null | *(parser pendiente)* |
| Health warning | "node OS changed" | Eliminado |
| State | Nunca ONLINE | **ONLINE** |

## Referencias

- `tailcfg.MapRequest` en `tailscale/tailscale/tailcfg/tailcfg.go` — campo `Endpoints`
- `alfs/tailscale-iot` — envía Endpoints en RegisterRequest (Headscale-specific, no necesario para SaaS)
- Health warning "node OS changed" — causado por inconsistencia Hostinfo entre Register y Map

## Consecuencias de seguridad

- El endpoint UDP se envía en el MapRequest (no cifrado aparte del Noise tunnel)
- El endpoint es la IP:port LAN del nodo (`<ip-lan>:51820`) — en producción sería la IP pública
- No se exponen secrets en el MapRequest

## Pendiente

- Parser de self IP (el `100.x.x.x` del nodo propio no se extrae correctamente del JSON)
- Parser de peer endpoints (bug menor: muestra `Endpoints":0` en vez de la IP real)
