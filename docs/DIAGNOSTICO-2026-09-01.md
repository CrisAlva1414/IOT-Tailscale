# Diagnóstico del Proyecto — 2026-09-01

## Qué busca el proyecto

**Cliente Tailscale mínimo en C puro para ESP32 (ESP-IDF)**

El objetivo es conectar un ESP32 a una tailnet de Tailscale y que sea **alcanzable** desde otros nodos (notebook, OrangePi, etc.). Caso de uso: el ESP32 almacena datos en SD card y el notebook hace polling cada 10 minutos para sincronizar archivos vía HTTPS sobre WireGuard.

**Prioridades**: 1) Seguridad, 2) Estabilidad, 3) Todo lo demás.

**No es un fork** — es una reimplementación selectiva inspirada en `alfs/tailscale-iot`, pero con superficie de ataque entendida y documentada.

## Estado actual

| Componente | Estado | Detalle |
|------------|--------|---------|
| Control plane | ✅ FULLY WORKING | Noise handshake, HTTP/2, Register, MapResponse |
| Self IP extraction | ✅ FIXED | `<ip-tailnet>` extraído de `Self.Addrs` |
| Peer parsing | ✅ WORKING | 4 peers parseados con endpoints |
| WireGuard core | ✅ TESTED | Handshake, transport, replay — todos los tests pasan |
| WG data plane | ⚠️ PARTIAL | Initiations enviadas, **sin responses** |
| HTTPS server | ❌ NOT IMPLEMENTED | Necesario para consultas desde notebook |
| SD card sync | ❌ NOT IMPLEMENTED | Necesario para archivos |

## Problemas bloqueantes (en orden de criticidad)

### 1. 🔴 CRÍTICO — WireGuard handshake no completa

El ESP32 envía WG initiations a los peers pero los peers **nunca responden**.

**Causa raíz**: El ESP32 está detrás de NAT (`<ip-lan>`). Los peers no conocen su endpoint real. Sin **disco protocol** de Tailscale, no hay NAT traversal.

**Sin esto, el ESP32 es un nodo "fantasma" en la tailnet**: registrado, con IP, pero inalcanzable.

**Opciones**:
- Implementar disco protocol (~500 líneas, complejo)
- Port forwarding manual en router (funciona pero no es portable)
- DERP relay (requeriría modificar el control plane, fuera de alcance v1)

### 2. 🟡 IMPORTANTE — No hay servicio de consultas

Incluso si el WG handshake completara, no hay nada que sirva consultas. Necesita: HTTPS server mínimo + SD card API. **Depende de**: Problema #1 resuelto primero.

### 3. 🟡 IMPORTANTE — Flash encryption no probado en hardware

Configs creadas (`sdkconfig.prod`) pero nunca testeadas. Requiere build Release + primer boot para quemar eFuses.

## Pregunta clave

¿Cuál es la implementación mínima viable del **disco protocol** de Tailscale para un cliente IoT en C, considerando que ya tenemos:
- Conexión HTTPS al control plane
- MapRequest/MapResponse funcionales
- WireGuard core completo
- Sin dependencias de Go ni del cliente oficial de Tailscale

## Fuentes primarias

- `docs/adr/0008-protocol-architecture-ts2021-noise-wireguard.md` — Arquitectura de protocolo
- `docs/adr/0011-wireguard-data-plane-integration.md` — WireGuard integration
- `docs/adr/0013-https-server-sd-card-sync.md` — ADR pendiente
- `docs/sessions/2026-09-01-data-plane-testing.md` — Resultados del testing en hardware
- Código fuente oficial: `tailscale/tailscale/control/controlclient/disco/*`

## Estado del nodo en Tailscale

```
Nombre:     <hostname>.ts.net
IP:         <ip-tailnet>
Tags:       tag:iot
Estado:     Registrado y autorizado, pero INALCANZABLE
```

## Próximo paso

El usuario tiene la solución al problema de NAT traversal. Pendiente de implementar y documentar en ADR-0014.
