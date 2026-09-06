# How to Use tsnode — Guía para Desarrolladores

## Qué es tsnode

tsnode es un **cliente Tailscale mínimo en C puro** para ESP32. Conecta tu dispositivo ESP32 a tu tailnet personal de Tailscale, asignándole una IP 100.x.x.x y permitiéndole comunicarse con otros nodos via WireGuard.

**En 3 pasos**: importar la librería, definir 3 variables, y tu dispositivo está en la tailnet.

## Requisitos

| Requisito | Versión |
|-----------|---------|
| ESP-IDF | v5.5+ |
| Hardware | ESP32, ESP32-C3, ESP32-S3 o ESP32-C6 |
| Cuenta | Tailscale (plan free suficiente) |

## Inicio rápido

Para empezar en 10 minutos, seguí **`docs/QUICKSTART.md`** (copiar el
componente, flags de sdkconfig, código mínimo, auth key, flash). Este
documento es la **guía extendida** del SDK: configuración, estados,
seguridad, multi-target y debugging.

## Variables de configuración

### tsnode_app_config_t

| Campo | Tipo | Requerido | Default | Descripción |
|-------|------|-----------|---------|-------------|
| `wifi_ssid` | `const char *` | Sí | — | SSID de la red WiFi (1-32 chars) |
| `wifi_psk` | `const char *` | Sí | — | Contraseña WPA2 (8-63 chars) |
| `ts_auth_key` | `const char *` | Sí | — | Auth key de Tailscale (`tskey-auth-...`) |
| `hostname` | `const char *` | No | `esp32-XXYYZZ` | Nombre del nodo en la tailnet |
| `control_host` | `const char *` | No | `controlplane.tailscale.com` | Host del control plane |
| `control_port` | `uint16_t` | No | `80` | Puerto del control plane |

### Ejemplo completo

```c
tsnode_start(&(tsnode_app_config_t){
    .wifi_ssid     = "MiSSID",
    .wifi_psk      = "MiPSK",
    .ts_auth_key   = "tskey-auth-...",
    .hostname      = "sensor-garaje",
    .control_host  = "controlplane.tailscale.com",
    .control_port  = 80,
});
```

## Monitoreo de estado

### Estados del nodo

| Estado | Significado |
|--------|-------------|
| `TSNODE_STATE_STOPPED` | Detenido |
| `TSNODE_STATE_INITIALIZED` | Inicializado, esperando start |
| `TSNODE_STATE_STARTING` | Conectando |
| `TSNODE_STATE_ONLINE` | Conectado a la tailnet |
| `TSNODE_STATE_ERROR` | Error |

### Consultar estado

```c
tsnode_state_t state;
tsnode_state_get(&state);

if (state == TSNODE_STATE_ONLINE) {
    /* Dispositivo conectado y alcanzable */
}
```

### Estados del cliente (detallados)

| Estado | Significado |
|--------|-------------|
| `IDLE` | Sin actividad |
| `FETCHING_KEY` | Obteniendo clave del control plane |
| `HANDSHAKING` | Handshake Noise/ts2021 |
| `REGISTERING` | Registrando nodo |
| `MAP_SYNC` | Sincronizando mapa de peers |
| `ONLINE` | Conectado, polling activo |
| `DONE` | Ciclo completado |
| `ERROR` | Error |

## Qué pasa internamente

Cuando llamás `tsnode_start()`, el dispositivo:

1. Guarda WiFi credentials en NVS
2. Guarda auth key en NVS
3. Conecta WiFi (bloquea hasta conectar)
4. Deriva hostname de la MAC si no se provee
5. Obtiene la clave pública del control plane (`/key?v=145`)
6. Realiza handshake Noise/ts2021 sobre HTTP/2
7. Registra el nodo (`/machine/register`)
8. Obtiene el mapa de peers (`/machine/map`)
9. Inicia WireGuard data plane con los peers conocidos
10. Permanece conectado, actualizando el mapa periódicamente

## Errores comunes

| Error | Causa | Solución |
|-------|-------|----------|
| "WiFi connection timeout" | SSID o PSK incorrectos | Verificar credenciales |
| "auth key must start with tskey-auth-" | Key en formato incorrecto | Generar nueva key en Tailscale |
| "registration error: invalid key" | Auth key expirada o inválida | Generar nueva key |
| "0 peers, self=" | Nodo no aprobado en la tailnet | Aprobar en consola de Tailscale |
| Crash en WG recv task | Stack insuficiente | Aumentar stack de la tarea |
| "parse MapResponse failed" | Respuesta del control plane corrupta | Verificar conectividad |

## Seguridad

### Lo que DEBES hacer

- Usar auth keys **one-time** (no reusable)
- Configurar **expiry corto** (días, no meses)
- **Taguear** las keys (`tag:esp32-iot`) para ACLs restrictivas
- **Habilitar flash encryption** antes de producción
- **Restringir ACLs** en Tailscale para `tag:esp32-iot`

### Lo que NO debes hacer

- ❌ No commitees auth keys en el repo
- ❌ No uses auth keys reutilizables en producción
- ❌ No publiques logs con claves, tokens o IPs
- ❌ No uses sin flash encryption fuera del banco de pruebas
- ❌ No asumas que el dispositivo es "seguro" sin encryption

## Limitaciones conocidas (v1)

- **Sin relay DERP**: si no hay ruta UDP directa a otros peers, el nodo no conecta
- **Sin IPv6**: solo IPv4 en la tailnet
- **Puerto 80**: el control plane usa HTTP, no HTTPS (el handshake Noise provee autenticación)
- **Sin SoftAP/BLE**: provisioning solo por serial
- **Aprobación interactiva**: si los ACLs lo requieren, el usuario debe visitar una URL

## Construcción multi-target

```bash
idf.py set-target esp32     # M5Stack Core 2 (primario v1)
idf.py set-target esp32c3   # Tier 1
idf.py set-target esp32s3   # Tier 1
idf.py set-target esp32c6   # Tier 1
idf.py build
```

## Debugging

### Logs útiles

```bash
idf.py monitor | grep -E "tsnode|wireguard|wg"
```

### Comandos de consola (bank of tests)

Si usás la app de referencia (`main/`), la consola serie ofrece:

| Comando | Descripción |
|---------|-------------|
| `help` | Lista de comandos |
| `wifi set <ssid>` | Configurar WiFi |
| `tskey set` | Configurar auth key |
| `tsconnect` | Conectar a Tailscale |
| `status` | Ver estado actual |
| `provision status` | Ver credenciales guardadas |
| `provision wipe` | Borrar credenciales |
| `tsforget` | Borrar identidad (nodo nuevo) |
| `reboot` | Reiniciar dispositivo |

## Estructura del proyecto

```
tu-proyecto/
├── components/
│   └── tsnode/              # La librería
│       ├── include/         # API pública
│       └── src/             # Implementación interna
├── main/
│   ├── main.c               # Tu código
│   ├── tsnode_simple.c      # Copiar de este repo
│   └── tsnode_simple.h      # Copiar de este repo
└── sdkconfig.defaults       # Configuración
```

## Documentación adicional

- `docs/QUICKSTART.md` — Inicio rápido paso a paso
- `docs/INTEGRATION.md` — Para portar a otra plataforma
- `docs/adr/` — Decisiones de arquitectura y seguridad
- `AGENTS.md` — Reglas para contribuir al proyecto
