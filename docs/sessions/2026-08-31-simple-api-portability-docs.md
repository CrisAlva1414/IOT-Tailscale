# 2026-08-31 — API simple, portability fixes, documentation

## Contexto

Cierre de la iteración de la librería tsnode. El usuario quería:
1. Que para el usuario final sea "importar, definir 3 variables, y listo"
2. Documentación para otro developer que quiera integrar la librería

## Cambios

### Port layer: tsnode_port_delay_ms()
- Nueva función en `src/port/tsnode_port.h`: `tsnode_port_delay_ms(uint32_t ms)`
- Implementación ESP-IDF en `tsnode_port_esp_idf.c` usando `vTaskDelay`
- Elimina dependencia directa de FreeRTOS del core del componente

### Refactor tsnode_client.c
- Reemplazadas 3 llamadas directas a `vTaskDelay(pdMS_TO_TICKS(...))` por `tsnode_port_delay_ms()`
- Eliminados `#include <freertos/FreeRTOS.h>` y `<freertos/task.h>` del core
- El core ahora es 100% portable vía port layer

### API simple: tsnode_app_config_t + tsnode_start()
- Nuevo struct público `tsnode_app_config_t` en `tsnode.h` (wifi_ssid, wifi_psk, ts_auth_key + overrides opcionales)
- `tsnode_start()` en `tsnode.h` toma el config y hace todo internamente
- Implementación real en `main/tsnode_simple.c` (wrapper copiable por el usuario)
- Componente mantiene stub `TSNODE_ERR_NOT_IMPLEMENTED` para no romper el API

### Documentación
- `docs/QUICKSTART.md`: guía paso a paso para usar la librería
- `docs/INTEGRATION.md`: guía para portar a otra plataforma o integrar en otro proyecto
- `docs/HOWTO-HUMANS.md`: guía completa para desarrolladores humanos
- `docs/HOWTO-AGENTS.md`: guía para AI coding assistants (reference a AGENTS.md)
- `README.md` actualizado con Quick Start y nuevo estado

### Pendiente moved to other repo
- Display M5Stack Core2: **dejado para otro repo** (no es core de la librería)

## Decisiones de seguridad tomadas o revisadas

- La API simple almacena WiFi credentials y auth key en NVS (mismo patrón que antes)
- Auth key validada por prefijo `tskey-auth-` antes de usar
- El stub del componente retorna NOT_IMPLEMENTED, forzando al usuario a usar el wrapper real

## Pendiente / bloqueado

Items dejados para futuras sesiones:

| Item | Esfuerzo | Notas |
|------|----------|-------|
| **ts2021.c portability** | ALTO (~400 líneas) | Refactor más extenso de lo esperado: functions internas necesitan crypto vtable, muchas llamadas a cambiar |
| **Data plane WG end-to-end** | MEDIO | MapResponse `"Addresses":null` — nodo registrado pero sin IP asignada. Necesita verificación en consola Tailscale |
| **Flash encryption** | BAJO | Activar antes de producción (ADR-0003) |

### Hallazgo clave: MapResponse Addresses null

El MapResponse del control plane devuelve `"Addresses":null` aunque el nodo
está aprobado con IP `<ip-tailnet>` asignada en la consola de Tailscale.
Esto sugiere que:
1. El nodo necesita ser "activated" (no solo "approved")
2. O hay un mismatch entre el estado del nodo y lo que el control plane devuelve
3. O el formato del MapResponse ha cambiado

Próximo paso: verificar el estado exacto del nodo en la consola de Tailscale
y comparar con el MapResponse recibido.

## Verificación

- Build ESP-IDF: **PASS** (target esp32)
- Tests host: **15/15 H2 PASS**, blake2s ALL PASS, replay ALL PASS, wg ALL PASS
- Tamaño del binario: verificable con `idf.py size`
