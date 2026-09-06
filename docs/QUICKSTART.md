# Quick Start — tsnode en tu proyecto ESP32

## Requisitos

- ESP-IDF v5.5+
- ESP32, ESP32-C3, ESP32-S3 o ESP32-C6
- Auth key de Tailscale

## Paso 1: Copiar el componente

```bash
cp -r components/tsnode /ruta/a/tu/proyecto/components/
```

## Paso 2: sdkconfig.defaults

Agrega al final de tu `sdkconfig.defaults`:

```
CONFIG_MBEDTLS_CHACHA20_C=y
CONFIG_MBEDTLS_POLY1305_C=y
CONFIG_MBEDTLS_CHACHAPOLY_C=y
```

## Paso 3: Código mínimo

```c
#include <nvs_flash.h>
#include "tsnode.h"

void app_main(void)
{
    nvs_flash_init();

    tsnode_init();

    tsnode_start(&(tsnode_app_config_t){
        .wifi_ssid   = "MiSSID",
        .wifi_psk    = "MiPSK",
        .ts_auth_key = "tskey-auth-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    });

    /* El device se conecta solo. El cliente corre en background. */
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
```

## Paso 4: Generar auth key

1. Andá a https://login.tailscale.com/admin/settings/keys
2. Generá una key con:
   - **Reusable**: OFF (one-time)
   - **Expiry**: 7 días
   - **Tags**: `tag:esp32-iot`
3. Copiá la key (empieza con `tskey-auth-`)

> **Seguridad de la key (ADR-0002/0003)**: la key es **de un solo uso**. Tras
> el primer registro el firmware la purga de NVS y pasa a autenticarse con la
> node key generada localmente. Si tu app hardcodea la key, que sea SOLO para
> el banco de pruebas; para despliegues reales usá el serial console de
> provisioning del app de referencia (`docs/adr/0007`).

## Paso 5: Compilar y flashear

```bash
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

## Qué ves en el serial

```
tsnode_init -> TSNODE_OK
WiFi connected
Tailscale client started (hostname: esp32-a1b2c3)
control key fetched OK
Noise handshake OK
registration done
netmap poll: N peers, self=100.x.x.x
```

## Configuración avanzada

```c
tsnode_start(&(tsnode_app_config_t){
    .wifi_ssid     = "MiSSID",
    .wifi_psk      = "MiPSK",
    .ts_auth_key   = "tskey-auth-...",
    .hostname      = "sensor-garaje",     /* NULL = auto de MAC */
    .control_host  = "controlplane.tailscale.com",  /* default */
    .control_port  = 80,                              /* default */
    /* Para nodos ya registrados, .ts_auth_key = NULL: la identidad
       persiste en NVS (node key) y no se re-registra (ADR-0021). */
});
```

## Monitorear estado

```c
tsnode_state_t state;
tsnode_state_get(&state);
// TSNODE_STATE_ONLINE = conectado a la tailnet
```

## Limitaciones conocidas (v1)

- Sin relay DERP (si no hay ruta directa, no conecta)
- Sin IPv6
- Puerto 80 para control plane (no TLS:443)
- Provisioning solo por serial (sin SoftAP/BLE)
- Si los ACLs piden aprobación interactiva, el usuario debe visitar una URL

## Solucionar problemas

| Síntoma | Causa | Solución |
|---------|-------|----------|
| "WiFi connection timeout" | SSID/PSK incorrectos | Verificar credenciales |
| "registration error: invalid key" | Auth key expirada o inválida | Generar nueva key |
| "0 peers, self=" | Nodo no aprobado | Aprobar en consola de Tailscale |
| Crash en WG recv | Stack insuficiente | Aumentar stack de la tarea |
