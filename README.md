# IOT-Tailscale

[![CI](https://github.com/CrisAlva1414/IOT-Tailscale/actions/workflows/ci.yml/badge.svg)](https://github.com/CrisAlva1414/IOT-Tailscale/actions/workflows/ci.yml)

Cliente Tailscale mínimo en **C puro** para ESP32 (ESP-IDF, sin ESPHome), como
reimplementación selectiva — no fork, no submódulo — del enfoque de
[`alfs/tailscale-iot`](https://github.com/alfs/tailscale-iot).

Tu ESP32 se une a una tailnet de Tailscale, obtiene una IP `100.x.x.x` y se
comunica con el resto de los nodos vía WireGuard con NAT traversal directo.
Plano de control (ts2021 sobre Noise, registro, `/machine/map` streaming) y
plano de datos (WireGuard + disco) implementados y validados en hardware.

**Estado**: validado en hardware real (M5Stack Core 2): nodo online con
uptime sostenido, `active/direct` en `tailscale status`, ping 0% pérdida,
auth key purgada tras el registro. CI en verde para `esp32`, `esp32c3`,
`esp32s3`, `esp32c6`.

## Quick Start (2 caminos)

**A — Usar el app de referencia (lo más simple):** clonar, definir credenciales,
build, flash.

```bash
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

Las credenciales se ingresan por el **serial console de provisioning**
(`docs/adr/0007`): WiFi SSID/PSK y auth key de Tailscale, sin hardcodear.

**B — Usar `tsnode` como librería en tu propio proyecto:**

```c
#include <nvs_flash.h>
#include "tsnode.h"

void app_main(void)
{
    nvs_flash_init();
    tsnode_init();
    tsnode_start(&(tsnode_app_config_t){
        .wifi_ssid   = "<ssid>",
        .wifi_psk    = "<wifi-psk>",
        .ts_auth_key = "tskey-auth-...",   /* one-time; tras registrar se borra */
    });
    /* el device se conecta solo; el cliente corre en background */
}
```

Pasos completos (copiar `components/tsnode`, flags de `sdkconfig`, auth key
recomendada, troubleshooting): **`docs/QUICKSTART.md`**.

### Generar la auth key

1. https://login.tailscale.com/admin/settings/keys
2. **Reusable**: OFF (one-time) · **Expiry**: 7 días · **Tags**: `tag:esp32-iot`
3. Copiá la key (empieza con `tskey-auth-`)

> Es mejor dejar la key fija al banco de pruebas: tras el primer registro el
> firmware la purga de NVS y pasa a autenticarse con su node key (ADR-0021).

## Qué es esto

Llevar dispositivos ESP32 a una tailnet personal (Tailscale SaaS, no
Headscale), con conectividad directa vía WireGuard sobre NAT traversal,
priorizando por sobre todo: **seguridad y estabilidad** (en ese orden).

- Target v1: **M5Stack Core 2** (ESP32 clásico); la librería apunta a toda la
  familia ESP32 con Wi-Fi para domótica y automatización.
- **Tier 1** (CI obligatorio en GitHub Actions): `esp32`, `esp32c3`, `esp32s3`,
  `esp32c6`. Tier 2 (sin hardware aún): `s2`, `c2`. Excluido: `h2` (sin Wi-Fi).
- Detalles de hardware y targets: `docs/adr/0004`, `docs/adr/0006`.

## Librería reutilizable

`components/tsnode/` es un componente ESP-IDF autocontenido
(`docs/adr/0005-packaging-and-reuse.md`): API pública solo en su `include/`,
sin lógica de aplicación adentro, con el core en **C puro** — sin headers de
plataforma (verificado por un guard en CI) — y el acceso al sistema confinado
a una capa de port de 16 funciones (`docs/INTEGRATION.md`).

Cada proyecto consume el componente y agrega su capa de aplicación encima.
La app de `main/` es un ejemplo completo de referencia (WiFi, provisioning por
serial, autostart, display del banco).

## Testing

- Tests unitarios en host (sin ESP-IDF): `make -C tests/unit test` — 7 bins,
  incl. vectors de protocolo de Noise/WireGuard/disco, ventana anti-replay,
  parsers fuzz-oriented.
- Análisis estático: `cppcheck` con flags en `docs/format/static-analysis.md`.
- CI (GitHub Actions): build `-Werror` de 4 targets + cppcheck + arch-guard.

## Qué NO es esto (v1)

- No soporta **DERP** (relay): si no hay ruta UDP directa, el nodo no conecta.
- No soporta IPv6, subnet routing, exit node, ni MagicDNS local.
- No es un fork de `alfs/tailscale-iot` ni depende de su código: es una
  reimplementación propia, inspirada en su enfoque y en las limitaciones que
  ese proyecto documentó.

## Seguridad (léelo antes de desplegar fuera de un banco)

- **Amenaza física y remota con igual prioridad.** Claves en flash extraíbles
  por atacante con acceso físico; mitigación en `docs/adr/0003`.
- En desarrollo se flashea en claro por defecto. Para desplegar en un entorno
  no controlado seguí obligatoriamente `docs/adr/0002-threat-model.md` y el
  checklist de `docs/INTEGRATION.md` (flash encryption Release, eFuses, ACLs).
- Todo lo versionado es público (ADR-0010): sin credenciales, IPs reales ni
  detalles del despliegue del operador en el repo.

## Leer antes de generar código o contribuir

- `AGENTS.md` — documento operativo completo (alcance, modelo de amenaza,
  reglas de C, estructura, proceso).
- `docs/adr/` — 21 decisiones de arquitectura, cada decisión de protocolo,
  memoria y manejo de claves respaldada.
- `docs/format/` — convenciones de código, commits, análisis estático y
  privacidad documental.

## Licencia

Ver `LICENSE`.