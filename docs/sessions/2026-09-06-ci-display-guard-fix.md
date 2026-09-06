# 2026-09-06 — fix CI esp32c3/esp32c6 (display driver)

## Contexto
La CI de GitHub Actions (`.github/workflows/ci.yml`, matrix esp32/esp32c3/esp32s3/esp32c6)
fallaba en cada push en `build (esp32c3)` y `build (esp32c6)`. El usuario recibía
notificaciones de build roto. Se pidió detectar el arch-guard crítico y corregir.

## Cambios
- diagnostico: lavado del `::error::` en el log del job cppcheck era ruido de un
  segundo del workflow; el job `cppcheck` (incl. arch-guard) estaba **verde**.
- causa raíz: `main/display.c` (driver ILI9342 del M5Stack Core 2) usa `SPI3_HOST`,
  periférico que ESP32-C3/C6 no exponen (solo `SPI2`). El build de esos targets
  rompía en `main/display.c:22`.
- fix: en `main/CMakeLists.txt` `display.c` se compila solo cuando
  `CONFIG_IDF_TARGET_ESP32 OR CONFIG_IDF_TARGET_ESP32S3`; el resto del app de
  referencia (incl. `components/tsnode`) compila igual en C3/C6 (ADR-0006 Tier 1).
- verificado localmente: build limpio esp32c3 (scratch en /tmp, sin tocar sdkconfig
  del board) y esp32 (build dir del repo). Commit `09cf9ed`, push a `main`.
- estado CI tras el push: `cppcheck`, `build (esp32)`, `esp32c3`, `esp32s3`,
  `esp32c6` → todos `success`.

## Decisiones de seguridad tomadas o revisadas
Ninguna nueva. Se reafirmó el arch-guard (ADR-0006: core de plataforma pura) que ya
pasa en CI y localmente (0 includes de `esp_|freertos|nvs|driver|lwip` en tsnode).

## Pendiente / bloqueado
- la integración de `tsnode` como librería en el dispositivo del usuario sigue
  documentada en `docs/QUICKSTART.md` (opción v1: copiar `components/tsnode`).
- GOAL-7 (flash encryption Release) sigue a la espera de decisión explícita del
  usuario (eFuse irreversible).