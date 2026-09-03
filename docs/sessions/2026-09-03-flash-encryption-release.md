# 2026-09-03 — Flash encryption Release build ready

## Contexto
GOAL-7: habilitar flash encryption en Release mode para producción. Las configs
(`sdkconfig.prod`) existían desde 2026-09-01 pero nunca se flashearon porque
faltaba la partition table custom con `nvs_keys`.

## Cambios
- **`partitions.csv`** (nuevo): partition table custom con `nvs` (24K), `nvs_keys`
  (8K, flag `encrypted` para NVS encryption flash-enc-based), `phy_init` (4K),
  `factory` (1500K).
- **`sdkconfig.defaults`**: cambiado de `CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE`
  a `CONFIG_PARTITION_TABLE_CUSTOM` + `CONFIG_PARTITION_TABLE_CUSTOM_FILENAME`
  + `CONFIG_PARTITION_TABLE_OFFSET=0xB000` (bootloader con flash encryption
  ocupa 0x90b0, excede el default 0x8000).
- Build Release con `SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.prod"`
  exitoso. Verificado: `CONFIG_SECURE_FLASH_ENC_ENABLED=y`,
  `CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y`, `CONFIG_NVS_ENCRYPTION=y`,
  `CONFIG_NVS_SEC_KEY_PROTECT_USING_FLASH_ENC=y`.
- Todos los tests unitarios PASS (h2, blake2s, replay, wg, nacl_box, icmp_echo).

## Decisiones de seguridad tomadas o revisadas
- Offset de partition table en 0xB000: necesario porque el bootloader de
  flash encryption Release es más grande que el default. ADR-0003 no documentaba
  este offset; se agrega como nota de implementación.
- `nvs_keys` partition de 8K (no 4K mínimo): margen para futuras claves NVS
  sin reasignar offsets.

## Pendiente / bloqueado
- Flashear en hardware real (M5Stack Core 2). **ATENCIÓN**: primer boot cifra
  in-place, no cortar alimentación durante ~1 min.
- Verificar eFuse `FLASH_CRYPT_CNT` quemado post-boot con `idf.py efuse-summary`.
- Verificar NVS init exitosa (sin `ESP_ERR_NVS_CORRUPT_KEY_PART`).
- GOAL-7 se marca COMPLETED recién tras validación en hardware.
