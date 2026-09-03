# 2026-08-31 — Curve25519 clamping fix + WG initiation success

## Contexto

Continuación del sprint anterior. El MapRequest ahora incluye Endpoints y el MapResponse devuelve peers. Pero el WG initiation fallaba con error 6 (CRYPTO) en el paso DH.

## Investigación

Investigación cruzada entre:
- Código fuente mbedTLS (`ecp.c`, `ecp.h`)
- RFC 7748 §5 (X20219 clamping)
- Repositorio alfs/tailscale-iot
- Paper original de Curve25519

### Hallazgo clave

El error `-0x4c80` = `MBEDTLS_ERR_ECP_INVALID_KEY` viene de `mbedtls_ecp_check_privkey()` que valida 4 condiciones para Curve25519:

1. `get_bit(d, 0) == 0` — bit 0 limpio
2. `get_bit(d, 1) == 0` — bit 1 limpio
3. `bitlen(d) - 1 == 254` — MPI debe ser exactamente 255 bits
4. `get_bit(d, 2) == 0` — bit 2 limpio

El clamping de RFC 7748 (byte-level: `key[0] &= 248`, `key[31] |= 64`) NO garantiza la condición #3. `mbedtls_mpi_read_binary_le()` puede producir un MPI con `bitlen < 255`.

En cambio, `mbedtls_ecp_gen_keypair()` usa `mbedtls_ecp_gen_privkey_mx()` que genera la key con operaciones a nivel de bit que garantizan las 4 condiciones.

El alfs/tailscale-iot funciona porque usa `noise-c` (implementación X20219 propia con Montgomery ladder), no pasa por `mbedtls_ecp_mul()`.

## Cambios realizados

### Crypto vtable (`wg.h`, `wg_crypto_mbedtls.c`)
- Nueva función `keygen()` en `tsnode_wg_crypto_t`
- Implementación: `tsnode_x25519_keygen()` (usa `mbedtls_ecp_gen_keypair`)
- También agregado `zeroize()` al vtable

### WG initiation (`wg.c`)
- Reemplazado `cr->random()` + `cr->pubkey()` por `cr->keygen()`
- Esto garantiza que la ephemeral key pasa validación mbedTLS

### x25519_wrapper.c
- Agregado clamping MPI-level en `tsnode_x25519_publickey()` (belt-and-suspenders)
- Restaurado RNG en `tsnode_x25519_shared()` (mbedTLS lo necesita para Curve25519)

### Host test backend (`wg_crypto_host.c`)
- Agregado `host_keygen()` y `host_zeroize()` al vtable

### Logging
- Debug logging en `ts2021.c` para cada paso del Noise handshake
- Debug logging en `wg.c` para WG initiation

## Verificación

### Host tests
- test_h2: 15/15 PASS
- test_blake2s: ALL PASS
- test_replay: ALL PASS
- test_wg: ALL PASS

### ESP32 firmware
- Noise handshake: **ALL steps OK** (random → keygen → pubkey → DH es → AEAD s → DH ss → AEAD ss)
- WG initiation: **created OK (148 bytes)**, **sent to <ip-public>:<port>**
- MapResponse: full netmap with 1 peer, self IP <ip-tailnet>/32

## Pendiente

- WG response + session establishment (necesita auth key válida y peer online)
- Parser self IP (no extrae 100.x.x.x del JSON)
- ts2021.c refactor (crypto vtable para portability)
- Flash encryption
