/*
 * Almacenamiento de credenciales provisionadas (ADR-0007).
 *
 * Namespace NVS dedicado 'tsnode_prov'. Los secretos nunca se loguean;
 * las validaciones son sintácticas antes de persistir. En reposo quedan
 * en claro SOLO en builds de desarrollo del banco (ADR-0003/0007).
 */

#ifndef PROV_STORE_H
#define PROV_STORE_H

#include <stdbool.h>
#include <stddef.h>

#include "tsnode_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROV_SSID_MAX_LEN 33 /* 32 + NUL */
#define PROV_PSK_MAX_LEN 64  /* 63 + NUL */
#define PROV_TSKEY_MAX_LEN 128

/*
 * Persiste credenciales Wi-Fi. Validación: ssid 1..32 bytes, psk 8..63
 * (WPA2). Retorna TSNODE_ERR_INVALID_ARG si no cumplen.
 */
tsnode_err_t prov_store_save_wifi(const char *ssid, const char *psk);

/* Recupera credenciales Wi-Fi. TSNODE_ERR_NOT_INITIALIZED si no hay. */
tsnode_err_t prov_store_get_wifi(char *ssid_out, size_t ssid_out_len,
                                 char *psk_out, size_t psk_out_len);

/* Persiste la auth key. Valida prefijo 'tskey-auth-' (solo sintáctico,
 * ADR-0007: la validez real se demuestra al registrar ante el control
 * plane). */
tsnode_err_t prov_store_save_tskey(const char *key);

/* Recupera la auth key. TSNODE_ERR_NOT_INITIALIZED si no hay. */
tsnode_err_t prov_store_get_tskey(char *key_out, size_t key_out_len);

/* Flags de presencia sin exponer valores. */
tsnode_err_t prov_store_has_wifi(bool *out_ssid, bool *out_psk);
tsnode_err_t prov_store_has_tskey(bool *out_key);

/* Borra todas las credenciales provisionadas. Idempotente. */
tsnode_err_t prov_store_wipe(void);

/*
 * Borra SOLO la auth key de un solo uso (ADR-0021 2c). Una vez que el nodo
 * alcanza ONLINE, esa key ya cumplió su función (y es de un solo uso): si
 * quedara en NVS, un reset posterior con identidad sin registrar (caso
 * límite) la reutilizaría sin necesidad. Las credenciales wifi y la
 * identidad registrada NO se tocan. Idempotente.
 */
tsnode_err_t prov_store_wipe_tskey(void);

#ifdef __cplusplus
}
#endif

#endif /* PROV_STORE_H */
