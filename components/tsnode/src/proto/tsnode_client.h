/*
 * Cliente Tailscale: ciclo de vida completo (ADR-0008).
 *
 * Orquesta: fetch control key → Noise handshake → register → map poll.
 * Ejecuta como tarea FreeRTOS dedicada.
 *
 * Este archivo es C puro: sin headers de plataforma (ADR-0006).
 */

#ifndef TSNODE_CLIENT_H
#define TSNODE_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tsnode_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Client state (visible to app for status reporting) */
typedef enum {
    TSNODE_CLIENT_IDLE = 0,
    TSNODE_CLIENT_FETCHING_KEY,
    TSNODE_CLIENT_HANDSHAKING,
    TSNODE_CLIENT_REGISTERING,
    TSNODE_CLIENT_MAP_SYNC,
    TSNODE_CLIENT_ONLINE,
    /* Ciclo one-shot completado: la tarea se auto-borró. Permite reiniciar. */
    TSNODE_CLIENT_DONE,
    TSNODE_CLIENT_ERROR,
} tsnode_client_state_t;

/* Límites de los strings que el cliente copia a storage propio en
 * tsnode_client_start() — el caller puede usar stack sin riesgo. */
#define TSNODE_CLIENT_HOSTNAME_MAX 64  /* 63 + NUL */
#define TSNODE_CLIENT_AUTHKEY_MAX 128  /* igual a PROV_TSKEY_MAX_LEN */
#define TSNODE_CLIENT_CTRLHOST_MAX 64

/* Client configuration (set before starting) */
typedef struct {
    const char *control_host;       /* "controlplane.tailscale.com" */
    uint16_t    control_port;       /* 80 for HTTP upgrade */
    const char *auth_key;           /* tskey-auth-...; NULL si la identidad ya
                                       está registrada (regdone, ADR-0021) */
    const char *hostname;           /* node hostname */
    uint8_t     machine_key_priv[32]; /* our machine key (or zeroed to generate) */
    /* WireGuard UDP endpoint (IP:port) — sent in MapRequest for connectivity */
    uint32_t    endpoint_ip;        /* host byte order, 0 = omit */
    uint16_t    endpoint_port;      /* WG listen port, 0 = omit */
    /* TEST-ONLY: si no NULL, salta el fetch de /key y usa esta hex de 64
     * chars como control key (para apuntar al server Go local). */
    const char *control_key_hex;
} tsnode_client_config_t;

/*
 * Start the Tailscale client task.
 * Requires: WiFi connected. auth_key solo es obligatorio si la identidad
 * NVS no completó aún el registro (ADR-0021): con regdone, el nodo se
 * autentica con su node key persistida.
 * El cliente COPIA el struct Y los strings (control_host, auth_key,
 * hostname) a storage propio: los punteros del caller pueden ser stack.
 */
tsnode_err_t tsnode_client_start(const tsnode_client_config_t *config);

/*
 * Erase the persisted identity (machine + node key) from NVS.
 * The next client start generates a fresh identity, which registers
 * as a NEW node (requires device approval again).
 */
void tsnode_client_forget_identity(void);

/*
 * Stop the client and disconnect from tailnet.
 */
tsnode_err_t tsnode_client_stop(void);

/*
 * Get current client state (for status display).
 */
tsnode_err_t tsnode_client_state_get(tsnode_client_state_t *out_state);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_CLIENT_H */
