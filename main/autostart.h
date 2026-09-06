/*
 * Arranque automático del cliente tsnode al boot (ADR-0021 2d).
 *
 * Flujo: espera WiFi (techo 30s), arranca tsnode_client con credenciales
 * de NVS (auth key opcional: puede estar ya consumida/borrada), espera
 * ONLINE (techo 90s) y solo entonces borra la auth key de un solo uso
 * (2c). Idempotente y no duplica si el cliente ya corre.
 */

#ifndef AUTOSTART_H
#define AUTOSTART_H

#include "tsnode_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Dispara el flujo de autostart (tarea de baja prioridad). Puede llamarse
 * en cualquier momento: si el cliente ya está activo, es no-op.
 * También la consola lo invoca tras 'tskey set' (provisioning tardío).
 */
tsnode_err_t autostart_start(void);

#ifdef __cplusplus
}
#endif

#endif /* AUTOSTART_H */