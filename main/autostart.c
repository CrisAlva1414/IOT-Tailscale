/*
 * Implementación del autostart (ADR-0021 2d).
 *
 * Corrida en tarea de baja prioridad para no bloquear app_main ni la
 * consola. Secuencia por diseño:
 *
 *   1. Esperar WiFi (techo AUTOSTART_WIFI_TIMEOUT_S).
 *   2. Construir la config del cliente: hostname derivado de MAC, endpoint
 *      WireGuard de la IP WiFi, control plane por default.
 *   3. Auth key OPCIONAL: si está en NVS se pasa; si no (ya consumida o
 *      nunca hubo) se pasa NULL y el cliente decide (registro previo ->
 *      node key; sin registro -> TSNODE_ERR_PROVISIONING claro).
 *   4. Arrancar el cliente y esperar ONLINE (techo AUTOSTART_ONLINE_TIMEOUT_S).
 *   5. Alcanzado ONLINE: borrar la auth key de un solo uso (2c). Si el
 *      boot nunca consumió nada (no llegó a ONLINE), la key sobrevive en
 *      NVS para un reintento legítimo — no se borra a ciegas por timeout.
 */

#include "autostart.h"

#include <string.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "prov_store.h"
#include "tsnode_client.h"
#include "wifi_app.h"

#define TAG "autostart"

#define AUTOSTART_WIFI_TIMEOUT_S   30
#define AUTOSTART_ONLINE_TIMEOUT_S 90

#define AUTOSTART_TASK_STACK 4096
#define AUTOSTART_TASK_PRIO  2 /* por debajo de la consola/wifi */

static void autostart_task(void *arg)
{
    (void)arg;

    /* 1. WiFi, con techo (ADR-0021 2d). Si no hay credenciales en NVS,
     * wifi_app queda esperando provisioning por consola: autostart sale
     * y 'tskey set' + 'wifi set' lo vuelven a disparar. */
    for (int i = 0; i < AUTOSTART_WIFI_TIMEOUT_S && !wifi_app_is_connected();
         i++) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    if (!wifi_app_is_connected()) {
        ESP_LOGW(TAG, "wifi no conectada en %ds — autostart abortado",
                 AUTOSTART_WIFI_TIMEOUT_S);
        vTaskDelete(NULL);
        return;
    }

    /* 2. Config del cliente. Los buffers son stack del caller: el cliente
     * los COPIA a storage propio en tsnode_client_start(). */
    tsnode_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.control_host = "controlplane.tailscale.com";
    cfg.control_port = 80;

    char hostname[TSNODE_CLIENT_HOSTNAME_MAX];
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(hostname, sizeof(hostname), "esp32-%02x%02x%02x",
             mac[3], mac[4], mac[5]);
    cfg.hostname = hostname;

    char ip_buf[16] = {0};
    wifi_app_get_ip(ip_buf, sizeof(ip_buf));
    if (ip_buf[0] != '\0') {
        unsigned a, b, c, d;
        if (sscanf(ip_buf, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            cfg.endpoint_ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                              ((uint32_t)c << 8) | (uint32_t)d;
            cfg.endpoint_port = 51820;
        }
    }

    /* 3. Auth key opcional (ADR-0021 2b/2c). */
    char auth_key[PROV_TSKEY_MAX_LEN];
    tsnode_err_t terr = prov_store_get_tskey(auth_key, sizeof(auth_key));
    if (terr == TSNODE_OK) {
        cfg.auth_key = auth_key;
    } else if (terr != TSNODE_ERR_NOT_INITIALIZED) {
        ESP_LOGW(TAG, "lectura de auth key falló (%d) — arranco sin ella",
                 terr);
        /* Sin key: el cliente decide si es legal (identidad registrada). */
    }

    /* 4. Arranque + espera ONLINE con techo. */
    terr = tsnode_client_start(&cfg);
    if (terr != TSNODE_OK) {
        ESP_LOGE(TAG, "tsnode_client_start: %s (%d)", tsnode_err_name(terr),
                 terr);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "cliente arrancado, esperando ONLINE (techo %ds)...",
             AUTOSTART_ONLINE_TIMEOUT_S);

    for (int i = 0; i < AUTOSTART_ONLINE_TIMEOUT_S; i++) {
        tsnode_client_state_t st = TSNODE_CLIENT_IDLE;
        if (tsnode_client_state_get(&st) == TSNODE_OK &&
            st == TSNODE_CLIENT_ONLINE) {
            /* 5. ONLINE: la auth key de un solo uso ya cumplió. Si falla el
             * wipe lo logueamos: no es fatal, pero queda material de
             * registro reutilizable en reposo (ADR-0021 2c). */
            terr = prov_store_wipe_tskey();
            if (terr == TSNODE_OK) {
                ESP_LOGI(TAG, "ONLINE — auth key de un solo uso borrada de "
                              "NVS (ADR-0021 2c)");
            } else {
                ESP_LOGW(TAG, "ONLINE pero falló prov_store_wipe_tskey: %d",
                         terr);
            }
            vTaskDelete(NULL);
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    ESP_LOGW(TAG, "sin ONLINE en %ds — la auth key se conserva (el registro "
                  "no se consumió)",
             AUTOSTART_ONLINE_TIMEOUT_S);
    vTaskDelete(NULL);
}

tsnode_err_t autostart_start(void)
{
    /* No duplicar si el cliente ya está en pleno arranque/operación: el
     * 'tskey set' de la consola también dispara esto y no debe spamear
     * tareas de autostart ni pisar un flujo manual en curso. */
    tsnode_client_state_t st = TSNODE_CLIENT_IDLE;
    if (tsnode_client_state_get(&st) == TSNODE_OK) {
        switch (st) {
        case TSNODE_CLIENT_FETCHING_KEY:
        case TSNODE_CLIENT_HANDSHAKING:
        case TSNODE_CLIENT_REGISTERING:
        case TSNODE_CLIENT_MAP_SYNC:
        case TSNODE_CLIENT_ONLINE:
            ESP_LOGI(TAG, "cliente ya activo (state=%d) — autostart no-op",
                     (int)st);
            return TSNODE_OK;
        default:
            break; /* IDLE / DONE / ERROR: se puede (re)arrancar */
        }
    }

    if (xTaskCreate(autostart_task, "autostart", AUTOSTART_TASK_STACK, NULL,
                    AUTOSTART_TASK_PRIO, NULL) != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(autostart) falló");
        return TSNODE_ERR_NO_MEMORY;
    }
    return TSNODE_OK;
}