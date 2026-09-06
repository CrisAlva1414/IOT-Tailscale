/*
 * App de referencia del banco de pruebas.
 *
 * Capa de aplicación (ADR-0006): Wi-Fi + consola de provisioning viven
 * acá, no en el componente. El cliente Tailscale se arranca después de
 * WiFi y provisioning exitosos.
 *
 * === API SIMPLE (para otros proyectos) ===
 *
 * Para usar tsnode en tu proyecto, copia tsnode_simple.c/h a tu main/ y:
 *
 *   #include "tsnode.h"
 *   void app_main(void) {
 *       nvs_flash_init();
 *       tsnode_init();
 *       tsnode_start(&(tsnode_app_config_t){
 *           .wifi_ssid = "MiSSID",
 *           .wifi_psk  = "MiPSK",
 *           .ts_auth_key = "tskey-auth-...",
 *       });
 *   }
 *
 * Ver docs/QUICKSTART.md para detalles completos.
 */

#include <nvs_flash.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "autostart.h"
#include "console.h"
#include "display.h"
#include "prov_store.h"
#include "tsnode.h"
#include "tsnode_client.h"
#include "wifi_app.h"

static const char *TAG = "tailnet_init";

static void init_nvs_or_panic(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS requiere formateo (%s)", esp_err_to_name(err));
        err = nvs_flash_erase();
        if (err == ESP_OK) {
            err = nvs_flash_init();
        }
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_flash_init -> %s: sin NVS no hay provisioning",
                 esp_err_to_name(err));
        return;
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "%s", "IOT-Tailscale: app de referencia del banco");

    init_nvs_or_panic();

    tsnode_err_t terr = tsnode_init();
    ESP_LOGI(TAG, "tsnode_init -> %s", tsnode_err_name(terr));

    /* Start WiFi (credentials come from NVS or console provisioning) */
    terr = wifi_app_start();
    ESP_LOGI(TAG, "wifi_app_start -> %s", tsnode_err_name(terr));

    /* Start serial console for debugging/provisioning */
    console_start();

    /* Autostart del cliente tsnode (ADR-0021 2d): si hay credenciales en
     * NVS, conecta por sí solo al boot; si no, espera provisioning y la
     * consola ('tskey set') lo vuelve a disparar. */
    terr = autostart_start();
    ESP_LOGI(TAG, "autostart_start -> %s", tsnode_err_name(terr));
}

/*
 * NOTE: el arranque manual sigue disponible con 'tsconnect' desde la
 * consola (para el matchear contra el stub local: 'tsconnectlocal').
 */
