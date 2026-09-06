/*
 * Consola serie — implementación (ADR-0007).
 *
 * Lectura carácter a carácter con echo controlado: los secretos no se
 * ecoan ni quedan en logs. Buffers acotados en compile-time.
 */

#include "console.h"

#include <driver/uart.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"

#include "autostart.h"
#include "prov_store.h"
#include "tsnode.h"
#include "tsnode_client.h"
#include "wifi_app.h"

#define CONSOLE_TAG "console"
#define CONSOLE_UART UART_NUM_0
#define CONSOLE_LINE_MAX 160
#define CONSOLE_TASK_STACK 4096

/*
 * Echo best-effort: un fallo de escritura al puerto serie solo degrada la
 * interacción humana, sin impacto de seguridad ni de estado; no hay acción
 * recuperable ante ese error en este contexto (banco de pruebas).
 */
static void console_write(const char *s)
{
    (void)uart_write_bytes(CONSOLE_UART, s, strlen(s));
}

static int read_line(char *buf, int max_len, bool echo)
{
    int len = 0;
    while (len < max_len - 1) {
        uint8_t ch = 0;
        int r = uart_read_bytes(CONSOLE_UART, &ch, 1, portMAX_DELAY);
        if (r != 1) {
            continue;
        }
        /* Solo '\r' termina línea: los clientes serie mandan "\r\n" y el
         * '\n' sobrante corrompería la lectura siguiente (bug visto en
         * banco). El '\n' se ignora siempre. */
        if (ch == '\r') {
            if (echo) {
                console_write("\r\n");
            }
            break;
        }
        if (ch == '\n') {
            continue;
        }
        if (ch == 0x08 || ch == 0x7f) { /* backspace / DEL */
            if (len > 0) {
                len--;
                if (echo) {
                    console_write("\b \b");
                }
            }
            continue;
        }
        if (ch < 0x20 || ch > 0x7e) {
            continue; /* solo printable ASCII */
        }
        buf[len++] = (char)ch;
        if (echo) {
            console_write((const char *)&ch);
        }
    }
    buf[len] = '\0';
    return len;
}

static void cmd_help(void)
{
    console_write(
        "comandos:\r\n"
        "  help                  esta ayuda\r\n"
        "  wifi set <ssid>       pide PSK sin echo, guarda y conecta\r\n"
        "  tskey set             pide auth key sin echo, valida prefijo\r\n"
        "  tsconnect             conecta a la tailnet (requiere wifi + tskey)\r\n"
        "  tsstop                detiene el cliente tailscale\r\n"
        "  tsconnectlocal <host> <port> [key]   test contra stub local\r\n"
        "  tsforget              borra identidad persistida (nodo nuevo al reconectar)\r\n"
        "  status                estado tsnode + wi-fi + IP\r\n"
        "  provision status      que credenciales hay cargadas\r\n"
        "  provision wipe        borra credenciales provisionadas\r\n"
        "  reboot                reinicia el dispositivo\r\n");
}

static void cmd_wifi_set(char *rest)
{
    if (rest == NULL || strlen(rest) == 0 || strlen(rest) > 32) {
        console_write("uso: wifi set <ssid> (1..32 chars)\r\n");
        return;
    }
    char psk[PROV_PSK_MAX_LEN];
    console_write("PSK (sin echo): ");
    read_line(psk, sizeof(psk), false);
    tsnode_err_t terr = prov_store_save_wifi(rest, psk);
    if (terr != TSNODE_OK) {
        /* La PSK sale de alcance sin loguearse jamás (ADR-0007). */
        memset(psk, 0, sizeof(psk));
        console_write("error guardando: ");
        console_write(tsnode_err_name(terr));
        console_write("\r\n");
        return;
    }
    terr = wifi_app_apply_credentials(rest, psk);
    memset(psk, 0, sizeof(psk));
    if (terr != TSNODE_OK) {
        console_write("guardado, pero connect fallo (ver log)\r\n");
        return;
    }
    console_write("guardado. conectando...\r\n");
}

static void cmd_tskey_set(void)
{
    char key[PROV_TSKEY_MAX_LEN];
    console_write("auth key (sin echo): ");
    read_line(key, sizeof(key), false);
    tsnode_err_t terr = prov_store_save_tskey(key);
    memset(key, 0, sizeof(key));
    if (terr != TSNODE_OK) {
        console_write("invalida (prefijo 'tskey-auth-' requerido) o error NVS\r\n");
        return;
    }
    console_write("guardada. se consumira al registrar contra el control plane\r\n");

    /* Provisioning tardío: si el boot ocurrió sin credenciales, autostart
     * ya salió sin hacer nada. Con la key recién guardada se re-dispara
     * (ADR-0021 2d). Si el cliente ya corre, es no-op. */
    (void)autostart_start();
}

static void cmd_status(void)
{
    char line[96];
    tsnode_state_t state = TSNODE_STATE_STOPPED;
    if (tsnode_state_get(&state) != TSNODE_OK) {
        state = TSNODE_STATE_ERROR;
    }
    if (wifi_app_is_connected()) {
        char ip[16];
        wifi_app_get_ip(ip, sizeof(ip));
        snprintf(line, sizeof(line), "tsnode: %s | wifi: up | ip: %s\r\n",
                 tsnode_state_name(state), ip);
    } else {
        snprintf(line, sizeof(line), "tsnode: %s | wifi: down\r\n",
                 tsnode_state_name(state));
    }
    console_write(line);
}

static void cmd_provision_status(void)
{
    bool has_ssid = false;
    bool has_psk = false;
    bool has_key = false;
    char line[80];
    tsnode_err_t terr = prov_store_has_wifi(&has_ssid, &has_psk);
    if (terr == TSNODE_OK) {
        terr = prov_store_has_tskey(&has_key);
    }
    if (terr != TSNODE_OK) {
        snprintf(line, sizeof(line), "provision: error %s\r\n",
                 tsnode_err_name(terr));
        console_write(line);
        return;
    }
    char ssid[PROV_SSID_MAX_LEN];
    char psk[PROV_PSK_MAX_LEN];
    ssid[0] = '\0';
    if (has_ssid &&
        prov_store_get_wifi(ssid, sizeof(ssid), psk, sizeof(psk)) == TSNODE_OK) {
        snprintf(line, sizeof(line), "wifi ssid: '%s' | psk: cargada\r\n", ssid);
    } else {
        snprintf(line, sizeof(line), "wifi: sin credenciales\r\n");
    }
    console_write(line);
    snprintf(line, sizeof(line), "auth key: %s\r\n",
             has_key ? "cargada" : "no cargada");
    console_write(line);
}

static void tsconnect_common(const char *host, uint16_t port,
                             const char *control_key_hex)
{
    if (!wifi_app_is_connected()) {
        console_write("error: wifi no conectada\r\n");
        return;
    }

    /* auth key OPCIONAL (ADR-0021): tras el primer registro exitoso se borra
     * de NVS (2c) y el nodo se autentica con su node key persistida. Si no
     * hay key Y la identidad no está registrada, el cliente responde con
     * TSNODE_ERR_PROVISIONING y log claro. */
    char auth_key[PROV_TSKEY_MAX_LEN];
    const char *auth_key_used = NULL;
    tsnode_err_t terr = prov_store_get_tskey(auth_key, sizeof(auth_key));
    if (terr == TSNODE_OK) {
        auth_key_used = auth_key;
    } else if (terr != TSNODE_ERR_NOT_INITIALIZED) {
        console_write("error leyendo auth key de NVS\r\n");
        return;
    }

    /* Get hostname from ESP32 MAC */
    char hostname[32];
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(hostname, sizeof(hostname), "esp32-%02x%02x%02x",
             mac[3], mac[4], mac[5]);

    /* Get WiFi IP for WireGuard endpoint */
    char ip_buf[16] = {0};
    wifi_app_get_ip(ip_buf, sizeof(ip_buf));
    uint32_t endpoint_ip = 0;
    uint16_t endpoint_port = 0;
    if (ip_buf[0] != '\0') {
        unsigned a, b, c, d;
        if (sscanf(ip_buf, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            endpoint_ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                          ((uint32_t)c << 8) | (uint32_t)d;
            endpoint_port = 51820;
        }
    }

    tsnode_client_config_t cfg = {
        .control_host = host,
        .control_port = port,
        .auth_key = auth_key_used,
        .hostname = hostname,
        .endpoint_ip = endpoint_ip,
        .endpoint_port = endpoint_port,
        .control_key_hex = control_key_hex,
    };
    memset(cfg.machine_key_priv, 0, sizeof(cfg.machine_key_priv));

    terr = tsnode_client_start(&cfg);
    memset(auth_key, 0, sizeof(auth_key));

    if (terr != TSNODE_OK) {
        console_write("error arrancando cliente: ");
        console_write(tsnode_err_name(terr));
        console_write("\r\n");
        return;
    }
    console_write("cliente iniciado (ver logs)\r\n");
}

static void cmd_tsconnect(void)
{
    tsconnect_common("controlplane.tailscale.com", 80, NULL);
}

/* TEST-ONLY: contra un server stub local (ej. goenv/) con upgrade HTTP.
 * Host, puerto y key opcional entran por consola, nunca hardcoded (ADR-0010).
 * La auth key puede ser inválida: el stub solo loguea el request. */
static void cmd_tsconnectlocal(char *rest)
{
    char host[TSNODE_CLIENT_CTRLHOST_MAX];
    uint16_t port = 0;

    char *save = NULL;
    char *tok = strtok_r(rest, " ", &save);
    if (tok == NULL || strlen(tok) >= sizeof(host)) {
        console_write("uso: tsconnectlocal <host> <port> [key-hex-64]\r\n");
        return;
    }
    strncpy(host, tok, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';

    tok = strtok_r(NULL, " ", &save);
    if (tok == NULL) {
        console_write("uso: tsconnectlocal <host> <port> [key-hex-64]\r\n");
        return;
    }
    char *end = NULL;
    long val = strtol(tok, &end, 10);
    if (end == tok || *end != '\0' || val < 1 || val > 65535) {
        console_write("puerto invalido\r\n");
        return;
    }
    port = (uint16_t)val;

    const char *key_hex = strtok_r(NULL, " ", &save);

    tsconnect_common(host, port, key_hex);
}

static void cmd_tsforget(void)
{
    tsnode_client_forget_identity();
    console_write("identidad borrada: proximo connect registra nodo nuevo\r\n");
}

static void cmd_tsstop(void)
{
    tsnode_err_t err = tsnode_client_stop();
    if (err == TSNODE_OK) {
        console_write("cliente detenido\r\n");
    } else {
        console_write("error deteniendo cliente\r\n");
    }
}

static void dispatch(char *line)
{
    if (strncmp(line, "help", 4) == 0) {
        cmd_help();
        return;
    }
    if (strncmp(line, "wifi set ", 9) == 0) {
        cmd_wifi_set(line + 9);
        return;
    }
    if (strcmp(line, "tskey set") == 0) {
        cmd_tskey_set();
        return;
    }
    if (strcmp(line, "tsconnect") == 0) {
        cmd_tsconnect();
        return;
    }
    if (strcmp(line, "tsstop") == 0) {
        cmd_tsstop();
        return;
    }
    if (strncmp(line, "tsconnectlocal ", 15) == 0) {
        cmd_tsconnectlocal(line + 15);
        return;
    }
    if (strcmp(line, "tsforget") == 0) {
        cmd_tsforget();
        return;
    }
    if (strcmp(line, "status") == 0) {
        cmd_status();
        return;
    }
    if (strcmp(line, "provision status") == 0) {
        cmd_provision_status();
        return;
    }
    if (strcmp(line, "provision wipe") == 0) {
        tsnode_err_t terr = prov_store_wipe();
        console_write(terr == TSNODE_OK ? "credenciales borradas\r\n"
                                        : "error borrando\r\n");
        return;
    }
    if (strcmp(line, "reboot") == 0) {
        console_write("reiniciando...\r\n");
        esp_restart();
        return;
    }
    console_write("comando desconocido; 'help' para ayuda\r\n");
}

static void console_task(void *arg)
{
    /* arg sin uso: convención FreeRTOS. */
    (void)arg;
    char line[CONSOLE_LINE_MAX];
    console_write("\r\ntsnode console (ADR-0007) — 'help'\r\n");
    for (;;) {
        console_write("tsnode> ");
        read_line(line, sizeof(line), true);
        if (line[0] != '\0') {
            dispatch(line);
        }
    }
}

void console_start(void)
{
    uart_config_t cfg = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    esp_err_t err = uart_param_config(CONSOLE_UART, &cfg);
    if (err == ESP_OK) {
        err = uart_set_pin(CONSOLE_UART, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE,
                           UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    }
    if (err == ESP_OK) {
        /* RX con buffer propio; TX best-effort sin buffer (bloqueante). */
        err = uart_driver_install(CONSOLE_UART, 256, 0, 0, NULL, 0);
    }
    if (err != ESP_OK) {
        ESP_LOGE(CONSOLE_TAG, "uart init -> %s", esp_err_to_name(err));
        return;
    }
    BaseType_t ok = xTaskCreate(console_task, "console", CONSOLE_TASK_STACK,
                                NULL, tskIDLE_PRIORITY + 2, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(CONSOLE_TAG, "xTaskCreate consola fallo");
    }
}
