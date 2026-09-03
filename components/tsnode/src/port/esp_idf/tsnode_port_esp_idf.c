/*
 * Implementación ESP-IDF del port de tsnode (ADR-0006).
 *
 * Único lugar del componente donde se permiten headers de plataforma.
 */

#include <stdarg.h>
#include <stdio.h>

#include <esp_err.h>
#include <esp_log.h>
#include <esp_random.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "tsnode_port.h"

/* ---- Logging ---- */

static tsnode_port_log_fn s_log_fn;

void tsnode_port_set_log(tsnode_port_log_fn fn)
{
    s_log_fn = fn;
}

tsnode_port_log_fn tsnode_port_get_log(void)
{
    return s_log_fn;
}

/* Default log implementation using ESP-IDF esp_log */
/* Tamaño del buffer de formato del mensaje. Debe cubrir la línea más larga
 * que el core pueda emitir: los dumps REG/JSON usan chunks de hasta 200 B
 * más prefijo (~10-40 B). 512 B deja margen holgado sin truncar (GOAL-4).
 * No se usa heap: buffer estático con techo en compile-time (AGENTS.md §4). */
#define TSNODE_DEFAULT_LOG_BUF 512u

static void default_log(int level, const char *tag, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    esp_log_level_t esp_level;
    switch (level) {
    case 0:  esp_level = ESP_LOG_ERROR;   break;
    case 1:  esp_level = ESP_LOG_WARN;    break;
    case 2:  esp_level = ESP_LOG_INFO;    break;
    default: esp_level = ESP_LOG_DEBUG;   break;
    }
    char buf[TSNODE_DEFAULT_LOG_BUF];
    int n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    /* Truncación nunca silenciosa (AGENTS.md §4): si el mensaje no cabía
     * en el buffer se avisa, para que un formato que crezca no pase
     * desapercibido (GOAL-4). */
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        esp_log_write(ESP_LOG_WARN, tag, "[tsnode] log truncated (%d>%u)",
                      n, (unsigned)sizeof(buf));
    }
    /* Use esp_log_write with level and tag only — no timestamp format
     * since ESP-IDF handles that internally. */
    esp_log_write(esp_level, tag, "%s", buf);
}

__attribute__((constructor))
static void init_default_log(void)
{
    s_log_fn = default_log;
}

tsnode_err_t tsnode_port_random_bytes(uint8_t *out, size_t len)
{
    if (out == NULL || len == 0) {
        return TSNODE_ERR_INVALID_ARG;
    }
    /*
     * esp_fill_random: entropía del hardware RNG. Con RF activo (Wi-Fi on)
     * la fuente es de calidad criptográfica; antes de activar RF el
     * bootloader aporta entropía de ruido térmico — suficiente para
     * nonces de sesión, no para claves de largo plazo. La generación de
     * node key ocurre con Wi-Fi ya arriba; verificado en el ADR de
     * arquitectura de protocolo cuando exista.
     */
    esp_fill_random(out, len);
    return TSNODE_OK;
}

tsnode_err_t tsnode_port_uptime_ms(uint64_t *out_ms)
{
    if (out_ms == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    /* esp_timer es monotónico, no depende de NTP ni ajustes de reloj. */
    *out_ms = (uint64_t)esp_timer_get_time() / 1000ULL;
    return TSNODE_OK;
}

tsnode_err_t tsnode_port_task_create(tsnode_port_task_fn fn, void *arg,
                                     const char *name, size_t stack_bytes,
                                     int priority)
{
    if (fn == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    BaseType_t ret = xTaskCreate((TaskFunction_t)fn, name ? name : "tsnode",
                                  (uint32_t)(stack_bytes / sizeof(StackType_t)),
                                  arg, priority, NULL);
    if (ret != pdPASS) {
        return TSNODE_ERR_NO_MEMORY;
    }
    return TSNODE_OK;
}

void tsnode_port_task_delete_self(void)
{
    vTaskDelete(NULL);
}

void tsnode_port_delay_ms(uint32_t ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}
