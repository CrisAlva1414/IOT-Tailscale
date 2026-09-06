# App de referencia del banco de pruebas (ADR-0006: capa de aplicación).
set(APP_SRCS
    "main.c"
    "console.c"
    "wifi_app.c"
    "prov_store.c"
    "tsnode_simple.c"
    "autostart.c"
)

# display.c es el driver ILI9342 del M5Stack Core 2 y usa SPI3_HOST, que
# ESP32-C3/C6 no exponen (solo SPI2). Se compila solo donde el periférico
# existe (esp32/esp32s3); en C3/C6 el app de referencia queda sin display
# pero el core/tsnode y el resto del app compilan igual (ADR-0006 Tier 1).
if(CONFIG_IDF_TARGET_ESP32 OR CONFIG_IDF_TARGET_ESP32S3)
    list(APPEND APP_SRCS "display.c")
endif()

idf_component_register(
    SRCS ${APP_SRCS}
    INCLUDE_DIRS "."
    REQUIRES tsnode nvs_flash esp_wifi esp_event esp_netif driver
)

# -Werror es intencional y no negociable — ver AGENTS.md §4.
#
# Sin -Wpedantic: los headers de ESP-IDF/newlib disparan pedwarns del
# preprocesador (#include_next) que ni el dialecto gnu ni los pragmas
# scoped suprimen. Detalle y compensación en docs/format/c-style.md.
target_compile_options(${COMPONENT_LIB} PRIVATE
    -std=gnu11
    -Wall
    -Wextra
    -Werror
)
