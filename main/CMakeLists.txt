# App de referencia del banco de pruebas (ADR-0006: capa de aplicación).
idf_component_register(
    SRCS "main.c"
         "console.c"
         "wifi_app.c"
         "prov_store.c"
         "tsnode_simple.c"
         "display.c"
         "autostart.c"
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
