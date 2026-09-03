# Componente reutilizable tsnode — frontera y capas en ADR-0005/0006.
# REQUIRES mínimos: solo lo que el port usa hoy (RNG hardware, esp_timer,
# networking/TLS para ts2021). Cada dependencia se agrega junto con su
# primer uso real, nunca adelantada.
idf_component_register(
    SRCS "src/tsnode.c"
         "src/port/esp_idf/tsnode_port_esp_idf.c"
         "src/port/esp_idf/tsnode_port_net_esp_idf.c"
         "src/port/esp_idf/tsnode_port_kv_esp_idf.c"
         "src/port/esp_idf/x25519_wrapper.c"
         "src/crypto/blake2s.c"
         "src/crypto/base64.c"
         "src/crypto/hmac_blake2s.c"
         "src/crypto/nacl_box.c"
         "${PROJECT_DIR}/third_party/salsa20poly1305/salsa20.c"
         "${PROJECT_DIR}/third_party/salsa20poly1305/poly1305.c"
         "src/wg/wg.c"
         "src/wg/replay.c"
         "src/wg/wg_crypto_mbedtls.c"
         "src/disco/disco.c"
         "src/proto/ts2021.c"
         "src/proto/h2.c"
         "src/proto/tsnode_register.c"
         "src/proto/tsnode_map.c"
         "src/proto/tsnode_client.c"
    INCLUDE_DIRS "include" "src/proto"
    PRIV_INCLUDE_DIRS "src" "src/port" "src/crypto" "src/wg" "src/disco"
                      "${PROJECT_DIR}/third_party/salsa20poly1305"
    REQUIRES esp_hw_support esp_timer mbedtls esp_netif nvs_flash lwip
)
