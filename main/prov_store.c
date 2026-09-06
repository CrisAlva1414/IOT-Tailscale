/*
 * Implementación de prov_store sobre NVS (ADR-0007).
 */

#include "prov_store.h"

#include <string.h>

#include "nvs.h"
#include "nvs_flash.h"

#define PROV_NAMESPACE "tsnode_prov"
#define TSKEY_PREFIX "tskey-auth-"

static tsnode_err_t nvs_to_tsnode(esp_err_t err)
{
    switch (err) {
    case ESP_OK:
        return TSNODE_OK;
    case ESP_ERR_NVS_NOT_FOUND:
        return TSNODE_ERR_NOT_INITIALIZED;
    default:
        return TSNODE_ERR_STORAGE;
    }
}

static bool valid_ssid(const char *ssid)
{
    size_t len = strlen(ssid);
    return len >= 1 && len <= 32;
}

static bool valid_psk(const char *psk)
{
    size_t len = strlen(psk);
    return len >= 8 && len <= 63;
}

static bool valid_tskey(const char *key)
{
    size_t len = strlen(key);
    return len > sizeof(TSKEY_PREFIX) && len < PROV_TSKEY_MAX_LEN &&
           strncmp(key, TSKEY_PREFIX, sizeof(TSKEY_PREFIX) - 1) == 0;
}

tsnode_err_t prov_store_save_wifi(const char *ssid, const char *psk)
{
    if (ssid == NULL || psk == NULL || !valid_ssid(ssid) || !valid_psk(psk)) {
        return TSNODE_ERR_INVALID_ARG;
    }
    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(PROV_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return nvs_to_tsnode(err);
    }
    err = nvs_set_str(h, "wifi_ssid", ssid);
    if (err == ESP_OK) {
        err = nvs_set_str(h, "wifi_psk", psk);
    }
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return nvs_to_tsnode(err);
}

tsnode_err_t prov_store_get_wifi(char *ssid_out, size_t ssid_out_len,
                                 char *psk_out, size_t psk_out_len)
{
    if (ssid_out == NULL || psk_out == NULL || ssid_out_len < PROV_SSID_MAX_LEN ||
        psk_out_len < PROV_PSK_MAX_LEN) {
        return TSNODE_ERR_INVALID_ARG;
    }
    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(PROV_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return nvs_to_tsnode(err);
    }
    size_t ssid_len = ssid_out_len;
    err = nvs_get_str(h, "wifi_ssid", ssid_out, &ssid_len);
    if (err == ESP_OK) {
        size_t psk_len = psk_out_len;
        err = nvs_get_str(h, "wifi_psk", psk_out, &psk_len);
    }
    nvs_close(h);
    return nvs_to_tsnode(err);
}

tsnode_err_t prov_store_save_tskey(const char *key)
{
    if (key == NULL || !valid_tskey(key)) {
        return TSNODE_ERR_INVALID_ARG;
    }
    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(PROV_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return nvs_to_tsnode(err);
    }
    err = nvs_set_str(h, "ts_auth_key", key);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return nvs_to_tsnode(err);
}

tsnode_err_t prov_store_get_tskey(char *key_out, size_t key_out_len)
{
    if (key_out == NULL || key_out_len < PROV_TSKEY_MAX_LEN) {
        return TSNODE_ERR_INVALID_ARG;
    }
    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(PROV_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return nvs_to_tsnode(err);
    }
    size_t len = key_out_len;
    err = nvs_get_str(h, "ts_auth_key", key_out, &len);
    nvs_close(h);
    return nvs_to_tsnode(err);
}

tsnode_err_t prov_store_has_wifi(bool *out_ssid, bool *out_psk)
{
    if (out_ssid == NULL || out_psk == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    *out_ssid = false;
    *out_psk = false;
    char ssid[PROV_SSID_MAX_LEN];
    char psk[PROV_PSK_MAX_LEN];
    tsnode_err_t terr = prov_store_get_wifi(ssid, sizeof(ssid), psk, sizeof(psk));
    if (terr == TSNODE_OK) {
        *out_ssid = true;
        *out_psk = true;
        return TSNODE_OK;
    }
    if (terr == TSNODE_ERR_NOT_INITIALIZED) {
        return TSNODE_OK;
    }
    return terr;
}

tsnode_err_t prov_store_has_tskey(bool *out_key)
{
    if (out_key == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    *out_key = false;
    char key[PROV_TSKEY_MAX_LEN];
    tsnode_err_t terr = prov_store_get_tskey(key, sizeof(key));
    if (terr == TSNODE_OK) {
        *out_key = true;
        return TSNODE_OK;
    }
    if (terr == TSNODE_ERR_NOT_INITIALIZED) {
        return TSNODE_OK;
    }
    return terr;
}

tsnode_err_t prov_store_wipe(void)
{
    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(PROV_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return nvs_to_tsnode(err);
    }
    err = nvs_erase_all(h);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return nvs_to_tsnode(err);
}

tsnode_err_t prov_store_wipe_tskey(void)
{
    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(PROV_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return nvs_to_tsnode(err);
    }
    err = nvs_erase_key(h, "ts_auth_key");
    if (err == ESP_OK) {
        err = nvs_commit(h);
    } else if (err == ESP_ERR_NVS_NOT_FOUND) {
        /* Idempotente: no había key que borrar. */
        err = ESP_OK;
    }
    nvs_close(h);
    return nvs_to_tsnode(err);
}
