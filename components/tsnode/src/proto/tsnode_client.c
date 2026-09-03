/*
 * Cliente Tailscale: ciclo de vida completo (ADR-0008).
 *
 * Orquesta: fetch control key → Noise handshake → register → map poll.
 * Ejecuta como tarea FreeRTOS dedicada.
 */

#include "tsnode_client.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "ts2021.h"
#include "h2.h"
#include "tsnode_map.h"
#include "tsnode_port.h"
#include "tsnode_register.h"
#include "x25519_wrapper.h"
#include "base64.h"
#include "wg.h"
#include "disco.h"

/* Port layer provides all platform abstractions (ADR-0006) */

#define TAG "tsnode_client"

/* ---- WG packet counters (Fase 1 instrumentation) ---- */
typedef struct {
    uint32_t tx_initiation;
    uint32_t tx_response;
    uint32_t tx_transport;
    uint32_t rx_initiation;
    uint32_t rx_response;
    uint32_t rx_transport;
    uint32_t rx_keepalive;
    uint32_t rx_unknown;
    uint32_t rx_errors;
} wg_pkt_counters_t;

static wg_pkt_counters_t s_wg_counters;

static void wg_log_counters(void)
{
    TSNODE_LOGI(TAG, "WG counters: TX init=%lu resp=%lu data=%lu | RX init=%lu resp=%lu data=%lu keep=%lu err=%lu unk=%lu",
                (unsigned long)s_wg_counters.tx_initiation,
                (unsigned long)s_wg_counters.tx_response,
                (unsigned long)s_wg_counters.tx_transport,
                (unsigned long)s_wg_counters.rx_initiation,
                (unsigned long)s_wg_counters.rx_response,
                (unsigned long)s_wg_counters.rx_transport,
                (unsigned long)s_wg_counters.rx_keepalive,
                (unsigned long)s_wg_counters.rx_errors,
                (unsigned long)s_wg_counters.rx_unknown);
}

/* Persistencia de identidad (ADR-0003): machine key + node key vía el KV
 * del port (NVS en ESP-IDF). En banco de pruebas sin flash encryption los
 * blobs están en claro — aceptado solo para desarrollo (ADR-0003). */
#define TS_ID_NVS_NAMESPACE "tsnode"
static const char *TS_ID_KEY_MACH = "machkey";
static const char *TS_ID_KEY_NODE = "nodekey";

/* Carga la identidad persistida. Si solo uno de los dos blobs es válido,
 * se descartan ambos para no mezclar identidades parciales. */
static bool load_identity(uint8_t mach[32], uint8_t node[32])
{
    bool ok_mach = tsnode_port_kv_get(TS_ID_NVS_NAMESPACE, TS_ID_KEY_MACH,
                                      mach, 32);
    bool ok_node = tsnode_port_kv_get(TS_ID_NVS_NAMESPACE, TS_ID_KEY_NODE,
                                      node, 32);
    if (ok_mach != ok_node) {
        memset(mach, 0, 32);
        memset(node, 0, 32);
        return false;
    }
    return ok_mach && ok_node && mach[0] != 0 && node[0] != 0;
}

static void save_identity(const uint8_t mach[32], const uint8_t node[32])
{
    bool ok_mach = tsnode_port_kv_set(TS_ID_NVS_NAMESPACE, TS_ID_KEY_MACH,
                                      mach, 32);
    bool ok_node = tsnode_port_kv_set(TS_ID_NVS_NAMESPACE, TS_ID_KEY_NODE,
                                      node, 32);
    if (!ok_mach || !ok_node) {
        TSNODE_LOGW(TAG, "identity persist failed");
    } else {
        TSNODE_LOGI(TAG, "identity persisted to NVS");
    }
}

void tsnode_client_forget_identity(void)
{
    tsnode_port_kv_del(TS_ID_NVS_NAMESPACE, TS_ID_KEY_MACH);
    tsnode_port_kv_del(TS_ID_NVS_NAMESPACE, TS_ID_KEY_NODE);
    TSNODE_LOGI(TAG, "identity erased from NVS");
}

#define CONTROL_KEY_BUF_SIZE 1024
#define REGISTER_BUF_SIZE    1024
/* Respuestas HTTP/2 completas (headers h2 ya removidos). RegisterResponse
 * ronda 600 B; 4 KiB es margen holgado (ADR-0009 D3). */
#define REGISTER_RESPONSE_BUF_SIZE 4096
#define MAP_REQUEST_BUF_SIZE 1024
/* MapResponse observado ~17 KB con tailnet chica; 32 KiB estático cubre
 * crecimiento moderado de peers sin heap (ADR-0009 D3). */
#define MAP_RESPONSE_BUF_SIZE 32768

static tsnode_client_state_t s_state = TSNODE_CLIENT_IDLE;
static tsnode_client_config_t s_config;
static ts2021_conn_t s_conn;
static uint8_t s_node_key[32];       /* WireGuard identity key (privada) */
static uint8_t s_node_key_pub[32];   /* pública, para header ts-lb */
static char s_node_key_pub_hex[65];  /* hex string de la pública */

/* Pushback para h2_io_recv: bytes ya extraídos del record layer que son
 * del flujo HTTP/2 (SETTINGS del server cuando no hay EarlyNoise, u
 * overshoot del drain de EarlyNoise). Estático, techo fijo (ADR-0009 D3). */
static uint8_t s_h2_pushback[1024];
static size_t s_h2_pushback_len;
static h2_conn_t s_h2;

/* Buffers grandes fuera del stack: la tarea corre con 40 KB y el pico de
 * crypto (mbedTLS) ya usa buena parte; 32 KB en stack es crash seguro. */
static uint8_t s_reg_resp[REGISTER_RESPONSE_BUF_SIZE];
static uint8_t s_map_resp[MAP_RESPONSE_BUF_SIZE];

/* ---- Timestamp helper for packet logging ---- */
static uint64_t s_start_ms = 0;

static void ts_init(void)
{
    if (s_start_ms == 0) {
        tsnode_port_uptime_ms(&s_start_ms);
    }
}

/* Returns milliseconds since s_start_ms (session-relative timestamp) */
static uint64_t ts_rel_ms(void)
{
    uint64_t now;
    tsnode_port_uptime_ms(&now);
    return now - s_start_ms;
}

/* Forward declarations for WireGuard integration (ADR-0011) */
static tsnode_err_t init_wg_device(void);

/* Forward declarations for Disco (ADR-0014) */
static tsnode_disco_state_t s_disco;
static bool s_disco_initialized = false;
static tsnode_err_t init_wg_socket(void);
static tsnode_err_t update_wg_peers(const tsnode_map_netmap_t *netmap);

/* ---- I/O callbacks para h2 sobre la capa de registros ts2021 ---- */

static tsnode_err_t h2_io_send(void *ctx, const uint8_t *data, size_t len)
{
    return ts2021_record_send((ts2021_conn_t *)ctx, data, len);
}

static tsnode_err_t h2_io_recv(void *ctx, uint8_t *buf, size_t cap,
                                size_t *out_len)
{
    /* Bytes rescatados por el bloque EarlyNoise (Step 6b): registros que ya
     * salieron del record layer pero pertenecen al flujo HTTP/2. Se sirven
     * antes que el transporte para no perderlos ni reordenarlos. */
    if (s_h2_pushback_len > 0) {
        size_t n = (s_h2_pushback_len < cap) ? s_h2_pushback_len : cap;
        memcpy(buf, s_h2_pushback, n);
        memmove(s_h2_pushback, s_h2_pushback + n, s_h2_pushback_len - n);
        s_h2_pushback_len -= n;
        *out_len = n;
        return TSNODE_OK;
    }

    /* Registros Noise de longitud cero son legales (padding del par):
     * se consumen acá para que h2 interprete 0 únicamente como EOF. */
    ts2021_conn_t *conn = (ts2021_conn_t *)ctx;
    do {
        tsnode_err_t err = ts2021_record_recv(conn, buf, cap, out_len);
        if (err != TSNODE_OK) return err;
    } while (*out_len == 0);
    return TSNODE_OK;
}

static void bytes_to_hex_str(char out[65], const uint8_t in[32])
{
    for (int i = 0; i < 32; i++) {
        snprintf(out + i * 2, 3, "%02x", in[i]);
    }
    out[64] = '\0';
}

/* ---- State management ---- */

static void set_state(tsnode_client_state_t state)
{
    s_state = state;
    TSNODE_LOGI(TAG, "state -> %d", (int)state);
}

/* ---- Fetch control server public key from /key?v=145 ---- */

static tsnode_err_t fetch_control_key(uint8_t key_out[32])
{
    set_state(TSNODE_CLIENT_FETCHING_KEY);

    tsnode_port_socket_t *sock = NULL;
    tsnode_err_t err = tsnode_port_tls_connect(&sock, s_config.control_host,
                                                443, 10000);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "TLS connect to %s failed: %d",
                    s_config.control_host, err);
        return err;
    }

    /* Send HTTPS GET /key?v=145 */
    char request[256];
    int n = snprintf(request, sizeof(request),
                     "GET /key?v=145 HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: tsnode/0.1.0\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     s_config.control_host);
    err = tsnode_port_socket_write(sock, (const uint8_t *)request,
                                    (size_t)n, 5000);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "send GET /key failed: %d", err);
        tsnode_port_socket_close(sock);
        return err;
    }

    /* Read response */
    uint8_t resp_buf[CONTROL_KEY_BUF_SIZE];
    size_t total = 0;
    size_t nread;

    while (total < sizeof(resp_buf) - 1) {
        err = tsnode_port_socket_read(sock, resp_buf + total,
                                       sizeof(resp_buf) - total - 1,
                                       &nread, 10000);
        if (err != TSNODE_OK && err != TSNODE_ERR_NETWORK) {
            break;
        }
        total += nread;
        if (nread == 0) break;
    }
    tsnode_port_socket_close(sock);

    resp_buf[total] = '\0';

    /* Debug: log raw response for protocol development */
    TSNODE_LOGI(TAG, "raw /key response (%u bytes): %.200s",
                (unsigned)total, (const char *)resp_buf);

    /* Parse HTTP response: find the JSON body after \r\n\r\n */
    const char *body = strstr((const char *)resp_buf, "\r\n\r\n");
    if (body == NULL) {
        TSNODE_LOGE(TAG, "no HTTP body in /key response");
        return TSNODE_ERR_NETWORK;
    }
    body += 4;

    TSNODE_LOGI(TAG, "key response body (%u bytes): %s",
                (unsigned)strlen(body), body);

    /* Extract "publicKey":"mkey:<hex>" — Noise public key from control server.
     * JSON may have tabs/newlines, so search for the key without strict spacing. */
    const char *pk_marker = "\"publicKey\"";
    const char *pk = strstr(body, pk_marker);
    if (pk != NULL) {
        /* Skip past the key name and any whitespace/colon/quote */
        pk += strlen(pk_marker);
        while (*pk == ' ' || *pk == ':' || *pk == '\t' || *pk == '\n' || *pk == '"') pk++;
        /* Skip "mkey:" prefix if present */
        if (strncmp(pk, "mkey:", 5) == 0) pk += 5;

        TSNODE_LOGI(TAG, "publicKey hex start: %.70s", pk);
        /* Debug: dump all 64 hex chars as codes */
        for (int d = 0; d < 64; d++) {
            char ch = pk[d];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) {
                TSNODE_LOGE(TAG, "BAD hex[%d] = 0x%02x '%c'", d, (uint8_t)ch,
                            (ch >= 0x20 && ch < 0x7f) ? ch : '?');
            }
        }
    }
    if (pk == NULL) {
        TSNODE_LOGE(TAG, "PublicKey not found in /key response");
        return TSNODE_ERR_NETWORK;
    }

    /* Decode hex (64 chars = 32 bytes) */
    for (int i = 0; i < 32; i++) {
        int hi = -1, lo = -1;
        char c;

        c = pk[i * 2];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;

        c = pk[i * 2 + 1];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;

        if (hi < 0 || lo < 0) {
            TSNODE_LOGE(TAG, "invalid hex in PublicKey");
            return TSNODE_ERR_CRYPTO;
        }
        key_out[i] = (uint8_t)((hi << 4) | lo);
    }

    TSNODE_LOGI(TAG, "control key fetched OK");
    return TSNODE_OK;
}

/* ---- Full connection sequence ---- */

static tsnode_err_t do_connect(void)
{
    tsnode_err_t err;

    s_h2_pushback_len = 0;

    /* Step 1: Fetch control server public key */
    uint8_t control_key[32];
    if (s_config.control_key_hex != NULL) {
        /* TEST-ONLY: control key provista (server Go local). */
        if (strlen(s_config.control_key_hex) != 64) {
            return TSNODE_ERR_INVALID_ARG;
        }
        for (int i = 0; i < 32; i++) {
            char hi_c = s_config.control_key_hex[i * 2];
            char lo_c = s_config.control_key_hex[i * 2 + 1];
            int hi = (hi_c >= '0' && hi_c <= '9') ? hi_c - '0'
                   : (hi_c >= 'a' && hi_c <= 'f') ? hi_c - 'a' + 10 : -1;
            int lo = (lo_c >= '0' && lo_c <= '9') ? lo_c - '0'
                   : (lo_c >= 'a' && lo_c <= 'f') ? lo_c - 'a' + 10 : -1;
            if (hi < 0 || lo < 0) return TSNODE_ERR_INVALID_ARG;
            control_key[i] = (uint8_t)((hi << 4) | lo);
        }
        TSNODE_LOGI(TAG, "control key from config (test mode)");
    } else {
        err = fetch_control_key(control_key);
        if (err != TSNODE_OK) return err;
    }

    /* Step 2: identidad — NVS primero (ADR-0003); si no existe, generar y
     * persistir. Con identidad persistida el nodo registrado es SIEMPRE el
     * mismo: la aprobación de device sobrevive reinicios. */
    uint8_t loaded_mach[32] = {0};
    uint8_t loaded_node[32] = {0};
    if (load_identity(loaded_mach, loaded_node)) {
        memcpy(s_config.machine_key_priv, loaded_mach, 32);
        memcpy(s_node_key, loaded_node, 32);
        if (tsnode_x25519_publickey(s_node_key, s_node_key_pub) != 0) {
            return TSNODE_ERR_CRYPTO;
        }
        TSNODE_LOGI(TAG, "identity loaded from NVS");
    } else {
        bool need_gen = true;
        for (int i = 0; i < 32; i++) {
            if (s_config.machine_key_priv[i] != 0) {
                need_gen = false;
                break;
            }
        }
        if (need_gen) {
            /* Use mbedTLS keygen which applies proper X25519 clamping internally */
            uint8_t temp_pub[32];
            if (tsnode_x25519_keygen(s_config.machine_key_priv, temp_pub) != 0) {
                return TSNODE_ERR_CRYPTO;
            }
            TSNODE_LOGI(TAG, "generated new machine key");
        }

        /* Step 2b: Generate node key (WireGuard identity) from random */
        if (tsnode_x25519_keygen(s_node_key, s_node_key_pub) != 0) {
            return TSNODE_ERR_CRYPTO;
        }

        save_identity(s_config.machine_key_priv, s_node_key);
    }

    /* Convert node key public to hex for headers */
    bytes_to_hex_str(s_node_key_pub_hex, s_node_key_pub);

    /* Step 2c: Initialize WireGuard device with node key (ADR-0011) */
    err = init_wg_device();
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "WG device init failed: %d", err);
        return err;
    }

    /* Step 2d: Bind UDP socket for WireGuard traffic (ADR-0011) */
    err = init_wg_socket();
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "WG socket init failed: %d", err);
        return err;
    }

    /* Step 3: Generate Noise initiation before TCP connect */
    ts2021_handshake_state_t hs_state;
    uint8_t noise_init[101];
    /* Protocol version = CurrentCapabilityVersion from tailcfg (145 as of 2026) */
    err = ts2021_handshake_initiate(&hs_state, noise_init,
                                     s_config.machine_key_priv,
                                     control_key, 145);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "Noise initiate failed: %d", err);
        return err;
    }

    /* Base64-encode initiation for HTTP header */
    char init_b64[160];
    size_t b64_len = tsnode_base64_encode(init_b64, sizeof(init_b64), noise_init, 101);
    TSNODE_LOGI(TAG, "init msg [%02x %02x %02x %02x %02x] b64_len=%zu",
                noise_init[0], noise_init[1], noise_init[2],
                noise_init[3], noise_init[4], b64_len);

    /* Step 4: TCP connect to control plane */
    set_state(TSNODE_CLIENT_HANDSHAKING);
    tsnode_port_socket_t *sock = NULL;
    err = tsnode_port_tcp_connect(&sock, s_config.control_host,
                                   s_config.control_port, 10000);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "TCP connect failed: %d", err);
        return err;
    }

    /* Step 5: HTTP upgrade to ts2021 with X-Tailscale-Handshake header */
    char upgrade_req[512];
    int n = snprintf(upgrade_req, sizeof(upgrade_req),
                     "POST /ts2021 HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: tailscale-control-protocol\r\n"
                     "Connection: upgrade\r\n"
                     "X-Tailscale-Handshake: %s\r\n"
                     "\r\n",
                     s_config.control_host, init_b64);
    err = tsnode_port_socket_write(sock, (const uint8_t *)upgrade_req,
                                    (size_t)n, 5000);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "send upgrade request failed");
        tsnode_port_socket_close(sock);
        return err;
    }

    /* Read HTTP 101 response */
    uint8_t resp[256];
    size_t resp_total = 0;
    size_t nread;
    bool got_101 = false;

    while (resp_total < sizeof(resp) - 1) {
        err = tsnode_port_socket_read(sock, resp + resp_total,
                                       sizeof(resp) - resp_total - 1,
                                       &nread, 10000);
        if (err != TSNODE_OK) break;
        resp_total += nread;
        resp[resp_total] = '\0';

        if (strstr((const char *)resp, "\r\n\r\n") != NULL) {
            TSNODE_LOGI(TAG, "upgrade response: %s", (const char *)resp);
            got_101 = (strstr((const char *)resp, "101") != NULL);
            break;
        }
        if (nread == 0) break;
    }

    if (!got_101) {
        TSNODE_LOGE(TAG, "HTTP upgrade failed (no 101)");
        tsnode_port_socket_close(sock);
        return TSNODE_ERR_NETWORK;
    }
    TSNODE_LOGI(TAG, "HTTP 101 Switching Protocols OK");

    /* The HTTP read loop may have already consumed the Noise response
     * bytes along with the HTTP headers. Check for extra bytes. */
    const char *hend = strstr((const char *)resp, "\r\n\r\n");
    size_t hdr_len = (hend != NULL) ? (size_t)(hend - (const char *)resp + 4) : resp_total;
    size_t leftover = resp_total - hdr_len;

    /* Step 6: Read Noise response (51 bytes) and complete handshake */
    uint8_t noise_resp[51];
    size_t resp_read = 0;

    /* If extra bytes were already read from the HTTP loop, use them */
    if (leftover >= 51) {
        memcpy(noise_resp, resp + hdr_len, 51);
        resp_read = 51;
        TSNODE_LOGI(TAG, "Noise response found in HTTP read (%zu extra)", leftover);
        /* Dump extra bytes beyond Noise response to see if server sent more */
        if (leftover > 51) {
            size_t extra = leftover - 51;
            if (extra > 64) extra = 64;
            char hexbuf[133];
            for (size_t i = 0; i < extra; i++) {
                snprintf(hexbuf + i*2, 3, "%02x", (uint8_t)resp[hdr_len + 51 + i]);
            }
            hexbuf[extra*2] = '\0';
            TSNODE_LOGI(TAG, "extra %zu bytes after Noise: %s", extra, hexbuf);
        }
    } else if (leftover > 0) {
        memcpy(noise_resp, resp + hdr_len, leftover);
        resp_read = leftover;
    }

    /* Read remaining bytes from socket */
    while (resp_read < 51) {
        size_t n;
        err = tsnode_port_socket_read(sock, noise_resp + resp_read,
                                       51 - resp_read, &n, 10000);
        if (err != TSNODE_OK || n == 0) break;
        resp_read += n;
    }
    if (err != TSNODE_OK || resp_read != 51) {
        TSNODE_LOGE(TAG, "read Noise response failed: resp_read=%zu err=%d",
                    resp_read, err);
        tsnode_port_socket_close(sock);
        return (err == TSNODE_OK) ? TSNODE_ERR_NETWORK : err;
    }

    err = ts2021_handshake_complete(&s_conn, &hs_state, noise_resp, sock);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "Noise handshake complete failed: %d", err);
        return err;
    }
    TSNODE_LOGI(TAG, "Noise handshake OK");

    /* Prebuffer any leftover bytes from the HTTP read that follow the
     * 51-byte Noise response.  These are server transport frames that
     * arrived in the same TCP segment and must be available to the
     * record layer. */
    if (leftover > 51) {
        ts2021_conn_prebuffer(&s_conn, (const uint8_t *)resp + hdr_len + 51,
                               leftover - 51);
    }

    /* Consume EarlyNoise payload (if present).
     *
     * After the Noise handshake the server may push an "early payload"
     * before any HTTP/2 communication.  Format (from conn.go):
     *   5 bytes: magic "\xff\xff\xffTS"
     *   4 bytes: payload length (big-endian uint32)
     *   N bytes: JSON (e.g. {"nodeKeyChallenge":"chalpub:..."})
     *
     * The Go client's ts2021.Conn.readHeader() silently consumes this.
     * The NodeKeyChallenge content is never used by the Go client, so we
     * simply skip it.
     *
     * The magic and length may span multiple Noise transport records,
     * so we accumulate bytes until we can check for the magic prefix. */
    {
        /* Accumulate at least 9 bytes (magic + length header) from the
         * first Noise record(s).  We keep a small ring buffer for any
         * bytes beyond the header that arrived in the same record. */
        uint8_t early_hdr[9];
        size_t hdr_have = 0;
        uint8_t extra[512] = {0}; /* bytes beyond the 9-byte header */
        size_t extra_len = 0;
        bool is_early = false;

        while (hdr_have < 9) {
            uint8_t frame[512];
            size_t frame_len;
            err = ts2021_record_recv(&s_conn, frame, sizeof(frame), &frame_len);
            if (err != TSNODE_OK) {
                TSNODE_LOGE(TAG, "recv post-handshake frame failed: %d", err);
                tsnode_port_socket_close(sock);
                return err;
            }
            TSNODE_LOGI(TAG, "post-handshake frame: %zu bytes", frame_len);

            /* How many bytes do we need to fill the header? */
            size_t need = 9 - hdr_have;
            size_t take = (frame_len < need) ? frame_len : need;
            memcpy(early_hdr + hdr_have, frame, take);
            hdr_have += take;

            /* Any remaining bytes in this frame are payload data */
            if (frame_len > take) {
                size_t rem = frame_len - take;
                if (rem <= sizeof(extra) - extra_len) {
                    memcpy(extra + extra_len, frame + take, rem);
                    extra_len += rem;
                }
            }

            /* Check magic once we have at least 5 bytes */
            if (hdr_have >= 5 && !is_early) {
                if (early_hdr[0] == 0xff && early_hdr[1] == 0xff &&
                    early_hdr[2] == 0xff && early_hdr[3] == 'T' &&
                    early_hdr[4] == 'S') {
                    is_early = true;
                    TSNODE_LOGI(TAG, "EarlyNoise magic detected");
                } else {
                    /* No es EarlyNoise: es el SETTINGS del server u otro
                     * frame del flujo HTTP/2. Los bytes ya salieron del
                     * record layer, así que van a pushback para que h2 los
                     * consuma en orden — nunca se descartan (ADR-0009). */
                    size_t hdr_bytes = (hdr_have < sizeof(early_hdr))
                                           ? hdr_have : sizeof(early_hdr);
                    size_t total = hdr_have + extra_len;
                    if (total > sizeof(s_h2_pushback)) {
                        TSNODE_LOGE(TAG, "pushback overflow");
                        tsnode_port_socket_close(sock);
                        return TSNODE_ERR_NO_MEMORY;
                    }
                    memcpy(s_h2_pushback, early_hdr, hdr_bytes);
                    memcpy(s_h2_pushback + hdr_bytes, extra, extra_len);
                    s_h2_pushback_len = total;
                    TSNODE_LOGI(TAG, "non-EarlyNoise post-handshake frame "
                                 "(%zu bytes): %zu bytes to h2 pushback",
                                 frame_len, total);
                    break;
                }
            }
        }

        if (is_early && hdr_have == 9) {
            /* Parse payload length from bytes 5-8 */
            uint32_t ep_len = ((uint32_t)early_hdr[5] << 24) |
                              ((uint32_t)early_hdr[6] << 16) |
                              ((uint32_t)early_hdr[7] << 8)  |
                              ((uint32_t)early_hdr[8]);
            TSNODE_LOGI(TAG, "EarlyNoise payload: %u bytes", ep_len);

            /* We already have extra_len bytes of the JSON payload.
             * Drain more records until we've consumed ep_len bytes total.
             * Si un registro excede lo que falta, el sobrante es del flujo
             * HTTP/2 y va a pushback — no se descarta. */
            size_t consumed = extra_len;
            while (consumed < ep_len) {
                uint8_t skip[256];
                size_t skip_len;
                err = ts2021_record_recv(&s_conn, skip, sizeof(skip), &skip_len);
                if (err != TSNODE_OK) break;
                if (consumed + skip_len > ep_len) {
                    size_t over = consumed + skip_len - ep_len;
                    if (over <= sizeof(s_h2_pushback) - s_h2_pushback_len) {
                        memcpy(s_h2_pushback + s_h2_pushback_len,
                               skip + (skip_len - over), over);
                        s_h2_pushback_len += over;
                    }
                    consumed = ep_len;
                    break;
                }
                consumed += skip_len;
            }
            TSNODE_LOGI(TAG, "EarlyNoise skipped (%u bytes, consumed %zu)",
                         ep_len, consumed);
        }
    }

    /* Step 7: HTTP/2 sobre el túnel Noise (ADR-0009).
     * Sin esta capa el server descarta la conexión con "bogus greeting":
     * verificado empíricamente contra controlplane.tailscale.com
     * (sesión 2026-08-23). El SETTINGS del server ya puede estar prebuffered;
     * h2_client_start lo consume del record layer. */
    h2_io_t h2io = {
        .ctx = &s_conn,
        .send_bytes = h2_io_send,
        .recv_record = h2_io_recv,
    };
    err = h2_client_start(&s_h2, &h2io);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "http2 start failed: %d", err);
        return err;
    }
    TSNODE_LOGI(TAG, "http2 over noise OK");

    /* Step 8: Register via POST /machine/register (h2). El header Ts-Lb
     * lleva nuestra node key pública (control/tsp/register.go). */
    set_state(TSNODE_CLIENT_REGISTERING);
    char reg_req[REGISTER_BUF_SIZE];
    size_t reg_len;
    err = tsnode_register_build_request(reg_req, sizeof(reg_req), &reg_len,
                                         s_node_key_pub,
                                         s_config.auth_key,
                                         s_config.hostname,
                                         145); /* CurrentCapabilityVersion */
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "build RegisterRequest failed: %d", err);
        return err;
    }

    char node_key_hex[65];
    bytes_to_hex_str(node_key_hex, s_node_key_pub);
    char lb_value[8 + 64 + 1]; /* "nodekey:" + hex + NUL */
    snprintf(lb_value, sizeof(lb_value), "nodekey:%s", node_key_hex);

    size_t reg_resp_len;
    err = h2_post(&s_h2, s_config.control_host, "/machine/register",
                  lb_value, (const uint8_t *)reg_req, reg_len,
                  s_reg_resp, sizeof(s_reg_resp) - 1, &reg_resp_len);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "register POST failed: %d", err);
        return err;
    }
    /* -1 arriba garantiza lugar para el NUL que exige el parser. */
    s_reg_resp[reg_resp_len] = '\0';
    TSNODE_LOGI(TAG, "RegisterResponse (%zu bytes)", reg_resp_len);
    /* Debug: dump full RegisterResponse */
    {
        size_t chunk = 200;
        for (size_t off = 0; off < reg_resp_len; off += chunk) {
            size_t len = reg_resp_len - off;
            if (len > chunk) len = chunk;
            TSNODE_LOGI(TAG, "REG[%zu]: %.*s", off, (int)len, s_reg_resp + off);
        }
    }

    tsnode_register_response_t reg_result;
    err = tsnode_register_parse_response(&reg_result,
                                          (const char *)s_reg_resp,
                                          reg_resp_len);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "parse RegisterResponse failed: %d", err);
        return err;
    }

    if (reg_result.error[0] != '\0') {
        TSNODE_LOGE(TAG, "registration error: %s", reg_result.error);
        return TSNODE_ERR_NETWORK;
    }

    if (reg_result.auth_url[0] != '\0') {
        /* El control plane pide login interactivo: la auth key no cubrió
         * el registro (expirada, reusada, o ACL). Es un fallo de
         * provisioning, no de protocolo. La URL no contiene secretos. */
        TSNODE_LOGE(TAG, "interactive auth required: %s",
                    reg_result.auth_url);
        return TSNODE_ERR_PROVISIONING;
    }

    if (!reg_result.machine_authorized) {
        /* Auth key aceptada pero device approval pendiente en la tailnet:
         * el nodo queda registrado esperando aprobación humana. */
        TSNODE_LOGW(TAG, "machine not yet authorized (device approval)");
    }
    TSNODE_LOGI(TAG, "registration done");

    /* Step 9: Map sync via POST /machine/map (h2). */
    set_state(TSNODE_CLIENT_MAP_SYNC);
    const uint8_t *dk = tsnode_disco_get_pubkey(&s_disco);
    uint8_t zero_disco[32] = {0};
    char map_req[MAP_REQUEST_BUF_SIZE];
    size_t map_req_len;
    err = tsnode_map_build_request(map_req, sizeof(map_req), &map_req_len,
                                    s_node_key_pub,
                                    dk ? dk : zero_disco,
                                    s_config.hostname,
                                    145, false,
                                    s_config.endpoint_ip,
                                    s_config.endpoint_port);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "build MapRequest failed: %d", err);
        return err;
    }

    size_t map_wire_len;
    err = h2_post(&s_h2, s_config.control_host, "/machine/map",
                  lb_value, (const uint8_t *)map_req, map_req_len,
                  s_map_resp, sizeof(s_map_resp) - 1, &map_wire_len);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "map POST failed: %d", err);
        return err;
    }
    s_map_resp[map_wire_len] = '\0';
    TSNODE_LOGI(TAG, "MapResponse (%zu bytes wire)", map_wire_len);

    const uint8_t *map_json = NULL;
    size_t map_json_len = 0;
    err = tsnode_map_parse_framed(s_map_resp, map_wire_len,
                                   &map_json, &map_json_len);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "parse MapResponse framing failed: %d", err);
        return err;
    }

    tsnode_map_netmap_t netmap;
    err = tsnode_map_parse_response(&netmap, (const char *)map_json,
                                     map_json_len);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "parse MapResponse failed: %d", err);
        return err;
    }

    TSNODE_LOGI(TAG, "netmap: %u peers, self=%s",
                netmap.peer_count, netmap.self_ip);

    set_state(TSNODE_CLIENT_ONLINE);
    return TSNODE_OK;
}

/* ---- Map polling loop ---- */

/* Intervalo base para MapRequest poll (segundos). Backoff exponencial
 * con jitter se aplica en caso de error (ADR-0008 D3). */
#define MAP_POLL_INTERVAL_BASE_S  30
#define MAP_POLL_INTERVAL_MAX_S   300
#define MAP_POLL_JITTER_PCT       20  /* ±20% jitter */

/* WireGuard device and UDP socket for data plane (ADR-0011) */
static tsnode_wg_device_t s_wg_dev;
static tsnode_port_udp_socket_t *s_wg_sock;
#define WG_RECV_BUF_SIZE 1500
#define WG_RECV_QUEUE_LEN 8

static tsnode_err_t init_wg_device(void)
{
    const tsnode_wg_crypto_t *crypto = tsnode_wg_crypto_mbedtls();
    tsnode_err_t err = tsnode_wg_device_init(&s_wg_dev, s_node_key, crypto);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "WG device init failed: %d", err);
        return err;
    }
    TSNODE_LOGI(TAG, "WireGuard device initialized");

    /* Initialize disco subsystem (ADR-0014) */
    err = tsnode_disco_load_or_generate(&s_disco, s_node_key_pub, crypto);
    if (err != TSNODE_OK) {
        TSNODE_LOGW(TAG, "disco init failed: %d (data plane will not work behind NAT)", err);
        /* Non-fatal: data plane may still work for direct connections */
    } else {
        s_disco_initialized = true;
        TSNODE_LOGI(TAG, "Disco subsystem initialized");
    }

    return TSNODE_OK;
}

static tsnode_err_t init_wg_socket(void)
{
    tsnode_err_t err = tsnode_port_udp_bind(&s_wg_sock, 51820);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "WG UDP bind failed: %d", err);
        return err;
    }
    TSNODE_LOGI(TAG, "WireGuard UDP socket bound to port 51820");
    return TSNODE_OK;
}

static int find_peer_by_key(const uint8_t key[32])
{
    for (int i = 0; i < TSNODE_WG_MAX_PEERS; i++) {
        if (s_wg_dev.peers[i].used &&
            memcmp(s_wg_dev.peers[i].cfg.public_key, key, 32) == 0) {
            return i;
        }
    }
    return -1;
}

static tsnode_err_t update_wg_peers(const tsnode_map_netmap_t *netmap)
{
    tsnode_err_t err;

    for (uint8_t i = 0; i < netmap->peer_count; i++) {
        const tsnode_map_peer_t *mp = &netmap->peers[i];

        /* Skip peers without endpoint (unreachable) */
        if (mp->endpoint_port == 0 || mp->endpoint_ip[0] == '\0') {
            continue;
        }

        int idx = find_peer_by_key(mp->key);
        if (idx < 0) {
            /* New peer: add to WG device */
            tsnode_wg_peer_cfg_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            memcpy(cfg.public_key, mp->key, 32);
            memcpy(cfg.preshared_key, mp->preshared_key, 32);
            cfg.allowed_ip = mp->allowed_ip;
            cfg.allowed_mask = mp->allowed_mask;

        idx = tsnode_wg_peer_add(&s_wg_dev, &cfg);
        if (idx < 0) {
            TSNODE_LOGW(TAG, "WG peer_add failed (full or dup?)");
            continue;
        }
        TSNODE_LOGI(TAG, "WG peer added: idx=%d key=...%02x%02x", idx,
                    mp->key[30], mp->key[31]);

        /* Register peer in disco subsystem if we have a disco key */
        if (s_disco_initialized) {
            bool has_disco_key = false;
            for (int k = 0; k < 32; k++) {
                if (mp->disco_key[k] != 0) { has_disco_key = true; break; }
            }
            if (has_disco_key) {
                uint32_t ep_ip = 0;
                if (mp->endpoint_port > 0) {
                    unsigned a, b, c, d;
                    if (sscanf(mp->endpoint_ip, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                        ep_ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                                ((uint32_t)c << 8) | (uint32_t)d;
                    }
                }
                tsnode_disco_add_peer(&s_disco, mp->key, mp->disco_key,
                                      ep_ip ? &ep_ip : NULL,
                                      mp->endpoint_port ? &mp->endpoint_port : NULL,
                                      ep_ip ? 1 : 0);
            }
        }
        }

        /* Initiate handshake if no active session */
        if (!tsnode_wg_peer_has_session(&s_wg_dev, idx)) {
            uint64_t now_ms;
            tsnode_port_uptime_ms(&now_ms);

            /* TAI64N timestamp from uptime (monotonic, always increasing) */
            uint8_t ts[12];
            uint32_t sec = (uint32_t)(now_ms / 1000);
            uint32_t nsec = (uint32_t)((now_ms % 1000) * 1000000);
            ts[0] = (uint8_t)(40); /* TAI64N century: 0x40 = 2000s era */
            ts[1] = (uint8_t)(1);
            ts[2] = (uint8_t)(1);
            ts[3] = (uint8_t)(1);
            ts[4] = (uint8_t)(sec >> 24);
            ts[5] = (uint8_t)(sec >> 16);
            ts[6] = (uint8_t)(sec >> 8);
            ts[7] = (uint8_t)(sec);
            ts[8] = (uint8_t)(nsec >> 24);
            ts[9] = (uint8_t)(nsec >> 16);
            ts[10] = (uint8_t)(nsec >> 8);
            ts[11] = (uint8_t)(nsec);

            uint8_t initiation[TSNODE_WG_INITIATION_LEN];
            TSNODE_LOGI(TAG, "WG TX initiation peer=%d key=...%02x%02x", idx, mp->key[30], mp->key[31]);
            err = tsnode_wg_create_initiation(&s_wg_dev, idx, ts, initiation);
            if (err != TSNODE_OK) {
                TSNODE_LOGE(TAG, "WG create_initiation failed: %d (peer %d)", err, idx);
                continue;
            }
            TSNODE_LOGI(TAG, "WG TX initiation ready %d bytes t=%lu ms", TSNODE_WG_INITIATION_LEN, (unsigned long)ts_rel_ms());

            /* Parse endpoint IP for sendto */
            uint32_t ep_ip = 0;
            {
                unsigned a, b, c, d;
                if (sscanf(mp->endpoint_ip, "%u.%u.%u.%u",
                           &a, &b, &c, &d) == 4) {
                    ep_ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                            ((uint32_t)c << 8) | (uint32_t)d;
                }
            }

            err = tsnode_port_udp_sendto(s_wg_sock, initiation,
                                          sizeof(initiation),
                                          ep_ip, mp->endpoint_port);
            if (err != TSNODE_OK) {
                TSNODE_LOGW(TAG, "WG TX initiation FAILED: %d peer=%d dst=%s:%u t=%lu ms",
                            err, idx, mp->endpoint_ip, mp->endpoint_port,
                            (unsigned long)ts_rel_ms());
            } else {
                s_wg_counters.tx_initiation++;
                TSNODE_LOGI(TAG, "WG TX init #%lu -> %s:%u len=%d t=%lu ms",
                            (unsigned long)s_wg_counters.tx_initiation,
                            mp->endpoint_ip, mp->endpoint_port,
                            TSNODE_WG_INITIATION_LEN, (unsigned long)ts_rel_ms());
            }
        }
    }

    return TSNODE_OK;
}

/* Si STUN ya descubrió nuestro endpoint público (GOAL-3), reemplazamos
 * la IP local WiFi (192.168.x.x) del config por la pública para que el
 * control plane la use como endpoint alcanzable desde internet. El puerto
 * STUN-descubierto es el puerto NAT externo del socket WG; es el correcto
 * a reportar (el control plane lo usa como Magicsock UDP endpoint). */
static void apply_stun_endpoint_to_config(void)
{
    if (!s_disco_initialized) return;

    uint32_t pub_ip;
    uint16_t pub_port;
    if (tsnode_disco_get_stun_endpoint(&s_disco, &pub_ip, &pub_port)) {
        s_config.endpoint_ip = pub_ip;
        s_config.endpoint_port = pub_port;
        TSNODE_LOGI(TAG, "MapRequest endpoint -> STUN public %u.%u.%u.%u:%u",
                    (pub_ip >> 24) & 0xFF, (pub_ip >> 16) & 0xFF,
                    (pub_ip >> 8) & 0xFF, pub_ip & 0xFF, pub_port);
    }
}

static tsnode_err_t do_map_poll(tsnode_map_netmap_t *netmap)
{
    tsnode_err_t err;

    /* Use STUN-discovered public endpoint if available (GOAL-3) */
    apply_stun_endpoint_to_config();

    /* Build MapRequest */
    const uint8_t *disco_key = tsnode_disco_get_pubkey(&s_disco);
    uint8_t zero_disco[32] = {0};
    char map_req[MAP_REQUEST_BUF_SIZE];
    size_t map_req_len;
    err = tsnode_map_build_request(map_req, sizeof(map_req), &map_req_len,
                                    s_node_key_pub,
                                    disco_key ? disco_key : zero_disco,
                                    s_config.hostname,
                                    145, false,
                                    s_config.endpoint_ip,
                                    s_config.endpoint_port);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "build MapRequest failed: %d", err);
        return err;
    }

    /* POST /machine/map via h2 */
    char lb_value[8 + 64 + 1];
    snprintf(lb_value, sizeof(lb_value), "nodekey:%s", s_node_key_pub_hex);

    size_t map_wire_len;
    err = h2_post(&s_h2, s_config.control_host, "/machine/map",
                  lb_value, (const uint8_t *)map_req, map_req_len,
                  s_map_resp, sizeof(s_map_resp) - 1, &map_wire_len);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "map POST failed: %d", err);
        return err;
    }
    s_map_resp[map_wire_len] = '\0';
    TSNODE_LOGI(TAG, "MapResponse poll (%zu bytes wire)", map_wire_len);

    /* Parse framing + JSON */
    const uint8_t *map_json = NULL;
    size_t map_json_len = 0;
    err = tsnode_map_parse_framed(s_map_resp, map_wire_len,
                                   &map_json, &map_json_len);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "parse MapResponse framing failed: %d", err);
        return err;
    }

    err = tsnode_map_parse_response(netmap, (const char *)map_json,
                                     map_json_len);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "parse MapResponse failed: %d", err);
        return err;
    }

    /* Debug: dump JSON in chunks */
    size_t chunk_size = 150;
    for (size_t offset = 0; offset < map_json_len; offset += chunk_size) {
        size_t len = map_json_len - offset;
        if (len > chunk_size) len = chunk_size;
        TSNODE_LOGI(TAG, "JSON[%zu]: %.*s", offset, (int)len, map_json + offset);
    }

    TSNODE_LOGI(TAG, "netmap poll: %u peers, self=%s",
                netmap->peer_count, netmap->self_ip);

    /* Debug: log self node key */
    char self_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(self_hex + i * 2, 3, "%02x", netmap->self_node_key[i]);
    }
    TSNODE_LOGI(TAG, "self key: %s", self_hex);

    /* Log first peer details if any */
    if (netmap->peer_count > 0) {
        for (uint8_t i = 0; i < netmap->peer_count && i < 3; i++) {
            const tsnode_map_peer_t *p = &netmap->peers[i];
            bool has_dk = false;
            for (int k = 0; k < 32; k++) {
                if (p->disco_key[k] != 0) { has_dk = true; break; }
            }
            TSNODE_LOGI(TAG, "peer[%d]: ip=%s ep=%s:%u disco=%s",
                        i, p->tailscale_ip, p->endpoint_ip, p->endpoint_port,
                        has_dk ? "yes" : "no");
        }
    }

    return TSNODE_OK;
}

/* ---- WireGuard UDP receive task (ADR-0011) ---- */

static void wg_recv_task(void *arg)
{
    (void)arg;
    TSNODE_LOGI(TAG, "WG recv task started");

    uint8_t pkt_buf[WG_RECV_BUF_SIZE];
    uint8_t inner_buf[TSNODE_WG_INNER_MAX];

    while (s_state == TSNODE_CLIENT_ONLINE || s_state == TSNODE_CLIENT_MAP_SYNC) {
        size_t nread;
        uint32_t src_ip;
        uint16_t src_port;

        tsnode_err_t err = tsnode_port_udp_recvfrom(s_wg_sock, pkt_buf,
                                                     sizeof(pkt_buf), &nread,
                                                     &src_ip, &src_port, 1000);
        if (err == TSNODE_ERR_TIMEOUT) {
            continue; /* Normal: no packet yet */
        }
        if (err != TSNODE_OK) {
            TSNODE_LOGW(TAG, "WG recv error: %d", err);
            tsnode_port_delay_ms(100);
            continue;
        }

        if (nread < 4) {
            continue; /* Too short for any WG message */
        }

        /* Demultiplex: disco magic vs WireGuard */
        if (s_disco_initialized && tsnode_disco_is_disco_packet(pkt_buf, nread)) {
            /* Disco packet - handle in disco subsystem */
            tsnode_disco_handle_packet(&s_disco, pkt_buf, nread,
                                       src_ip, src_port, s_wg_sock,
                                       tsnode_wg_crypto_mbedtls());
            continue;
        }

        /* STUN Binding Success Response (from our STUN/DERP server) */
        if (s_disco_initialized && tsnode_disco_is_stun_response(pkt_buf, nread)) {
            tsnode_disco_stun_parse_response(&s_disco, pkt_buf, nread);
            continue;
        }

        /* Determine message type from first byte */
        uint8_t msg_type = pkt_buf[0];

        switch (msg_type) {
        case TSNODE_WG_MSG_TYPE_HANDSHAKE_INITIATION: {
            s_wg_counters.rx_initiation++;
            TSNODE_LOGI(TAG, "WG RX init #%lu from %u.%u.%u.%u:%u len=%zu t=%lu ms",
                        (unsigned long)s_wg_counters.rx_initiation,
                        (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                        (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
                        nread, (unsigned long)ts_rel_ms());

            int peer_idx = -1;
            err = tsnode_wg_consume_initiation(&s_wg_dev, pkt_buf, nread,
                                                &peer_idx);
            if (err != TSNODE_OK) {
                TSNODE_LOGW(TAG, "WG consume_initiation failed: %d", err);
                continue;
            }

            /* Build and send response */
            uint64_t now_ms;
            tsnode_port_uptime_ms(&now_ms);
            uint8_t response[TSNODE_WG_RESPONSE_LEN];
            err = tsnode_wg_create_response(&s_wg_dev, peer_idx, now_ms,
                                             response);
            if (err != TSNODE_OK) {
                TSNODE_LOGW(TAG, "WG create_response failed: %d", err);
                continue;
            }

            err = tsnode_port_udp_sendto(s_wg_sock, response,
                                          sizeof(response),
                                          src_ip, src_port);
            if (err != TSNODE_OK) {
                TSNODE_LOGW(TAG, "WG response send failed: %d", err);
            } else {
                TSNODE_LOGI(TAG, "WG response sent to %u.%u.%u.%u:%u",
                            (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                            (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port);
            }
            break;
        }

        case TSNODE_WG_MSG_TYPE_HANDSHAKE_RESPONSE: {
            s_wg_counters.rx_response++;
            TSNODE_LOGI(TAG, "WG RX resp #%lu from %u.%u.%u.%u:%u len=%zu t=%lu ms",
                        (unsigned long)s_wg_counters.rx_response,
                        (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                        (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
                        nread, (unsigned long)ts_rel_ms());

            int peer_idx = -1;
            uint64_t now_ms;
            tsnode_port_uptime_ms(&now_ms);
            err = tsnode_wg_consume_response(&s_wg_dev, pkt_buf, nread,
                                              now_ms, &peer_idx);
            if (err != TSNODE_OK) {
                TSNODE_LOGW(TAG, "WG consume_response failed: %d", err);
                continue;
            }
            TSNODE_LOGI(TAG, "WG session ESTABLISHED peer=%d t=%lu ms", peer_idx, (unsigned long)ts_rel_ms());
            break;
        }

        case TSNODE_WG_MSG_TYPE_TRANSPORT_DATA: {
            int peer_idx = -1;
            size_t inner_len = 0;
            err = tsnode_wg_decap(&s_wg_dev, pkt_buf, nread,
                                   inner_buf, sizeof(inner_buf), &inner_len,
                                   &peer_idx);
            if (err == TSNODE_ERR_REPLAY) {
                /* Replay duplicate — silently drop */
                continue;
            }
            if (err != TSNODE_OK) {
                TSNODE_LOGW(TAG, "WG decap failed: %d", err);
                continue;
            }

            if (inner_len == 0) {
                /* Keepalive (empty payload) */
                s_wg_counters.rx_keepalive++;
                TSNODE_LOGI(TAG, "WG RX keepalive #%lu peer=%d t=%lu ms",
                            (unsigned long)s_wg_counters.rx_keepalive,
                            peer_idx, (unsigned long)ts_rel_ms());
            } else {
                /* Inner IP packet — for v1, log and drop (no TUN) */
                s_wg_counters.rx_transport++;
                TSNODE_LOGI(TAG, "WG RX data #%lu peer=%d %zu bytes (no TUN) t=%lu ms",
                            (unsigned long)s_wg_counters.rx_transport,
                            peer_idx, inner_len, (unsigned long)ts_rel_ms());
            }
            break;
        }

        default:
            /* Unknown WG message type — could be disco (handled in Phase 2) */
            s_wg_counters.rx_unknown++;
            TSNODE_LOGW(TAG, "WG RX unknown type=%u #%lu from %u.%u.%u.%u:%u len=%zu t=%lu ms",
                        msg_type, (unsigned long)s_wg_counters.rx_unknown,
                        (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                        (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
                        nread, (unsigned long)ts_rel_ms());
            break;
        }
    }

    wg_log_counters();
    TSNODE_LOGI(TAG, "WG recv task exiting");
    tsnode_port_task_delete_self();
}

/* ---- Session cleanup between reconnection attempts ---- */

/* Release all resources held by an active or partially-active session so
 * that the next do_connect() starts from a clean state.  Fixes:
 *   B1 — UDP socket was leaked on every do_connect error path.
 *   A1 — needed by the reconnection loop to cleanly tear down before retry. */
static void cleanup_session(void)
{
    ts2021_conn_close(&s_conn);

    if (s_wg_sock != NULL) {
        tsnode_port_udp_close(s_wg_sock);
        s_wg_sock = NULL;
    }

    /* Reset h2 pushback buffer so stale bytes from the previous session
     * don't corrupt the next HTTP/2 stream. */
    s_h2_pushback_len = 0;

    /* Force disco re-init on next successful connect so the keypair is
     * reloaded from NVS (it may have been persisted from the previous
     * session; we want a consistent state). */
    s_disco_initialized = false;

    memset(&s_h2, 0, sizeof(s_h2));
}

/* ---- Task entry point (called by port task) ---- */

/* Reconnection backoff schedule (seconds).  First retry is immediate,
 * then exponential up to a cap.  The backoff resets after the node has
 * been successfully ONLINE for at least one full poll cycle. */
#define RECONNECT_BACKOFF_MIN_S   5
#define RECONNECT_BACKOFF_MAX_S  60

static void client_task(void *arg)
{
    (void)arg;
    TSNODE_LOGI(TAG, "client task started");
    ts_init();

    uint32_t reconnect_backoff_s = 0;
    uint32_t consecutive_errors = 0;

    while (s_state != TSNODE_CLIENT_IDLE) {
        /* Backoff before retry (skip on first iteration).
         * Sleep in 1-second chunks so tsnode_client_stop() is responsive. */
        if (reconnect_backoff_s > 0) {
            TSNODE_LOGI(TAG, "reconnect in %us", reconnect_backoff_s);
            for (uint32_t i = 0; i < reconnect_backoff_s; i++) {
                if (s_state == TSNODE_CLIENT_IDLE) break;
                tsnode_port_delay_ms(1000);
            }
            if (s_state == TSNODE_CLIENT_IDLE) break;
        }

        /* Clean up any leftover state from previous session */
        cleanup_session();

        /* ---- Connect phase ---- */
        tsnode_err_t err = do_connect();
        if (err != TSNODE_OK) {
            TSNODE_LOGE(TAG, "connect failed: %s (%d) — retrying",
                        tsnode_err_name(err), err);
            set_state(TSNODE_CLIENT_ERROR);
            reconnect_backoff_s = RECONNECT_BACKOFF_MIN_S *
                                  (1 << (consecutive_errors < 4 ? consecutive_errors : 4));
            if (reconnect_backoff_s > RECONNECT_BACKOFF_MAX_S) {
                reconnect_backoff_s = RECONNECT_BACKOFF_MAX_S;
            }
            consecutive_errors++;
            continue;
        }

        /* ---- Connected: enter polling loop ---- */
        TSNODE_LOGI(TAG, "connected — entering poll loop");
        consecutive_errors = 0;
        reconnect_backoff_s = 0;

        /* Start WireGuard UDP receive task (ADR-0011) */
        err = tsnode_port_task_create(wg_recv_task, NULL,
                                       "wg_recv", 8192, 4);
        if (err != TSNODE_OK) {
            TSNODE_LOGE(TAG, "WG recv task create failed: %d", err);
            /* Non-fatal: data plane won't work but control plane is fine */
        }

        uint32_t poll_interval_s = MAP_POLL_INTERVAL_BASE_S;
        uint32_t poll_consecutive_errors = 0;

        while (s_state == TSNODE_CLIENT_ONLINE) {
            /* Sleep with jitter */
            uint32_t jitter = (poll_interval_s * MAP_POLL_JITTER_PCT) / 100;
            uint32_t sleep_s = poll_interval_s;
            if (jitter > 0) {
                uint64_t uptime_ms;
                tsnode_port_uptime_ms(&uptime_ms);
                uint32_t tick = (uint32_t)(uptime_ms / 1000);
                if ((tick % 100) < 50) {
                    sleep_s += (tick % jitter);
                } else {
                    sleep_s -= (tick % jitter);
                }
            }
            /* Sleep in 1-second chunks so tsnode_client_stop() is responsive */
            for (uint32_t i = 0; i < sleep_s; i++) {
                if (s_state != TSNODE_CLIENT_ONLINE) break;
                tsnode_port_delay_ms(1000);
            }

            if (s_state != TSNODE_CLIENT_ONLINE) break;

            tsnode_map_netmap_t netmap;
            tsnode_err_t poll_err = do_map_poll(&netmap);
            if (poll_err != TSNODE_OK) {
                poll_consecutive_errors++;
                poll_interval_s = MAP_POLL_INTERVAL_BASE_S *
                                  (1 << (poll_consecutive_errors < 5 ? poll_consecutive_errors : 5));
                if (poll_interval_s > MAP_POLL_INTERVAL_MAX_S) {
                    poll_interval_s = MAP_POLL_INTERVAL_MAX_S;
                }
                TSNODE_LOGW(TAG, "map poll error, backoff to %us",
                            poll_interval_s);

                if (poll_consecutive_errors >= 3) {
                    TSNODE_LOGE(TAG, "too many map poll errors — "
                                "dropping connection for reconnect");
                    break;  /* exit poll loop → outer loop reconnects */
                }
                continue;
            }

            /* Success: reset poll backoff */
            poll_consecutive_errors = 0;
            poll_interval_s = MAP_POLL_INTERVAL_BASE_S;

            wg_log_counters();

            tsnode_err_t wg_err = update_wg_peers(&netmap);
            if (wg_err != TSNODE_OK) {
                TSNODE_LOGW(TAG, "WG peer update failed: %d", wg_err);
            }

            if (s_disco_initialized) {
                uint32_t stun_ip = netmap.stun.valid ? netmap.stun.ip : 0;
                uint16_t stun_port = netmap.stun.valid ? netmap.stun.port : 0;
                tsnode_disco_poll(&s_disco, stun_ip, stun_port, s_wg_sock,
                                  tsnode_wg_crypto_mbedtls());
            }
        }

        /* Poll loop exited — reconnect unless stop was requested */
        TSNODE_LOGI(TAG, "poll loop exited (state=%d)", (int)s_state);
        reconnect_backoff_s = RECONNECT_BACKOFF_MIN_S;
    }

    /* Clean exit: user called tsnode_client_stop() */
    cleanup_session();
    TSNODE_LOGI(TAG, "client task exiting (state=%d)", (int)s_state);
    tsnode_port_task_delete_self();
}

/* ---- Public API ---- */

tsnode_err_t tsnode_client_start(const tsnode_client_config_t *config)
{
    if (config == NULL || config->auth_key == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (s_state != TSNODE_CLIENT_IDLE && s_state != TSNODE_CLIENT_ERROR &&
        s_state != TSNODE_CLIENT_DONE) {
        return TSNODE_ERR_INVALID_STATE;
    }

    memcpy(&s_config, config, sizeof(s_config));

    /* Copiar los strings a storage propio: los punteros originales pueden
     * apuntar al stack del caller, que se recicla cuando esta función
     * retorna. Sin esta copia el JSON del register sale con memoria
     * reutilizada (bug raíz del HTTP 500 en producción). */
    static char ctrl_host[TSNODE_CLIENT_CTRLHOST_MAX];
    static char auth_key_cp[TSNODE_CLIENT_AUTHKEY_MAX];
    static char hostname_cp[TSNODE_CLIENT_HOSTNAME_MAX];
    if (s_config.control_host != NULL) {
        int n = snprintf(ctrl_host, sizeof(ctrl_host), "%s",
                         s_config.control_host);
        if (n < 0 || (size_t)n >= sizeof(ctrl_host)) {
            return TSNODE_ERR_INVALID_ARG;
        }
        s_config.control_host = ctrl_host;
    }
    if (s_config.auth_key != NULL) {
        int n = snprintf(auth_key_cp, sizeof(auth_key_cp), "%s",
                         s_config.auth_key);
        if (n < 0 || (size_t)n >= sizeof(auth_key_cp)) {
            return TSNODE_ERR_INVALID_ARG;
        }
        s_config.auth_key = auth_key_cp;
    }
    if (s_config.hostname != NULL) {
        int n = snprintf(hostname_cp, sizeof(hostname_cp), "%s",
                         s_config.hostname);
        if (n < 0 || (size_t)n >= sizeof(hostname_cp)) {
            return TSNODE_ERR_INVALID_ARG;
        }
        s_config.hostname = hostname_cp;
    }

    /* Default control plane */
    if (s_config.control_host == NULL) {
        s_config.control_host = "controlplane.tailscale.com";
    }
    if (s_config.control_port == 0) {
        s_config.control_port = 80;
    }

    set_state(TSNODE_CLIENT_FETCHING_KEY);

    /* Create task via port (40KB stack for mbedTLS + crypto, priority 5) */
    tsnode_err_t err = tsnode_port_task_create(client_task, NULL,
                                                "tsclient", 40960, 5);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "task create failed: %d", err);
        return err;
    }

    return TSNODE_OK;
}

tsnode_err_t tsnode_client_stop(void)
{
    ts2021_conn_close(&s_conn);

    /* Close WireGuard UDP socket if open */
    if (s_wg_sock != NULL) {
        tsnode_port_udp_close(s_wg_sock);
        s_wg_sock = NULL;
    }

    set_state(TSNODE_CLIENT_IDLE);
    return TSNODE_OK;
}

tsnode_err_t tsnode_client_state_get(tsnode_client_state_t *out_state)
{
    if (out_state == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    *out_state = s_state;
    return TSNODE_OK;
}
