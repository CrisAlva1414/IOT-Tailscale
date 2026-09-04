/*
 * Noise IK handshake client — core de ts2021 (ADR-0008).
 *
 * Implementa el patrón Noise IK:
 *   -> e, es, s, ss   (initiación, 101 bytes)
 *   <- e, ee, se      (respuesta, 51 bytes)
 *
 * Cipher suite: Noise_IK_25519_ChaChaPoly_BLAKE2s
 * Prologue: "Tailscale Control Protocol v" + uint16 version
 *
 * Este archivo es C puro: sin headers de plataforma (ADR-0006).
 * Acceso a crypto via mbedTLS (X25519, ChaCha20-Poly1305) y
 * blake2s propio (RFC 7693). Acceso a red via tsnode_port.h.
 *
 * Fuentes primarias verificadas (ADR-0008):
 *   tailscale/tailscale control/controlbase/handshake.go
 *   tailscale/tailscale control/controlbase/messages.go
 */

#include "ts2021.h"

#include <inttypes.h>
#include <string.h>

#include "blake2s.h"
#include "hmac_blake2s.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/error.h"
#include "x25519_wrapper.h"

#include "tsnode_port.h"

#define TAG "ts2021"

/* ---- Noise frame sizes (verified from source) ---- */
#define NOISE_INITIATION_SIZE  101
#define NOISE_RESPONSE_SIZE     51
#define NOISE_EPH_PUB_SIZE      32
#define NOISE_MACHINE_PUB_ENC   48
#define NOISE_TAG_SIZE          16
#define NOISE_MAX_FRAME       4096
#define NOISE_NONCE_SIZE        12

#define MSG_TYPE_INITIATION  1
#define MSG_TYPE_RESPONSE    2
#define MSG_TYPE_ERROR       3
#define MSG_TYPE_RECORD      4

static const char PROLOGUE_PREFIX[] = "Tailscale Control Protocol v";

/* ---- Noise symmetric state ---- */

typedef struct {
    uint8_t ck[32];
    uint8_t h[32];
} noise_symmetric_t;

static void noise_sym_init(noise_symmetric_t *s)
{
    tsnode_blake2s(s->h, 32, (const uint8_t *)NOISE_PROTOCOL_NAME,
                   strlen(NOISE_PROTOCOL_NAME));
    memcpy(s->ck, s->h, 32);
}

static void noise_mix_hash(noise_symmetric_t *s, const uint8_t *data,
                           size_t len)
{
    tsnode_blake2s_ctx ctx;
    tsnode_blake2s_init(&ctx, 32);
    tsnode_blake2s_update(&ctx, s->h, 32);
    tsnode_blake2s_update(&ctx, data, len);
    tsnode_blake2s_final(&ctx, s->h, 32);
}

/* ---- HKDF-BLAKE2s per Noise spec ----
 *
 * Noise MixKey expects:
 *   shared = X25519(priv, pub)
 *   (ck', k) = HKDF(ck, shared, 64 bytes) where:
 *     ck' = first 32 bytes (new chaining key)
 *     k   = next 32 bytes (AEAD key for next message)
 *
 * For Split():
 *   (k1, k2) = HKDF-Expand(prk=ck, info=nil, L=64)
 *   k1 = tx key, k2 = rx key
 *
 * HMAC/HKDF primitives live in crypto/hmac_blake2s.c (shared with wg.c,
 * verified against wireguard-go device/noise-helpers.go @ master).
 */
static void noise_key_derive(uint8_t new_ck[32], uint8_t key[32],
                             const uint8_t ikm[32], const uint8_t salt[32])
{
    tsnode_hkdf_blake2s_2(new_ck, key, salt, ikm, 32);
}

static void noise_split(uint8_t c1[32], uint8_t c2[32], const uint8_t ck[32])
{
    tsnode_hkdf_blake2s_2(c1, c2, ck, NULL, 0);
}

/* ---- AEAD with zero nonce (single-use, handshake only) ---- */

static tsnode_err_t noise_encrypt_to(uint8_t *out, size_t *out_len,
                                     const uint8_t key[32],
                                     const uint8_t *plaintext, size_t pt_len,
                                     const uint8_t *aad, size_t aad_len)
{
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0) {
        mbedtls_chachapoly_free(&ctx);
        return TSNODE_ERR_CRYPTO;
    }
    uint8_t nonce[12] = {0};
    uint8_t tag[16];
    ret = mbedtls_chachapoly_encrypt_and_tag(&ctx, pt_len, nonce,
                                             aad, aad_len,
                                             plaintext, out, tag);
    mbedtls_chachapoly_free(&ctx);
    if (ret != 0) {
        return TSNODE_ERR_CRYPTO;
    }
    memcpy(out + pt_len, tag, 16);
    *out_len = pt_len + 16;
    return TSNODE_OK;
}

static tsnode_err_t noise_decrypt_from(uint8_t *out, size_t *out_len,
                                       const uint8_t key[32],
                                       const uint8_t *ciphertext, size_t ct_len,
                                       const uint8_t *aad, size_t aad_len)
{
    if (ct_len < 16) {
        return TSNODE_ERR_CRYPTO;
    }
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0) {
        mbedtls_chachapoly_free(&ctx);
        return TSNODE_ERR_CRYPTO;
    }
    uint8_t nonce[12] = {0};
    ret = mbedtls_chachapoly_auth_decrypt(&ctx, ct_len - 16, nonce,
                                          aad, aad_len,
                                          ciphertext + ct_len - 16,
                                          ciphertext, out);
    mbedtls_chachapoly_free(&ctx);
    if (ret != 0) {
        return TSNODE_ERR_CRYPTO;
    }
    *out_len = ct_len - 16;
    return TSNODE_OK;
}

/* ---- Public: Noise IK handshake ---- */

tsnode_err_t ts2021_handshake_client(ts2021_conn_t *conn,
                                     const uint8_t machine_key_priv[32],
                                     const uint8_t control_key_pub[32],
                                     uint16_t protocol_version,
                                     tsnode_port_socket_t *sock)
{
    if (conn == NULL || machine_key_priv == NULL || control_key_pub == NULL ||
        sock == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    noise_symmetric_t s;
    uint8_t machine_key_pub[32];
    uint8_t eph_priv[32], eph_pub[32];
    tsnode_err_t err;

    /* Generate ephemeral key pair */
    err = tsnode_port_random_bytes(eph_priv, 32);
    if (err != TSNODE_OK) return err;

    if (tsnode_x25519_keygen(eph_priv, eph_pub) != 0) {
        return TSNODE_ERR_CRYPTO;
    }

    /* Get our machine public key from private */
    if (tsnode_x25519_publickey(machine_key_priv, machine_key_pub) != 0) {
        err = TSNODE_ERR_CRYPTO; goto cleanup;
    }

    /* Initialize symmetric state: h = ck = Hash(protocolName) */
    noise_sym_init(&s);

    /* Prologue: "Tailscale Control Protocol v" + decimal version string */
    uint8_t prologue[64];
    size_t plen = strlen(PROLOGUE_PREFIX);
    memcpy(prologue, PROLOGUE_PREFIX, plen);
    char ver_str[8];
    int ver_len = snprintf(ver_str, sizeof(ver_str), "%u", protocol_version);
    memcpy(prologue + plen, ver_str, ver_len);
    plen += ver_len;
    noise_mix_hash(&s, prologue, plen);

    /* <- s: mixHash(serverPublicKey) */
    noise_mix_hash(&s, control_key_pub, 32);

    /* -> e: mixHash(ephemeralPub) */
    noise_mix_hash(&s, eph_pub, 32);

    /* -> es: MixDH(ephemeral, serverKey) */
    uint8_t ck_new[32], k_es[32];
    uint8_t shared_es[32];
    if (tsnode_x25519_shared(shared_es, eph_priv, control_key_pub) != 0) {
        err = TSNODE_ERR_CRYPTO; goto cleanup;
    }
    noise_key_derive(ck_new, k_es, shared_es, s.ck);
    memcpy(s.ck, ck_new, 32);
    mbedtls_platform_zeroize(shared_es, sizeof(shared_es));

    /* -> s: EncryptAndHash(machinePub) — 32 bytes plaintext */
    uint8_t enc_machine_pub[48];
    size_t enc_len;
    err = noise_encrypt_to(enc_machine_pub, &enc_len, k_es,
                           machine_key_pub, 32, s.h, 32);
    if (err != TSNODE_OK) goto cleanup;
    noise_mix_hash(&s, enc_machine_pub, enc_len);

    /* -> ss: MixDH(machineKey, serverKey) */
    uint8_t ck_new2[32], k_ss[32];
    uint8_t shared_ss[32];
    if (tsnode_x25519_shared(shared_ss, machine_key_priv, control_key_pub) != 0) {
        err = TSNODE_ERR_CRYPTO; goto cleanup;
    }
    noise_key_derive(ck_new2, k_ss, shared_ss, s.ck);
    memcpy(s.ck, ck_new2, 32);
    mbedtls_platform_zeroize(shared_ss, sizeof(shared_ss));

    /* -> ss: EncryptAndHash(nil) — empty payload, tag only */
    uint8_t tag_ss[16];
    size_t tag_ss_len;
    err = noise_encrypt_to(tag_ss, &tag_ss_len, k_ss, NULL, 0, s.h, 32);
    if (err != TSNODE_OK) goto cleanup;
    noise_mix_hash(&s, tag_ss, tag_ss_len);

    /* Assemble initiation message (101 bytes) */
    uint8_t initiation[NOISE_INITIATION_SIZE];
    memset(initiation, 0, sizeof(initiation));
    initiation[0] = (uint8_t)(protocol_version >> 8);
    initiation[1] = (uint8_t)(protocol_version & 0xFF);
    initiation[2] = MSG_TYPE_INITIATION;
    initiation[3] = 0;
    initiation[4] = 96;
    memcpy(initiation + 5, eph_pub, 32);
    memcpy(initiation + 37, enc_machine_pub, 48);
    memcpy(initiation + 85, tag_ss, 16);

    err = tsnode_port_socket_write(sock, initiation, sizeof(initiation), 5000);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "send initiation failed");
        goto cleanup;
    }

    /* Receive response (51 bytes) */
    uint8_t resp_buf[NOISE_RESPONSE_SIZE];
    size_t resp_read;
    err = tsnode_port_socket_read(sock, resp_buf, sizeof(resp_buf),
                                  &resp_read, 10000);
    if (err != TSNODE_OK || resp_read != NOISE_RESPONSE_SIZE) {
        TSNODE_LOGE(TAG, "read response failed: resp_read=%zu err=%d",
                    resp_read, err);
        err = (err == TSNODE_OK) ? TSNODE_ERR_NETWORK : err;
        goto cleanup;
    }

    if (resp_buf[0] == MSG_TYPE_ERROR) {
        uint16_t err_len = ((uint16_t)resp_buf[1] << 8) | resp_buf[2];
        TSNODE_LOGE(TAG, "server error frame (%u bytes)", err_len);
        err = TSNODE_ERR_NETWORK;
        goto cleanup;
    }

    if (resp_buf[0] != MSG_TYPE_RESPONSE) {
        TSNODE_LOGE(TAG, "unexpected response type: %u", resp_buf[0]);
        err = TSNODE_ERR_NETWORK;
        goto cleanup;
    }

    /* Parse response: type(1) + len(2) + ephemeral_pub(32) + tag(16) */
    uint8_t control_eph_pub[32];
    uint8_t resp_tag[16];
    memcpy(control_eph_pub, resp_buf + 3, 32);
    memcpy(resp_tag, resp_buf + 35, 16);

    /* <- e: mixHash(controlEphemeralPub) */
    noise_mix_hash(&s, control_eph_pub, 32);

    /* <- ee: MixDH(machineEphemeral, controlEphemeral) */
    uint8_t ck_ee[32], k_ee[32];
    uint8_t shared_ee[32];
    if (tsnode_x25519_shared(shared_ee, eph_priv, control_eph_pub) != 0) {
        err = TSNODE_ERR_CRYPTO; goto cleanup;
    }
    noise_key_derive(ck_ee, k_ee, shared_ee, s.ck);
    memcpy(s.ck, ck_ee, 32);
    mbedtls_platform_zeroize(shared_ee, sizeof(shared_ee));

    /* <- se: MixDH(machineKey, controlEphemeral) */
    uint8_t ck_se[32], k_se[32];
    uint8_t shared_se[32];
    if (tsnode_x25519_shared(shared_se, machine_key_priv, control_eph_pub) != 0) {
        err = TSNODE_ERR_CRYPTO; goto cleanup;
    }
    noise_key_derive(ck_se, k_se, shared_se, s.ck);
    memcpy(s.ck, ck_se, 32);
    mbedtls_platform_zeroize(shared_se, sizeof(shared_se));

    /* <- se: DecryptAndHash(response tag) — empty payload */
    uint8_t dec_tag[16];
    size_t dec_tag_len;
    err = noise_decrypt_from(dec_tag, &dec_tag_len, k_se,
                             resp_tag, 16, s.h, 32);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "response tag verification failed");
        goto cleanup;
    }
    noise_mix_hash(&s, resp_tag, 16);

    /* Split: derive tx/rx keys */
    uint8_t tx_key[32], rx_key[32];
    noise_split(tx_key, rx_key, s.ck);

    /* Fill connection context */
    memcpy(conn->tx_key, tx_key, 32);
    memcpy(conn->rx_key, rx_key, 32);
    conn->sock = sock;
    conn->tx_counter = 1;
    conn->rx_counter = 1;
    conn->established = true;

    mbedtls_platform_zeroize(eph_priv, sizeof(eph_priv));
    mbedtls_platform_zeroize(eph_pub, sizeof(eph_pub));
    mbedtls_platform_zeroize(tx_key, sizeof(tx_key));
    mbedtls_platform_zeroize(rx_key, sizeof(rx_key));

    TSNODE_LOGI(TAG, "handshake OK, record layer established");
    return TSNODE_OK;

cleanup:
    mbedtls_platform_zeroize(eph_priv, sizeof(eph_priv));
    mbedtls_platform_zeroize(eph_pub, sizeof(eph_pub));
    return err;
}

/* ---- Record layer ---- */

static tsnode_err_t ts2021_conn_read(ts2021_conn_t *conn, uint8_t *buf,
                                      size_t need, size_t *got, uint32_t timeout_ms);

tsnode_err_t ts2021_record_send(ts2021_conn_t *conn, const uint8_t *data,
                                size_t len)
{
    if (conn == NULL || !conn->established) {
        return TSNODE_ERR_INVALID_STATE;
    }
    if (data == NULL || len == 0) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (len > NOISE_MAX_FRAME - 3 - 16) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* Build nonce: 4 zero bytes + 8-byte big-endian counter */
    uint8_t nonce[NOISE_NONCE_SIZE] = {0};
    nonce[4]  = (uint8_t)(conn->tx_counter >> 56);
    nonce[5]  = (uint8_t)(conn->tx_counter >> 48);
    nonce[6]  = (uint8_t)(conn->tx_counter >> 40);
    nonce[7]  = (uint8_t)(conn->tx_counter >> 32);
    nonce[8]  = (uint8_t)(conn->tx_counter >> 24);
    nonce[9]  = (uint8_t)(conn->tx_counter >> 16);
    nonce[10] = (uint8_t)(conn->tx_counter >> 8);
    nonce[11] = (uint8_t)(conn->tx_counter);

    if (conn->tx_counter == 0xFFFFFFFFFFFFFFFFULL) {
        return TSNODE_ERR_CRYPTO;
    }

    /* Encrypt */
    uint8_t ciphertext[NOISE_MAX_FRAME];
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, conn->tx_key);
    if (ret != 0) {
        mbedtls_chachapoly_free(&ctx);
        return TSNODE_ERR_CRYPTO;
    }
    uint8_t tag[16];
    ret = mbedtls_chachapoly_encrypt_and_tag(&ctx, len, nonce,
                                              NULL, 0,
                                              data, ciphertext, tag);
    mbedtls_chachapoly_free(&ctx);
    if (ret != 0) {
        return TSNODE_ERR_CRYPTO;
    }
    memcpy(ciphertext + len, tag, 16);

    size_t ct_len = len + 16;

    /* Frame: type(1) + length(2 BE) + ciphertext+tag */
    uint8_t frame[3 + NOISE_MAX_FRAME];
    frame[0] = MSG_TYPE_RECORD;
    frame[1] = (uint8_t)(ct_len >> 8);
    frame[2] = (uint8_t)(ct_len & 0xFF);
    memcpy(frame + 3, ciphertext, ct_len);

    tsnode_err_t err = tsnode_port_socket_write(conn->sock, frame,
                                                 3 + ct_len, 5000);
    conn->tx_counter++;
    return err;
}

tsnode_err_t ts2021_record_recv(ts2021_conn_t *conn, uint8_t *buf,
                                size_t buf_size, size_t *out_len)
{
    if (conn == NULL || !conn->established) {
        return TSNODE_ERR_INVALID_STATE;
    }
    if (buf == NULL || buf_size == 0 || out_len == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* Read header: type(1) + length(2) */
    uint8_t header[3];
    size_t header_read;
    uint32_t timeout = conn->recv_timeout_ms ? conn->recv_timeout_ms : 10000;
    tsnode_err_t err = ts2021_conn_read(conn, header,
                                         sizeof(header), &header_read, timeout);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "recv header read err=%d", err);
        return err;
    }
    if (header_read != sizeof(header)) {
        TSNODE_LOGE(TAG, "recv header short: %zu bytes (type=0x%02x)", header_read, header[0]);
        return TSNODE_ERR_NETWORK;
    }

    TSNODE_LOGI(TAG, "recv frame: type=0x%02x len=%u", header[0],
                (unsigned)(((uint16_t)header[1] << 8) | header[2]));

    if (header[0] == MSG_TYPE_ERROR) {
        uint16_t err_len = ((uint16_t)header[1] << 8) | header[2];
        uint8_t err_msg[256];
        size_t err_read;
        size_t to_read = err_len < sizeof(err_msg) ? err_len : sizeof(err_msg);
        ts2021_conn_read(conn, err_msg, to_read, &err_read, 5000);
        TSNODE_LOGW(TAG, "error frame (%u bytes)", err_len);
        return TSNODE_ERR_NETWORK;
    }

    if (header[0] != MSG_TYPE_RECORD) {
        return TSNODE_ERR_NETWORK;
    }

    uint16_t ct_len = ((uint16_t)header[1] << 8) | header[2];
    if (ct_len < 16 || ct_len > NOISE_MAX_FRAME) {
        return TSNODE_ERR_NETWORK;
    }

    /* Read ciphertext */
    uint8_t ct_buf[NOISE_MAX_FRAME];
    size_t ct_read;
    err = ts2021_conn_read(conn, ct_buf, ct_len, &ct_read, timeout);
    if (err != TSNODE_OK) return err;
    if (ct_read != ct_len) return TSNODE_ERR_NETWORK;

    /* Build nonce */
    uint8_t nonce[NOISE_NONCE_SIZE] = {0};
    nonce[4]  = (uint8_t)(conn->rx_counter >> 56);
    nonce[5]  = (uint8_t)(conn->rx_counter >> 48);
    nonce[6]  = (uint8_t)(conn->rx_counter >> 40);
    nonce[7]  = (uint8_t)(conn->rx_counter >> 32);
    nonce[8]  = (uint8_t)(conn->rx_counter >> 24);
    nonce[9]  = (uint8_t)(conn->rx_counter >> 16);
    nonce[10] = (uint8_t)(conn->rx_counter >> 8);
    nonce[11] = (uint8_t)(conn->rx_counter);

    /* Decrypt */
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, conn->rx_key);
    if (ret != 0) {
        mbedtls_chachapoly_free(&ctx);
        return TSNODE_ERR_CRYPTO;
    }
    /* Tag is the last 16 bytes of ct_buf */
    ret = mbedtls_chachapoly_auth_decrypt(&ctx, ct_len - 16, nonce,
                                          NULL, 0,
                                          ct_buf + ct_len - 16,
                                          ct_buf, buf);
    mbedtls_chachapoly_free(&ctx);
    if (ret != 0) {
        TSNODE_LOGE(TAG, "recv decrypt failed: -0x%04x", -ret);
        return TSNODE_ERR_CRYPTO;
    }

    *out_len = ct_len - 16;
    conn->rx_counter++;
    TSNODE_LOGI(TAG, "recv record OK: %zu bytes plaintext", *out_len);
    return TSNODE_OK;
}

void ts2021_conn_close(ts2021_conn_t *conn)
{
    if (conn == NULL) return;
    if (conn->sock != NULL) {
        tsnode_port_socket_close(conn->sock);
        conn->sock = NULL;
    }
    mbedtls_platform_zeroize(conn->tx_key, 32);
    mbedtls_platform_zeroize(conn->rx_key, 32);
    mbedtls_platform_zeroize(conn->prebuf, sizeof(conn->prebuf));
    conn->prebuf_len = 0;
    conn->established = false;
}

void ts2021_conn_prebuffer(ts2021_conn_t *conn, const uint8_t *data,
                            size_t len)
{
    if (conn == NULL || data == NULL || len == 0) return;
    size_t space = sizeof(conn->prebuf) - conn->prebuf_len;
    if (len > space) len = space;
    memcpy(conn->prebuf + conn->prebuf_len, data, len);
    conn->prebuf_len += len;
    TSNODE_LOGI(TAG, "prebuffered %zu bytes (total %zu)", len, conn->prebuf_len);
}

void ts2021_set_recv_timeout(ts2021_conn_t *conn, uint32_t timeout_ms)
{
    if (conn == NULL) return;
    conn->recv_timeout_ms = timeout_ms;
    TSNODE_LOGI(TAG, "recv timeout set to %u ms", (unsigned)timeout_ms);
}

/* Read from prebuf first, then socket */
static tsnode_err_t ts2021_conn_read(ts2021_conn_t *conn, uint8_t *buf,
                                      size_t need, size_t *got, uint32_t timeout_ms)
{
    size_t total = 0;
    /* Consume from prebuf first */
    if (conn->prebuf_len > 0) {
        size_t take = (conn->prebuf_len < need) ? conn->prebuf_len : need;
        memcpy(buf, conn->prebuf, take);
        /* Shift remaining prebuf data */
        if (take < conn->prebuf_len) {
            memmove(conn->prebuf, conn->prebuf + take,
                    conn->prebuf_len - take);
        }
        conn->prebuf_len -= take;
        total += take;
    }
    /* Read remaining from socket */
    while (total < need) {
        size_t n = 0;
        tsnode_err_t err = tsnode_port_socket_read(conn->sock, buf + total,
                                                    need - total, &n,
                                                    timeout_ms);
        if (err != TSNODE_OK) {
            *got = total;
            return err;
        }
        if (n == 0) break;
        total += n;
    }
    *got = total;
    return TSNODE_OK;
}

/* ---- Split handshake: initiate + complete (for HTTP upgrade flow) ---- */

tsnode_err_t ts2021_handshake_initiate(
    ts2021_handshake_state_t *state,
    uint8_t init_out[101],
    const uint8_t machine_key_priv[32],
    const uint8_t control_key_pub[32],
    uint16_t protocol_version)
{
    if (state == NULL || init_out == NULL || machine_key_priv == NULL ||
        control_key_pub == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    tsnode_err_t err;
    noise_symmetric_t s;
    uint8_t machine_key_pub[32];
    uint8_t eph_priv[32], eph_pub[32];

    /* Generate ephemeral key pair */
    err = tsnode_port_random_bytes(eph_priv, 32);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "random_bytes failed: %d", err);
        return err;
    }
    TSNODE_LOGI(TAG, "Noise: random OK");

    if (tsnode_x25519_keygen(eph_priv, eph_pub) != 0) {
        TSNODE_LOGE(TAG, "x25519_keygen failed");
        return TSNODE_ERR_CRYPTO;
    }
    TSNODE_LOGI(TAG, "Noise: keygen OK");

    /* Get our machine public key from private */
    int pk_ret = tsnode_x25519_publickey(machine_key_priv, machine_key_pub);
    if (pk_ret != 0) {
        TSNODE_LOGE(TAG, "x25519_publickey failed: %d", pk_ret);
        return TSNODE_ERR_CRYPTO;
    }
    TSNODE_LOGI(TAG, "Noise: pubkey OK");

    /* Initialize symmetric state: h = ck = Hash(protocolName) */
    noise_sym_init(&s);

    /* Prologue: "Tailscale Control Protocol v" + decimal version string */
    uint8_t prologue[64];
    size_t plen = strlen(PROLOGUE_PREFIX);
    memcpy(prologue, PROLOGUE_PREFIX, plen);
    char ver_str[8];
    int ver_len = snprintf(ver_str, sizeof(ver_str), "%u", protocol_version);
    memcpy(prologue + plen, ver_str, ver_len);
    plen += ver_len;
    noise_mix_hash(&s, prologue, plen);

    /* <- s: mixHash(serverPublicKey) */
    noise_mix_hash(&s, control_key_pub, 32);

    /* -> e: mixHash(ephemeralPub) */
    noise_mix_hash(&s, eph_pub, 32);

    /* -> es: MixDH(ephemeral, serverKey) */
    uint8_t ck_new[32], k_es[32];
    uint8_t shared_es[32];
    if (tsnode_x25519_shared(shared_es, eph_priv, control_key_pub) != 0) {
        TSNODE_LOGE(TAG, "Noise: DH es failed");
        return TSNODE_ERR_CRYPTO;
    }
    TSNODE_LOGI(TAG, "Noise: DH es OK");
    noise_key_derive(ck_new, k_es, shared_es, s.ck);
    memcpy(s.ck, ck_new, 32);
    mbedtls_platform_zeroize(shared_es, sizeof(shared_es));

    /* -> s: EncryptAndHash(machinePub) — 32 bytes plaintext */
    uint8_t enc_machine_pub[48];
    size_t enc_len;
    err = noise_encrypt_to(enc_machine_pub, &enc_len, k_es,
                           machine_key_pub, 32, s.h, 32);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "Noise: AEAD s failed: %d", err);
        return err;
    }
    TSNODE_LOGI(TAG, "Noise: AEAD s OK");
    noise_mix_hash(&s, enc_machine_pub, enc_len);

    /* -> ss: MixDH(machineKey, serverKey) */
    uint8_t ck_new2[32], k_ss[32];
    uint8_t shared_ss[32];
    if (tsnode_x25519_shared(shared_ss, machine_key_priv, control_key_pub) != 0) {
        TSNODE_LOGE(TAG, "Noise: DH ss failed");
        return TSNODE_ERR_CRYPTO;
    }
    TSNODE_LOGI(TAG, "Noise: DH ss OK");
    noise_key_derive(ck_new2, k_ss, shared_ss, s.ck);
    memcpy(s.ck, ck_new2, 32);
    mbedtls_platform_zeroize(shared_ss, sizeof(shared_ss));

    /* -> ss: EncryptAndHash(nil) — empty payload, tag only */
    uint8_t tag_ss[16];
    size_t tag_ss_len;
    err = noise_encrypt_to(tag_ss, &tag_ss_len, k_ss, NULL, 0, s.h, 32);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "Noise: AEAD ss failed: %d", err);
        return err;
    }
    TSNODE_LOGI(TAG, "Noise: AEAD ss OK");
    noise_mix_hash(&s, tag_ss, tag_ss_len);

    /* Assemble initiation message (101 bytes) */
    memset(init_out, 0, 101);
    init_out[0] = (uint8_t)(protocol_version >> 8);
    init_out[1] = (uint8_t)(protocol_version & 0xFF);
    init_out[2] = MSG_TYPE_INITIATION;
    init_out[3] = 0;
    init_out[4] = 96;
    memcpy(init_out + 5, eph_pub, 32);
    memcpy(init_out + 37, enc_machine_pub, 48);
    memcpy(init_out + 85, tag_ss, 16);

    /* Save state for completion */
    memcpy(state->handshake_hash, s.h, 32);
    memcpy(state->chaining_key, s.ck, 32);
    memcpy(state->eph_priv, eph_priv, 32);
    memcpy(state->eph_pub, eph_pub, 32);
    memcpy(state->machine_key_priv, machine_key_priv, 32);
    memcpy(state->control_key_pub, control_key_pub, 32);
    state->protocol_version = protocol_version;
    state->initiated = true;

    /* Clean up local copies */
    mbedtls_platform_zeroize(eph_priv, sizeof(eph_priv));
    mbedtls_platform_zeroize(k_es, sizeof(k_es));
    mbedtls_platform_zeroize(k_ss, sizeof(k_ss));

    return TSNODE_OK;
}

tsnode_err_t ts2021_handshake_complete(
    ts2021_conn_t *conn,
    const ts2021_handshake_state_t *state,
    const uint8_t response[51],
    tsnode_port_socket_t *sock)
{
    if (conn == NULL || state == NULL || response == NULL || sock == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (!state->initiated) {
        return TSNODE_ERR_INVALID_STATE;
    }

    tsnode_err_t err;
    noise_symmetric_t s;

    /* Restore state */
    memcpy(s.h, state->handshake_hash, 32);
    memcpy(s.ck, state->chaining_key, 32);

    /* Parse response: type(1) + len(2) + ephemeral_pub(32) + tag(16) */
    if (response[0] == MSG_TYPE_ERROR) {
        uint16_t err_len = ((uint16_t)response[1] << 8) | response[2];
        TSNODE_LOGE(TAG, "server error frame (%u bytes)", err_len);
        return TSNODE_ERR_NETWORK;
    }
    if (response[0] != MSG_TYPE_RESPONSE) {
        TSNODE_LOGE(TAG, "unexpected response type: %u", response[0]);
        return TSNODE_ERR_NETWORK;
    }

    uint8_t control_eph_pub[32];
    uint8_t resp_tag[16];
    memcpy(control_eph_pub, response + 3, 32);
    memcpy(resp_tag, response + 35, 16);

    /* <- e: mixHash(controlEphemeralPub) */
    noise_mix_hash(&s, control_eph_pub, 32);

    /* <- ee: MixDH(machineEphemeral, controlEphemeral) */
    uint8_t ck_ee[32], k_ee[32];
    uint8_t shared_ee[32];
    if (tsnode_x25519_shared(shared_ee, state->eph_priv, control_eph_pub) != 0) {
        return TSNODE_ERR_CRYPTO;
    }
    noise_key_derive(ck_ee, k_ee, shared_ee, s.ck);
    memcpy(s.ck, ck_ee, 32);
    mbedtls_platform_zeroize(shared_ee, sizeof(shared_ee));

    /* <- se: MixDH(controlEphemeral, machineKey) */
    uint8_t ck_se[32], k_se[32];
    uint8_t shared_se[32];
    if (tsnode_x25519_shared(shared_se, state->machine_key_priv, control_eph_pub) != 0) {
        return TSNODE_ERR_CRYPTO;
    }
    noise_key_derive(ck_se, k_se, shared_se, s.ck);
    memcpy(s.ck, ck_se, 32);
    mbedtls_platform_zeroize(shared_se, sizeof(shared_se));

    /* <- e: DecryptAndHash(tag) — empty payload */
    uint8_t decrypted_tag[16];
    size_t dec_len;
    err = noise_decrypt_from(decrypted_tag, &dec_len, k_se, resp_tag, 16, s.h, 32);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "response tag verification failed");
        return TSNODE_ERR_CRYPTO;
    }
    noise_mix_hash(&s, resp_tag, 16);

    /* Split: derive tx/rx keys from chaining key via HKDF-BLAKE2s.
     * Go: hkdf.New(newBLAKE2s, nil, s.ck[:], nil) -> k1 || k2
     * This is HKDF-Extract(salt=ck, IKM=nil) then HKDF-Expand(prk, nil, 64) */
    uint8_t derived[64];
    noise_split(derived, derived + 32, s.ck);

    memcpy(conn->tx_key, derived, 32);
    memcpy(conn->rx_key, derived + 32, 32);
    conn->tx_counter = 0;
    conn->rx_counter = 0;
    conn->sock = sock;
    conn->established = true;
    conn->prebuf_len = 0;
    conn->recv_timeout_ms = 10000;  /* Default: 10s per-record timeout */

    mbedtls_platform_zeroize(&s, sizeof(s));
    mbedtls_platform_zeroize(derived, sizeof(derived));

    return TSNODE_OK;
}
