/*
 * Disco protocol: minimal implementation for NAT traversal (ADR-0014).
 *
 * Implements: STUN binding, crypto_box PING/PONG, hole puncher.
 * Uses the NaCl crypto_box construction with X25519 from the WireGuard
 * crypto backend as the DH injector (ADR-0015).
 *
 * Pure C11, no platform headers (ADR-0006). All I/O via port layer.
 */

#include "disco.h"
#include "wg.h"
#include "tsnode_port.h"
#include "nacl_box.h"

#include <stdio.h>
#include <string.h>

#define TAG "tsnode_disco"

/* ---- Disco magic bytes ---- */
/* "TS" + 0xf0 0x9f 0x92 0xac (emoji in UTF-8, used for demux) */
static const uint8_t DISCO_MAGIC[6] = {
    0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac
};

/* ---- NVS keys for disco key persistence ---- */
#define TS_ID_NVS_NAMESPACE "tsnode"
static const char *TS_ID_KEY_DISCO_PUB  = "discpub";
static const char *TS_ID_KEY_DISCO_PRIV = "discprv";

/* ---- Internal helpers ---- */

/* Constant-time comparison (AGENTS.md section 4: never use memcmp for secrets).
 * Retorna TRUE si los buffers son iguales (nombre explícito: ct_equal, no
 * ct_memcmp — memcmp retorna 0 en la igualdad, esto retorna 1). Los call
 * sites usan `if (ct_equal(...))` como condición de igualdad. */
static bool ct_equal(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *x = a;
    const volatile uint8_t *y = b;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= x[i] ^ y[i];
    }
    return diff == 0;
}

/* Format IP:port for logging (no emoji, clean ASCII) */
static void log_ip_port(const char *prefix, uint32_t ip, uint16_t port)
{
    TSNODE_LOGI(TAG, "%s%u.%u.%u.%u:%u",
                prefix,
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF, ip & 0xFF, port);
}

/* ---- Lifecycle ---- */

tsnode_err_t tsnode_disco_init(tsnode_disco_state_t *st,
                               const uint8_t wg_pubkey[32],
                               const tsnode_wg_crypto_t *crypto)
{
    if (st == NULL || wg_pubkey == NULL || crypto == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    memset(st, 0, sizeof(*st));
    memcpy(st->my_wg_pubkey, wg_pubkey, 32);

    /* Generate disco keypair */
    tsnode_err_t err = crypto->keygen(st->my_kp.priv, st->my_kp.pub);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "disco keygen failed: %d", err);
        return err;
    }

    TSNODE_LOGI(TAG, "disco init OK");
    return TSNODE_OK;
}

tsnode_err_t tsnode_disco_load_or_generate(tsnode_disco_state_t *st,
                                           const uint8_t wg_pubkey[32],
                                           const tsnode_wg_crypto_t *crypto)
{
    if (st == NULL || wg_pubkey == NULL || crypto == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    memset(st, 0, sizeof(*st));
    memcpy(st->my_wg_pubkey, wg_pubkey, 32);

    /* Try to load from NVS */
    bool ok_pub = tsnode_port_kv_get(TS_ID_NVS_NAMESPACE, TS_ID_KEY_DISCO_PUB,
                                     st->my_kp.pub, TSNODE_DISCO_KEY_LEN);
    bool ok_priv = tsnode_port_kv_get(TS_ID_NVS_NAMESPACE, TS_ID_KEY_DISCO_PRIV,
                                      st->my_kp.priv, TSNODE_DISCO_KEY_LEN);

    if (ok_pub && ok_priv) {
        TSNODE_LOGI(TAG, "disco keys loaded from NVS");
        return TSNODE_OK;
    }

    /* Generate new keypair */
    TSNODE_LOGI(TAG, "no disco keys in NVS, generating new pair");
    tsnode_err_t err = crypto->keygen(st->my_kp.priv, st->my_kp.pub);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "disco keygen failed: %d", err);
        return err;
    }

    /* Persist to NVS */
    bool saved_pub = tsnode_port_kv_set(TS_ID_NVS_NAMESPACE, TS_ID_KEY_DISCO_PUB,
                                        st->my_kp.pub, TSNODE_DISCO_KEY_LEN);
    bool saved_priv = tsnode_port_kv_set(TS_ID_NVS_NAMESPACE, TS_ID_KEY_DISCO_PRIV,
                                         st->my_kp.priv, TSNODE_DISCO_KEY_LEN);

    if (!saved_pub || !saved_priv) {
        TSNODE_LOGW(TAG, "disco key persist failed (will regenerate on next boot)");
    } else {
        TSNODE_LOGI(TAG, "disco keys persisted to NVS");
    }

    return TSNODE_OK;
}

const uint8_t *tsnode_disco_get_pubkey(const tsnode_disco_state_t *st)
{
    if (st == NULL) return NULL;
    return st->my_kp.pub;
}

/* ---- Peer management ---- */

tsnode_err_t tsnode_disco_add_peer(tsnode_disco_state_t *st,
                                   const uint8_t wg_pubkey[32],
                                   const uint8_t disco_pubkey[32],
                                   const uint32_t *endpoint_ips,
                                   const uint16_t *endpoint_ports,
                                   int n_eps)
{
    if (st == NULL || wg_pubkey == NULL || disco_pubkey == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    TSNODE_LOGI(TAG, "disco add: %d peers", st->n_peers);

    /* Check if peer already exists (by WG key) */
    for (int i = 0; i < st->n_peers; i++) {
        if (memcmp(st->peers[i].wg_pubkey, wg_pubkey, 32) == 0) {
            TSNODE_LOGI(TAG, "disco add: updating existing peer %d (n_peers=%d)",
                        i, st->n_peers);
            /* Update existing peer */
            memcpy(st->peers[i].disco_pubkey, disco_pubkey, TSNODE_DISCO_KEY_LEN);
            st->peers[i].n_endpoints = 0;
            if (endpoint_ips != NULL && endpoint_ports != NULL) {
                unsigned int max_eps = n_eps > 0 ? (unsigned int)n_eps : 0u;
                for (unsigned int j = 0; j < max_eps && j < TSNODE_DISCO_MAX_ENDPOINTS; j++) {
                    st->peers[i].endpoints[j].ip = endpoint_ips[j];
                    st->peers[i].endpoints[j].port = endpoint_ports[j];
                    st->peers[i].n_endpoints++;
                }
            }
            TSNODE_LOGI(TAG, "disco peer %d updated", i);
            return TSNODE_OK;
        }
    }

    /* Add new peer */
    if ((unsigned int)st->n_peers >= TSNODE_DISCO_MAX_PEERS) {
        TSNODE_LOGW(TAG, "disco peer table full");
        return TSNODE_ERR_NO_MEMORY;
    }

    tsnode_disco_peer_t *peer = &st->peers[st->n_peers];
    memcpy(peer->wg_pubkey, wg_pubkey, 32);
    memcpy(peer->disco_pubkey, disco_pubkey, TSNODE_DISCO_KEY_LEN);
    peer->n_endpoints = 0;
    if (endpoint_ips != NULL && endpoint_ports != NULL) {
        unsigned int max_eps = n_eps > 0 ? (unsigned int)n_eps : 0u;
        for (unsigned int j = 0; j < max_eps && j < TSNODE_DISCO_MAX_ENDPOINTS; j++) {
            peer->endpoints[j].ip = endpoint_ips[j];
            peer->endpoints[j].port = endpoint_ports[j];
            peer->n_endpoints++;
        }
    }

    TSNODE_LOGI(TAG, "disco peer %d added", st->n_peers);
    st->n_peers++;
    return TSNODE_OK;
}

/* ---- Packet detection ---- */

bool tsnode_disco_is_disco_packet(const uint8_t *pkt, size_t len)
{
    if (len < TSNODE_DISCO_MAGIC_LEN + TSNODE_DISCO_KEY_LEN + TSNODE_DISCO_NONCE_LEN + 2) {
        return false;
    }
    return memcmp(pkt, DISCO_MAGIC, TSNODE_DISCO_MAGIC_LEN) == 0;
}

bool tsnode_disco_is_stun_response(const uint8_t *pkt, size_t len)
{
    if (len < 20) return false;
    /* RFC 5389: Binding Success Response type = 0x0101, magic cookie at 4..7 */
    const uint8_t magic[4] = { 0x21, 0x12, 0xa4, 0x42 };
    return (pkt[0] == 0x01 && pkt[1] == 0x01) &&
           memcmp(pkt + 4, magic, 4) == 0;
}

/* ---- Find peer by disco key ---- */

static tsnode_disco_peer_t *find_peer_by_disco_key(tsnode_disco_state_t *st,
                                                    const uint8_t disco_pub[32])
{
    for (int i = 0; i < st->n_peers; i++) {
        if (ct_equal(st->peers[i].disco_pubkey, disco_pub, 32)) {
            return &st->peers[i];
        }
    }
    return NULL;
}

/* ---- crypto_box operations ---- */

/* Derive the crypto_box shared key from X25519 DH + HSalsa20 fold.
 * This is the NaCl box.Precompute used by Tailscale disco.
 * crypto->dh provides X25519; nacl_box adds the HSalsa20(shared,0,sigma)
 * folding that ChaCha20-era code omitted (and which is required for
 * wire-interoperability with Tailscale's XSalsa20-Poly1305 secretbox). */
static tsnode_err_t disco_box_seal(uint8_t *out, size_t *out_len,
                                   const uint8_t *plain, size_t plain_len,
                                   const uint8_t nonce[24],
                                   const uint8_t peer_pub[32],
                                   const uint8_t my_priv[32],
                                   const tsnode_wg_crypto_t *crypto)
{
    return tsnode_nacl_box_seal(out, out_len, plain, plain_len, nonce,
                                my_priv, peer_pub, crypto->dh);
}

/* Decrypt with crypto_box (NaCl XSalsa20-Poly1305). Verify anti-replay
 * of the DH result and authentication both fail closed inside nacl_box. */
static tsnode_err_t disco_box_open(uint8_t *plain, size_t *plain_len,
                                   const uint8_t *box, size_t box_len,
                                   const uint8_t nonce[24],
                                   const uint8_t sender_pub[32],
                                   const uint8_t my_priv[32],
                                   const tsnode_wg_crypto_t *crypto)
{
    return tsnode_nacl_box_open(plain, plain_len, box, box_len, nonce,
                                my_priv, sender_pub, crypto->dh);
}

/* ---- Handle incoming disco packet ---- */

tsnode_err_t tsnode_disco_handle_packet(tsnode_disco_state_t *st,
                                        const uint8_t *pkt, size_t len,
                                        uint32_t src_ip, uint16_t src_port,
                                        tsnode_port_udp_socket_t *udp_sock,
                                        const tsnode_wg_crypto_t *crypto)
{
    if (st == NULL || pkt == NULL || crypto == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    if (!tsnode_disco_is_disco_packet(pkt, len)) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* Parse header */
    const uint8_t *sender_disco_pub = pkt + TSNODE_DISCO_MAGIC_LEN;
    const uint8_t *nonce = pkt + TSNODE_DISCO_MAGIC_LEN + TSNODE_DISCO_KEY_LEN;
    const uint8_t *box = pkt + TSNODE_DISCO_MAGIC_LEN + TSNODE_DISCO_KEY_LEN + TSNODE_DISCO_NONCE_LEN;
    size_t box_len = len - TSNODE_DISCO_MAGIC_LEN - TSNODE_DISCO_KEY_LEN - TSNODE_DISCO_NONCE_LEN;

    if (box_len < TSNODE_DISCO_MACBYTES + 2) {
        TSNODE_LOGW(TAG, "disco packet too short");
        return TSNODE_ERR_NETWORK;
    }

    /* Find sender peer */
    tsnode_disco_peer_t *peer = find_peer_by_disco_key(st, sender_disco_pub);
    if (peer == NULL) {
        TSNODE_LOGW(TAG, "disco from unknown peer");
        return TSNODE_OK;
    }

    /* Decrypt */
    uint8_t plain[TSNODE_DISCO_MAX_PKT];
    size_t plain_len = 0;
    tsnode_err_t err = disco_box_open(plain, &plain_len, box, box_len,
                                      nonce, sender_disco_pub, st->my_kp.priv,
                                      crypto);
    if (err != TSNODE_OK) {
        TSNODE_LOGW(TAG, "disco decrypt failed");
        return err;
    }

    /* Parse inner message */
    uint8_t msg_type = plain[0];
    switch (msg_type) {
    case TSNODE_DISCO_PING: {
        TSNODE_LOGI(TAG, "disco RX PING");

        /* Extract txid */
        uint8_t txid[TSNODE_DISCO_TXID_LEN];
        memcpy(txid, plain + 2, TSNODE_DISCO_TXID_LEN);

        /* Build PONG */
        uint8_t pong_plain[TSNODE_DISCO_PONG_LEN];
        pong_plain[0] = TSNODE_DISCO_PONG;
        pong_plain[1] = 0x00;
        memcpy(pong_plain + 2, txid, TSNODE_DISCO_TXID_LEN);
        memset(pong_plain + 14, 0, 16);
        pong_plain[30] = 0;
        pong_plain[31] = 0;

        /* Encrypt PONG */
        uint8_t pong_nonce[24];
        err = crypto->random(pong_nonce, 24);
        if (err != TSNODE_OK) return err;

        uint8_t pong_box[TSNODE_DISCO_MAX_PKT];
        size_t pong_box_len = 0;
        err = disco_box_seal(pong_box, &pong_box_len, pong_plain, TSNODE_DISCO_PONG_LEN,
                             pong_nonce, peer->disco_pubkey, st->my_kp.priv, crypto);
        if (err != TSNODE_OK) {
            TSNODE_LOGE(TAG, "disco PONG encrypt failed");
            return err;
        }

        /* Build PONG packet */
        uint8_t pkt_out[TSNODE_DISCO_MAX_PKT];
        memcpy(pkt_out, DISCO_MAGIC, TSNODE_DISCO_MAGIC_LEN);
        memcpy(pkt_out + TSNODE_DISCO_MAGIC_LEN, st->my_kp.pub, TSNODE_DISCO_KEY_LEN);
        memcpy(pkt_out + TSNODE_DISCO_MAGIC_LEN + TSNODE_DISCO_KEY_LEN, pong_nonce, 24);
        memcpy(pkt_out + TSNODE_DISCO_MAGIC_LEN + TSNODE_DISCO_KEY_LEN + 24,
               pong_box, pong_box_len);

        size_t pkt_len = TSNODE_DISCO_MAGIC_LEN + TSNODE_DISCO_KEY_LEN + 24 + pong_box_len;

        /* Send PONG via UDP socket */
        if (udp_sock != NULL) {
            err = tsnode_port_udp_sendto(udp_sock, pkt_out, pkt_len, src_ip, src_port);
            if (err != TSNODE_OK) {
                TSNODE_LOGW(TAG, "disco PONG send failed: %d", err);
            } else {
                log_ip_port("disco TX PONG -> ", src_ip, src_port);
            }
        }
        break;
    }
    case TSNODE_DISCO_PONG: {
        uint8_t txid[TSNODE_DISCO_TXID_LEN];
        memcpy(txid, plain + 2, TSNODE_DISCO_TXID_LEN);
        if (ct_equal(txid, peer->pending_txid, TSNODE_DISCO_TXID_LEN)) {
            peer->direct_path_ok = true;
            peer->retry_count = 0;
            /* Guardar la ruta directa REAL (IP:port del que respondió el
             * PONG, normalmente el LAN del peer). El data plane WG usa esto
             * para el handshake, no el endpoints[0] público del MapResponse. */
            peer->direct_ip = src_ip;
            peer->direct_port = src_port;
            uint64_t now_ms;
            tsnode_port_uptime_ms(&now_ms);
            peer->last_pong_ms = now_ms;
            log_ip_port("disco RX PONG - direct path ", src_ip, src_port);
            TSNODE_LOGI(TAG, "disco RX PONG - direct path confirmed");
        } else {
            TSNODE_LOGW(TAG, "disco PONG unexpected txid");
        }
        break;
    }
    default:
        TSNODE_LOGW(TAG, "disco unknown type 0x%02x", msg_type);
        break;
    }

    return TSNODE_OK;
}

/* ---- Send PING ---- */

tsnode_err_t tsnode_disco_send_ping(tsnode_disco_state_t *st, int peer_idx,
                                    tsnode_port_udp_socket_t *udp_sock,
                                    const tsnode_wg_crypto_t *crypto)
{
    if (st == NULL || peer_idx < 0 || peer_idx >= st->n_peers || crypto == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    tsnode_disco_peer_t *peer = &st->peers[peer_idx];
    if (peer->n_endpoints == 0) {
        return TSNODE_ERR_INVALID_STATE;
    }

    /* Generate random txid and nonce */
    tsnode_err_t err;
    err = crypto->random(peer->pending_txid, TSNODE_DISCO_TXID_LEN);
    if (err != TSNODE_OK) return err;

    uint8_t nonce[24];
    err = crypto->random(nonce, 24);
    if (err != TSNODE_OK) return err;

    /* Build plaintext: type(1) + ver(1) + txid(12) + nodekey(32) = 46 bytes */
    uint8_t plain[64];
    plain[0] = TSNODE_DISCO_PING;
    plain[1] = 0x00;
    memcpy(plain + 2, peer->pending_txid, TSNODE_DISCO_TXID_LEN);
    memcpy(plain + 14, st->my_wg_pubkey, 32);
    size_t plain_len = 46;

    /* Encrypt with crypto_box */
    uint8_t box[TSNODE_DISCO_MAX_PKT];
    size_t box_len = 0;
    err = disco_box_seal(box, &box_len, plain, plain_len,
                         nonce, peer->disco_pubkey, st->my_kp.priv, crypto);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "disco PING encrypt failed");
        return err;
    }

    /* Build full packet */
    uint8_t pkt[TSNODE_DISCO_MAX_PKT];
    memcpy(pkt, DISCO_MAGIC, TSNODE_DISCO_MAGIC_LEN);
    memcpy(pkt + TSNODE_DISCO_MAGIC_LEN, st->my_kp.pub, TSNODE_DISCO_KEY_LEN);
    memcpy(pkt + TSNODE_DISCO_MAGIC_LEN + TSNODE_DISCO_KEY_LEN, nonce, 24);
    memcpy(pkt + TSNODE_DISCO_MAGIC_LEN + TSNODE_DISCO_KEY_LEN + 24, box, box_len);

    size_t pkt_len = TSNODE_DISCO_MAGIC_LEN + TSNODE_DISCO_KEY_LEN + 24 + box_len;

    /* Send to all endpoints */
    if (udp_sock != NULL) {
        for (int i = 0; i < peer->n_endpoints; i++) {
            err = tsnode_port_udp_sendto(udp_sock, pkt, pkt_len,
                                         peer->endpoints[i].ip,
                                         peer->endpoints[i].port);
            if (err != TSNODE_OK) {
                TSNODE_LOGW(TAG, "disco PING send failed: %d", err);
            } else {
                log_ip_port("disco TX PING -> ", peer->endpoints[i].ip,
                            peer->endpoints[i].port);
            }
        }
    }

    peer->retry_count++;
    return TSNODE_OK;
}

/* ---- STUN: discover public endpoint ---- */

tsnode_err_t tsnode_disco_stun_request(tsnode_disco_state_t *st,
                                       uint32_t stun_server_ip,
                                       uint16_t stun_server_port,
                                       tsnode_port_udp_socket_t *udp_sock,
                                       const tsnode_wg_crypto_t *crypto)
{
    if (st == NULL || stun_server_ip == 0 || crypto == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* RFC 5389 STUN Binding Request (20 bytes) */
    uint8_t req[20];
    req[0] = 0x00; req[1] = 0x01;  /* Binding Request */
    req[2] = 0x00; req[3] = 0x00;  /* Message Length = 0 */
    req[4] = 0x21; req[5] = 0x12;  /* Magic Cookie */
    req[6] = 0xA4; req[7] = 0x42;

    tsnode_err_t err = crypto->random(req + 8, 12);
    if (err != TSNODE_OK) return err;

    if (udp_sock != NULL) {
        err = tsnode_port_udp_sendto(udp_sock, req, sizeof(req),
                                     stun_server_ip, stun_server_port);
        if (err != TSNODE_OK) {
            TSNODE_LOGW(TAG, "STUN send failed: %d", err);
            return err;
        }
        log_ip_port("STUN TX -> ", stun_server_ip, stun_server_port);
    }

    return TSNODE_OK;
}

tsnode_err_t tsnode_disco_stun_parse_response(tsnode_disco_state_t *st,
                                              const uint8_t *resp, size_t len)
{
    if (st == NULL || resp == NULL || len < 32) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* Check: must be Binding Success Response */
    if (resp[0] != 0x01 || resp[1] != 0x01) {
        return TSNODE_ERR_NETWORK;
    }

    uint16_t msg_len = (uint16_t)((resp[2] << 8) | resp[3]);
    const uint8_t *attrs = resp + 20;
    size_t attrs_len = msg_len;

    while (attrs_len >= 4) {
        uint16_t attr_type = (uint16_t)((attrs[0] << 8) | attrs[1]);
        uint16_t attr_len  = (uint16_t)((attrs[2] << 8) | attrs[3]);
        size_t attr_total = 4 + attr_len + ((4 - (attr_len % 4)) % 4);

        if (attr_total > attrs_len) break;

        /* XOR-MAPPED-ADDRESS (0x0020) */
        if (attr_type == 0x0020 && attr_len >= 8 && attrs[5] == 0x01) {
            uint16_t xport = (uint16_t)((attrs[6] << 8) | attrs[7]);
            uint32_t xip   = ((uint32_t)attrs[8] << 24) |
                             ((uint32_t)attrs[9] << 16) |
                             ((uint32_t)attrs[10] << 8) |
                             (uint32_t)attrs[11];

            st->stun.public_port = (uint16_t)(xport ^ 0x2112);
            st->stun.public_ip = xip ^ 0x2112A442;
            st->stun.discovered = true;

            log_ip_port("STUN RX: public endpoint ", st->stun.public_ip, st->stun.public_port);
            return TSNODE_OK;
        }

        attrs += attr_total;
        attrs_len -= attr_total;
    }

    return TSNODE_ERR_NETWORK;
}

/* ---- Poll (periodic tasks) ---- */

tsnode_err_t tsnode_disco_poll(tsnode_disco_state_t *st,
                               uint32_t stun_server_ip,
                               uint16_t stun_server_port,
                               tsnode_port_udp_socket_t *udp_sock,
                               const tsnode_wg_crypto_t *crypto)
{
    if (st == NULL || crypto == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    uint64_t now_ms;
    tsnode_port_uptime_ms(&now_ms);

    TSNODE_LOGI(TAG, "poll: stun=%u.%u.%u.%u:%u n_peers=%d",
                (stun_server_ip >> 24) & 0xff, (stun_server_ip >> 16) & 0xff,
                (stun_server_ip >> 8) & 0xff, stun_server_ip & 0xff,
                stun_server_port, st->n_peers);

    /* Periodic STUN (every 30s) */
    if (!st->stun.discovered || (now_ms - st->last_stun_ms) > TSNODE_DISCO_STUN_INTERVAL_MS) {
        tsnode_disco_stun_request(st, stun_server_ip, stun_server_port, udp_sock, crypto);
        st->last_stun_ms = now_ms;
    }

    /* Per-peer tasks */
    for (int i = 0; i < st->n_peers; i++) {
        tsnode_disco_peer_t *peer = &st->peers[i];

        if (peer->direct_path_ok) {
            /* Keepalive: re-PING every 20s */
            if ((now_ms - peer->last_pong_ms) > TSNODE_DISCO_KEEPALIVE_MS) {
                TSNODE_LOGI(TAG, "disco keepalive peer=%d", i);
                tsnode_disco_send_ping(st, i, udp_sock, crypto);
            }
            continue;
        }

        /* Retry hole-punching */
        if ((unsigned int)peer->retry_count < TSNODE_DISCO_MAX_RETRIES) {
            if (peer->retry_count == 0 ||
                (now_ms - peer->last_pong_ms) > TSNODE_DISCO_RETRY_MS) {
                tsnode_disco_send_ping(st, i, udp_sock, crypto);
                peer->last_pong_ms = now_ms;
            }
        }
    }

    return TSNODE_OK;
}

/* ---- Get STUN-discovered public endpoint ---- */

bool tsnode_disco_get_stun_endpoint(const tsnode_disco_state_t *st,
                                    uint32_t *ip_out, uint16_t *port_out)
{
    if (st == NULL || ip_out == NULL || port_out == NULL) {
        return false;
    }
    if (!st->stun.discovered) {
        return false;
    }
    *ip_out = st->stun.public_ip;
    *port_out = st->stun.public_port;
    return true;
}

/* ---- Get best endpoint ---- */

bool tsnode_disco_get_peer_endpoint(const tsnode_disco_state_t *st,
                                    int peer_idx,
                                    uint32_t *ip_out, uint16_t *port_out)
{
    if (st == NULL || peer_idx < 0 || peer_idx >= st->n_peers ||
        ip_out == NULL || port_out == NULL) {
        return false;
    }

    const tsnode_disco_peer_t *peer = &st->peers[peer_idx];

    if (!peer->direct_path_ok) {
        return false;
    }

    /* Devolver la ruta directa REAL confirmada por PONG (ej. LAN del peer);
     * no endpoints[0] que es el público del MapResponse. */
    if (peer->direct_ip != 0 && peer->direct_port != 0) {
        *ip_out = peer->direct_ip;
        *port_out = peer->direct_port;
        return true;
    }

    /* Fallback defensivo: si no hay ruta directa guardada pero direct_path_ok
     * quedó seteado, usar el primer endpoint. */
    if (peer->n_endpoints > 0) {
        *ip_out = peer->endpoints[0].ip;
        *port_out = peer->endpoints[0].port;
        return true;
    }

    return false;
}

int tsnode_disco_find_peer_by_wg_key(const tsnode_disco_state_t *st,
                                     const uint8_t wg_pubkey[32])
{
    if (st == NULL || wg_pubkey == NULL) {
        return -1;
    }
    for (int i = 0; i < st->n_peers; i++) {
        if (memcmp(st->peers[i].wg_pubkey, wg_pubkey, 32) == 0) {
            return i;
        }
    }
    return -1;
}
