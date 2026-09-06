/*
 * Disco host tests — PING/PONG round-trip and endpoint selection
 * (ADR-0018: WG handshake uses the disco-confirmed direct path).
 *
 * Exercises the real disco.c against host stubs for the port layer:
 *   - tsnode_disco_find_peer_by_wg_key (lookup semantics, NULL safety)
 *   - tsnode_disco_get_peer_endpoint (direct path preferred over
 *     endpoints[0], defensive fallback, fail-closed when no route)
 *   - full disco PING -> PONG round-trip through nacl_box seal/open,
 *     including direct_ip/direct_port capture from the PONG UDP source
 *   - incoming PING answered with a PONG (src address echoed back)
 *   - tampered/unknown txid in a PONG is fail-closed (no direct path)
 *
 * Crypto backend: TweetNaCl X25519 (independent reference) + vendored
 * Salsa20/Poly1305 from third_party/. The wg_crypto_host backend only
 * supplies keygen/random for disco itself; message crypto here uses
 * tsnode_nacl_box directly with the TweetNaCl DH, like test_nacl_box.
 */

#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disco.h"
#include "nacl_box.h"
#include "tsnode_err.h"
#include "tweetnacl.h"
#include "wg.h"

static int failures;

/* ------------------------------------------------------------------ */
/* Port-layer stubs (ADR-0006: core never touches platform headers)   */
/* ------------------------------------------------------------------ */

static uint64_t g_uptime_ms;
static uint64_t g_uptime_step_ms = 1000;

tsnode_err_t tsnode_port_uptime_ms(uint64_t *out_ms)
{
    if (out_ms == NULL) return TSNODE_ERR_INVALID_ARG;
    *out_ms = g_uptime_ms;
    g_uptime_ms += g_uptime_step_ms;
    return TSNODE_OK;
}

/* KV store: no persistence in host tests. load_or_generate is not
 * exercised here (tests use tsnode_disco_init), so these just satisfy
 * the link. */
bool tsnode_port_kv_get(const char *ns, const char *key, uint8_t *out,
                        size_t len)
{
    (void)ns; (void)key; (void)out; (void)len;
    return false;
}

bool tsnode_port_kv_set(const char *ns, const char *key, const uint8_t *val,
                        size_t len)
{
    (void)ns; (void)key; (void)val; (void)len;
    return true;
}

void tsnode_port_kv_del(const char *ns, const char *key)
{
    (void)ns; (void)key;
}

/* UDP send capture: keeps the last datagram and its destination so tests
 * can inspect PING/PONG packets and where disco sent them. */
static uint8_t g_tx_buf[TSNODE_DISCO_MAX_PKT];
static size_t g_tx_len;
static uint32_t g_tx_ip;
static uint16_t g_tx_port;
static int g_tx_count;

/* The port stubs ignore the socket content; a non-NULL pointer is enough
 * to let disco actually "send" (amortized into g_tx_*). */
static char g_dummy_sock;

tsnode_err_t tsnode_port_udp_sendto(tsnode_port_udp_socket_t *sock,
                                    const uint8_t *data, size_t len,
                                    uint32_t dest_ip, uint16_t dest_port)
{
    (void)sock;
    if (data == NULL || len > sizeof(g_tx_buf)) {
        return TSNODE_ERR_NETWORK;
    }
    memcpy(g_tx_buf, data, len);
    g_tx_len = len;
    g_tx_ip = dest_ip;
    g_tx_port = dest_port;
    g_tx_count++;
    return TSNODE_OK;
}

static tsnode_port_log_fn g_log_fn;

void tsnode_port_set_log(tsnode_port_log_fn fn)
{
    g_log_fn = fn;
}

tsnode_port_log_fn tsnode_port_get_log(void)
{
    return g_log_fn;
}

/* Optional diagnostic logging from the core (TSNODE_TEST_LOG=1). */
static void test_log(int level, const char *tag, const char *fmt, ...)
{
    (void)level;
    fprintf(stderr, "[%s] ", tag);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int ct_cmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff != 0;
}

/* TweetNaCl X25519 used as the box DH backend (independent reference). */
static tsnode_err_t tweet_dh(uint8_t shared[32], const uint8_t priv[32],
                             const uint8_t pub[32])
{
    if (crypto_scalarmult_curve25519_tweet(shared, priv, pub) != 0) {
        return TSNODE_ERR_CRYPTO;
    }
    return TSNODE_OK;
}

/* Deterministic keypair (TweetNaCl clamps internally, RFC 7748 §5). */
static void make_keypair(uint8_t priv[32], uint8_t pub[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(0x40 + seed + i);
    if (crypto_scalarmult_curve25519_tweet_base(pub, priv) != 0) {
        printf("  FAIL keygen\n");
        failures++;
    }
}

/* Build a full disco wire packet: magic|sender_pub|nonce|box */
static size_t wrap_disco_pkt(uint8_t *out,
                             const uint8_t sender_pub[32],
                             const uint8_t nonce[24],
                             const uint8_t *box, size_t box_len)
{
    static const uint8_t magic[6] = {
        0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac
    };
    memcpy(out, magic, 6);
    memcpy(out + 6, sender_pub, 32);
    memcpy(out + 6 + 32, nonce, 24);
    memcpy(out + 6 + 32 + 24, box, box_len);
    return 6 + 32 + 24 + box_len;
}

/* IPv4-mapped 16-byte form of an IPv4 address (Tailscale disco ip16). */
static void ip16_from_ipv4(uint8_t out[16], uint32_t ip)
{
    memset(out, 0, 10);
    out[10] = 0xff; out[11] = 0xff;
    out[12] = (uint8_t)((ip >> 24) & 0xff);
    out[13] = (uint8_t)((ip >> 16) & 0xff);
    out[14] = (uint8_t)((ip >> 8) & 0xff);
    out[15] = (uint8_t)(ip & 0xff);
}

/* ------------------------------------------------------------------ */
/* 1. find_peer_by_wg_key                                              */
/* ------------------------------------------------------------------ */

static void test_find_peer_by_wg_key(void)
{
    tsnode_disco_state_t st;
    const tsnode_wg_crypto_t *cr = tsnode_wg_crypto_host();
    uint8_t my_wg_pub[32];
    uint8_t peer_a_priv[32], peer_a_pub[32];
    uint8_t peer_b_priv[32], peer_b_pub[32];

    for (int i = 0; i < 32; i++) my_wg_pub[i] = (uint8_t)(0x10 + i);
    make_keypair(peer_a_priv, peer_a_pub, 1);
    make_keypair(peer_b_priv, peer_b_pub, 2);

    printf("find_peer_by_wg_key:\n");

    /* Empty table -> -1 */
    tsnode_disco_state_t empty;
    memset(&empty, 0, sizeof(empty));
    if (tsnode_disco_find_peer_by_wg_key(&empty, peer_a_pub) != -1) {
        printf("  FAIL empty table not -1\n"); failures++;
    } else printf("  OK   empty table -> -1\n");

    if (tsnode_disco_init(&st, my_wg_pub, cr) != TSNODE_OK) {
        printf("  FAIL init\n"); failures++; return;
    }

    uint32_t eps_a[2] = { 0xc0000001u, 0xc0a80132u }; /* 192.0.2.1 / 192.168.1.50 */
    uint16_t ports_a[2] = { 41641, 41641 };
    uint32_t eps_b[1] = { 0xcb007105u };              /* 203.0.113.5 */
    uint16_t ports_b[1] = { 41641 };

    if (tsnode_disco_add_peer(&st, peer_a_pub, peer_a_pub, eps_a, ports_a, 2)
        != TSNODE_OK) {
        printf("  FAIL add peer A\n"); failures++; return;
    }
    if (tsnode_disco_add_peer(&st, peer_b_pub, peer_b_pub, eps_b, ports_b, 1)
        != TSNODE_OK) {
        printf("  FAIL add peer B\n"); failures++; return;
    }
    /* Adding the same peer again updates in place (no duplicate) */
    tsnode_disco_add_peer(&st, peer_a_pub, peer_a_pub, eps_a, ports_a, 2);

    int ia = tsnode_disco_find_peer_by_wg_key(&st, peer_a_pub);
    int ib = tsnode_disco_find_peer_by_wg_key(&st, peer_b_pub);
    if (ia != 0 || ib != 1 || st.n_peers != 2) {
        printf("  FAIL lookup: ia=%d ib=%d n=%d\n", ia, ib, st.n_peers);
        failures++;
    } else printf("  OK   found both peers (no dup)\n");

    uint8_t unknown[32];
    memset(unknown, 0x77, sizeof(unknown));
    if (tsnode_disco_find_peer_by_wg_key(&st, unknown) != -1) {
        printf("  FAIL unknown key not -1\n"); failures++;
    } else printf("  OK   unknown key -> -1\n");

    if (tsnode_disco_find_peer_by_wg_key(NULL, peer_a_pub) != -1 ||
        tsnode_disco_find_peer_by_wg_key(&st, NULL) != -1) {
        printf("  FAIL NULL args accepted\n"); failures++;
    } else printf("  OK   NULL args -> -1\n");
}

/* ------------------------------------------------------------------ */
/* 2. get_peer_endpoint: direct path semantics (ADR-0018)              */
/* ------------------------------------------------------------------ */

static void test_get_peer_endpoint(void)
{
    tsnode_disco_state_t st;
    const tsnode_wg_crypto_t *cr = tsnode_wg_crypto_host();
    uint8_t my_wg_pub[32];
    uint8_t peer_priv[32], peer_pub[32];

    for (int i = 0; i < 32; i++) my_wg_pub[i] = (uint8_t)(0x20 + i);
    make_keypair(peer_priv, peer_pub, 3);

    printf("get_peer_endpoint (direct path, ADR-0018):\n");

    if (tsnode_disco_init(&st, my_wg_pub, cr) != TSNODE_OK) {
        printf("  FAIL init\n"); failures++; return;
    }

    /* endpoints[0] = public (hairpin-NAT dead end), [1] = LAN */
    uint32_t eps[2] = { 0xcb007105u, 0xc0a80132u }; /* 203.0.113.5, 192.168.1.50 */
    uint16_t ports[2] = { 41641, 41641 };
    if (tsnode_disco_add_peer(&st, peer_pub, peer_pub, eps, ports, 2)
        != TSNODE_OK) {
        printf("  FAIL add peer\n"); failures++; return;
    }

    uint32_t ip = 0; uint16_t port = 0;

    /* No direct path yet -> fail closed */
    if (tsnode_disco_get_peer_endpoint(&st, 0, &ip, &port)) {
        printf("  FAIL endpoint returned before direct path\n"); failures++;
    } else printf("  OK   no direct path -> false\n");

    /* Fake a confirmed direct route on the peer's LAN IP */
    st.peers[0].direct_path_ok = true;
    st.peers[0].direct_ip = 0xc0a80132u;
    st.peers[0].direct_port = 41641;

    if (!tsnode_disco_get_peer_endpoint(&st, 0, &ip, &port)) {
        printf("  FAIL direct path not returned\n"); failures++;
    } else if (ip != 0xc0a80132u || port != 41641) {
        printf("  FAIL got %u.%u.%u.%u:%u, want 192.168.1.50:41641\n",
               (ip >> 24) & 0xff, (ip >> 16) & 0xff,
               (ip >> 8) & 0xff, ip & 0xff, port);
        failures++;
    } else printf("  OK   direct path preferred over endpoints[0]\n");

    /* Defensive fallback: direct_path_ok set but no route recorded */
    st.peers[0].direct_ip = 0;
    st.peers[0].direct_port = 0;
    if (!tsnode_disco_get_peer_endpoint(&st, 0, &ip, &port)) {
        printf("  FAIL fallback not returned\n"); failures++;
    } else if (ip != 0xcb007105u || port != 41641) {
        printf("  FAIL fallback got wrong endpoint\n"); failures++;
    } else printf("  OK   fallback to endpoints[0]\n");

    /* Bounds / NULL args */
    if (tsnode_disco_get_peer_endpoint(&st, 5, &ip, &port) ||
        tsnode_disco_get_peer_endpoint(&st, -1, &ip, &port)) {
        printf("  FAIL out-of-range idx accepted\n"); failures++;
    } else printf("  OK   out-of-range idx -> false\n");

    if (tsnode_disco_get_peer_endpoint(NULL, 0, &ip, &port) ||
        tsnode_disco_get_peer_endpoint(&st, 0, NULL, &port) ||
        tsnode_disco_get_peer_endpoint(&st, 0, &ip, NULL)) {
        printf("  FAIL NULL args accepted\n"); failures++;
    } else printf("  OK   NULL args -> false\n");
}

/* ------------------------------------------------------------------ */
/* 3. Full PING -> PONG round-trip; direct_ip/port from PONG source    */
/* ------------------------------------------------------------------ */

static void test_ping_pong_roundtrip(void)
{
    tsnode_disco_state_t st;
    const tsnode_wg_crypto_t *cr = tsnode_wg_crypto_host();
    uint8_t my_wg_pub[32];
    uint8_t peer_priv[32], peer_pub[32];

    for (int i = 0; i < 32; i++) my_wg_pub[i] = (uint8_t)(0x30 + i);
    make_keypair(peer_priv, peer_pub, 4);

    printf("PING -> PONG round-trip + direct path capture:\n");

    if (tsnode_disco_init(&st, my_wg_pub, cr) != TSNODE_OK) {
        printf("  FAIL init\n"); failures++; return;
    }

    uint32_t eps[2] = { 0xcb007105u, 0xc0a80132u }; /* public, LAN */
    uint16_t ports[2] = { 41641, 41641 };
    if (tsnode_disco_add_peer(&st, peer_pub, peer_pub, eps, ports, 2)
        != TSNODE_OK) {
        printf("  FAIL add peer\n"); failures++; return;
    }

    /* 3a. We send a PING to all endpoints; capture the last datagram. */
    g_tx_count = 0;
    uint8_t ping_pkt[TSNODE_DISCO_MAX_PKT];
    size_t ping_len;
    const uint8_t *sender_pub, *nonce, *box;
    size_t box_len;

    if (tsnode_disco_send_ping(&st, 0, (tsnode_port_udp_socket_t *)&g_dummy_sock, cr) != TSNODE_OK) {
        printf("  FAIL send_ping\n"); failures++; return;
    }
    /* sendto was called once per endpoint (2 here). */
    if (g_tx_count != 2) {
        printf("  FAIL sendto count %d (want 2)\n", g_tx_count); failures++;
    } else printf("  OK   PING sent to all endpoints (%d sendto)\n", g_tx_count);

    ping_len = g_tx_len;
    if (ping_len > sizeof(ping_pkt)) { printf("  FAIL ping too big\n"); failures++; return; }
    memcpy(ping_pkt, g_tx_buf, ping_len);

    if (ping_len < 6 + 32 + 24 + TSNODE_DISCO_MACBYTES + TSNODE_DISCO_PING_MIN_LEN) {
        printf("  FAIL PING packet too short (%zu)\n", ping_len); failures++; return;
    }
    sender_pub = ping_pkt + 6;
    nonce = ping_pkt + 6 + 32;
    box = ping_pkt + 6 + 32 + 24;
    box_len = ping_len - 6 - 32 - 24;

    /* The sender pub inside the PING must be our own disco key. */
    if (ct_cmp(sender_pub, tsnode_disco_get_pubkey(&st), 32)) {
        printf("  FAIL PING sender pub != our disco pub\n"); failures++;
    } else printf("  OK   PING sender pub is ours\n");

    /* 3b. Peer (receiver = peer_priv) decrypts the PING. */
    uint8_t ping_plain[TSNODE_DISCO_MAX_PKT];
    size_t ping_plain_len = 0;
    if (tsnode_nacl_box_open(ping_plain, &ping_plain_len, box, box_len,
                             nonce, peer_priv, sender_pub, tweet_dh)
        != TSNODE_OK) {
        printf("  FAIL peer cannot decrypt PING\n"); failures++; return;
    }
    if (ping_plain_len != TSNODE_DISCO_PING_MIN_LEN ||
        ping_plain[0] != TSNODE_DISCO_PING || ping_plain[1] != 0) {
        printf("  FAIL PING plaintext mismatch (len=%zu type=%u)\n",
               ping_plain_len, ping_plain[0]);
        failures++; return;
    }
    if (ct_cmp(ping_plain + 14, my_wg_pub, 32)) {
        printf("  FAIL PING nodekey != our WG pubkey\n"); failures++;
    } else printf("  OK   PING plaintext ok (type, nodekey)\n");

    const uint8_t *txid = ping_plain + 2;
    if (ct_cmp(txid, st.peers[0].pending_txid, TSNODE_DISCO_TXID_LEN)) {
        printf("  FAIL pending_txid not echoed\n"); failures++;
    } else printf("  OK   txid round-trips through pending_txid\n");

    /* 3c. Peer builds a PONG and sends it FROM its LAN endpoint. */
    uint8_t pong_plain[TSNODE_DISCO_PONG_LEN];
    pong_plain[0] = TSNODE_DISCO_PONG;
    pong_plain[1] = 0;
    memcpy(pong_plain + 2, txid, TSNODE_DISCO_TXID_LEN);
    ip16_from_ipv4(pong_plain + 14, 0xc0a80132u); /* peer LAN */
    pong_plain[30] = (uint8_t)(41641 >> 8);
    pong_plain[31] = (uint8_t)(41641 & 0xff);

    uint8_t pong_nonce[24];
    memset(pong_nonce, 0x5a, sizeof(pong_nonce));
    uint8_t pong_box[TSNODE_DISCO_MAX_PKT];
    size_t pong_box_len = 0;
    if (tsnode_nacl_box_seal(pong_box, &pong_box_len, pong_plain,
                             TSNODE_DISCO_PONG_LEN, pong_nonce,
                             peer_priv, sender_pub, tweet_dh) != TSNODE_OK) {
        printf("  FAIL peer cannot seal PONG\n"); failures++; return;
    }

    uint8_t pong_pkt[TSNODE_DISCO_MAX_PKT];
    size_t pong_len = wrap_disco_pkt(pong_pkt, peer_pub, pong_nonce,
                                     pong_box, pong_box_len);

    /* 3d. Our side receives the PONG from peer LAN 192.168.1.50:41641. */
    g_tx_count = 0;
    tsnode_err_t err = tsnode_disco_handle_packet(
        &st, pong_pkt, pong_len, 0xc0a80132u, 41641, (tsnode_port_udp_socket_t *)&g_dummy_sock, cr);
    if (err != TSNODE_OK) {
        printf("  FAIL handle PONG: %d\n", err); failures++; return;
    }

    if (!st.peers[0].direct_path_ok) {
        printf("  FAIL direct_path_ok not set\n"); failures++;
    } else printf("  OK   direct_path_ok set\n");

    if (st.peers[0].direct_ip != 0xc0a80132u ||
        st.peers[0].direct_port != 41641) {
        printf("  FAIL direct path %u.%u.%u.%u:%u, want 192.168.1.50:41641\n",
               (st.peers[0].direct_ip >> 24) & 0xff,
               (st.peers[0].direct_ip >> 16) & 0xff,
               (st.peers[0].direct_ip >> 8) & 0xff,
               st.peers[0].direct_ip & 0xff,
               st.peers[0].direct_port);
        failures++;
    } else printf("  OK   direct path captured from PONG source\n");

    if (st.peers[0].retry_count != 0) {
        printf("  FAIL retry_count not reset (%d)\n", st.peers[0].retry_count);
        failures++;
    } else printf("  OK   retry_count reset\n");

    /* 3e. get_peer_endpoint now returns the direct (LAN) route. */
    uint32_t ep_ip = 0; uint16_t ep_port = 0;
    if (!tsnode_disco_get_peer_endpoint(&st, 0, &ep_ip, &ep_port)) {
        printf("  FAIL endpoint not returned after PONG\n"); failures++;
    } else if (ep_ip != 0xc0a80132u || ep_port != 41641) {
        printf("  FAIL endpoint = %u.%u.%u.%u:%u, want LAN\n",
               (ep_ip >> 24) & 0xff, (ep_ip >> 16) & 0xff,
               (ep_ip >> 8) & 0xff, ep_ip & 0xff, ep_port);
        failures++;
    } else printf("  OK   WG handshake endpoint = direct path (ADR-0018)\n");
}

/* ------------------------------------------------------------------ */
/* 4. Incoming PING answered with PONG to the sender address           */
/* ------------------------------------------------------------------ */

static void test_incoming_ping_responds_pong(void)
{
    tsnode_disco_state_t st;
    const tsnode_wg_crypto_t *cr = tsnode_wg_crypto_host();
    uint8_t my_wg_pub[32];
    uint8_t peer_priv[32], peer_pub[32];

    for (int i = 0; i < 32; i++) my_wg_pub[i] = (uint8_t)(0x40 + i);
    make_keypair(peer_priv, peer_pub, 5);

    printf("incoming PING -> PONG response:\n");

    if (tsnode_disco_init(&st, my_wg_pub, cr) != TSNODE_OK) {
        printf("  FAIL init\n"); failures++; return;
    }

    uint32_t eps[1] = { 0xc0a80132u };
    uint16_t ports[1] = { 41641 };
    tsnode_disco_add_peer(&st, peer_pub, peer_pub, eps, ports, 1);

    /* Peer (peer_priv) sends us a PING. */
    uint8_t ping_plain[TSNODE_DISCO_PING_MIN_LEN];
    ping_plain[0] = TSNODE_DISCO_PING;
    ping_plain[1] = 0;
    for (unsigned int i = 0; i < TSNODE_DISCO_TXID_LEN; i++)
        ping_plain[2 + i] = (uint8_t)(0xc0 + i);
    memset(ping_plain + 14, 0x6d, 32);            /* peer's nodekey */

    uint8_t nonce[24];
    memset(nonce, 0x2c, sizeof(nonce));
    uint8_t box[TSNODE_DISCO_MAX_PKT];
    size_t box_len = 0;
    if (tsnode_nacl_box_seal(box, &box_len, ping_plain, sizeof(ping_plain),
                             nonce, peer_priv, st.my_kp.pub, tweet_dh)
        != TSNODE_OK) {
        printf("  FAIL peer seal\n"); failures++; return;
    }

    uint8_t ping_pkt[TSNODE_DISCO_MAX_PKT];
    size_t ping_len = wrap_disco_pkt(ping_pkt, peer_pub, nonce, box, box_len);

    /* Our side handles it; must answer PONG to the source. */
    g_tx_count = 0;
    tsnode_err_t err = tsnode_disco_handle_packet(
        &st, ping_pkt, ping_len, 0xc0a80132u, 41641, (tsnode_port_udp_socket_t *)&g_dummy_sock, cr);
    if (err != TSNODE_OK) {
        printf("  FAIL handle PING: %d\n", err); failures++; return;
    }
    if (g_tx_count != 1 || g_tx_ip != 0xc0a80132u || g_tx_port != 41641) {
        printf("  FAIL PONG not sent to sender (cnt=%d ip=%u.%u.%u.%u:%u)\n",
               g_tx_count,
               (g_tx_ip >> 24) & 0xff, (g_tx_ip >> 16) & 0xff,
               (g_tx_ip >> 8) & 0xff, g_tx_ip & 0xff, g_tx_port);
        failures++;
    } else printf("  OK   PONG sent to sender address\n");

    /* Verify the PONG: decrypt as the peer would. */
    const uint8_t *ps = g_tx_buf + 6;
    const uint8_t *pn = g_tx_buf + 6 + 32;
    const uint8_t *pb = g_tx_buf + 6 + 32 + 24;
    size_t pb_len = g_tx_len - 6 - 32 - 24;

    if (ct_cmp(ps, st.my_kp.pub, 32)) {
        printf("  FAIL PONG sender != our pub\n"); failures++;
        return;
    }
    uint8_t pong_plain[TSNODE_DISCO_MAX_PKT];
    size_t pong_plain_len = 0;
    if (tsnode_nacl_box_open(pong_plain, &pong_plain_len, pb, pb_len,
                             pn, peer_priv, ps, tweet_dh) != TSNODE_OK) {
        printf("  FAIL peer cannot decrypt PONG\n"); failures++; return;
    }
    if (pong_plain_len != TSNODE_DISCO_PONG_LEN ||
        pong_plain[0] != TSNODE_DISCO_PONG) {
        printf("  FAIL PONG plaintext wrong (len=%zu type=%u)\n",
               pong_plain_len, pong_plain[0]);
        failures++; return;
    }
    if (ct_cmp(pong_plain + 2, ping_plain + 2, TSNODE_DISCO_TXID_LEN)) {
        printf("  FAIL PONG txid mismatch\n"); failures++;
    } else printf("  OK   PONG plaintext (type + echoed txid)\n");
}

/* ------------------------------------------------------------------ */
/* 5. PONG with unknown txid is fail-closed                            */
/* ------------------------------------------------------------------ */

static void test_pong_wrong_txid_fail_closed(void)
{
    tsnode_disco_state_t st;
    const tsnode_wg_crypto_t *cr = tsnode_wg_crypto_host();
    uint8_t my_wg_pub[32];
    uint8_t peer_priv[32], peer_pub[32];

    for (int i = 0; i < 32; i++) my_wg_pub[i] = (uint8_t)(0x50 + i);
    make_keypair(peer_priv, peer_pub, 6);

    printf("PONG wrong txid is fail-closed:\n");

    if (tsnode_disco_init(&st, my_wg_pub, cr) != TSNODE_OK) {
        printf("  FAIL init\n"); failures++; return;
    }

    uint32_t eps[1] = { 0xc0a80132u };
    uint16_t ports[1] = { 41641 };
    tsnode_disco_add_peer(&st, peer_pub, peer_pub, eps, ports, 1);

    /* Send a real PING so pending_txid is meaningful... */
    tsnode_disco_send_ping(&st, 0, (tsnode_port_udp_socket_t *)&g_dummy_sock, cr);

    /* ...but the peer answers with a DIFFERENT txid. */
    uint8_t pong_plain[TSNODE_DISCO_PONG_LEN];
    pong_plain[0] = TSNODE_DISCO_PONG;
    pong_plain[1] = 0;
    memset(pong_plain + 2, 0xaa, TSNODE_DISCO_TXID_LEN);
    memset(pong_plain + 14, 0, 16);
    pong_plain[30] = 0;
    pong_plain[31] = 0;

    uint8_t nonce[24];
    memset(nonce, 0x1f, sizeof(nonce));
    uint8_t box[TSNODE_DISCO_MAX_PKT];
    size_t box_len = 0;
    if (tsnode_nacl_box_seal(box, &box_len, pong_plain, sizeof(pong_plain),
                             nonce, peer_priv, st.my_kp.pub, tweet_dh)
        != TSNODE_OK) {
        printf("  FAIL seal\n"); failures++; return;
    }

    uint8_t pong_pkt[TSNODE_DISCO_MAX_PKT];
    size_t pong_len = wrap_disco_pkt(pong_pkt, peer_pub, nonce, box, box_len);

    tsnode_err_t err = tsnode_disco_handle_packet(
        &st, pong_pkt, pong_len, 0xc0a80132u, 41641, (tsnode_port_udp_socket_t *)&g_dummy_sock, cr);
    if (err != TSNODE_OK) {
        printf("  FAIL handle_packet returned %d\n", err); failures++; return;
    }

    if (st.peers[0].direct_path_ok || st.peers[0].direct_ip != 0 ||
        st.peers[0].direct_port != 0) {
        printf("  FAIL stale/forged PONG accepted\n"); failures++;
    } else printf("  OK   forged PONG rejected (direct path unset)\n");
}

int main(void)
{
    if (getenv("TSNODE_TEST_LOG")) {
        tsnode_port_set_log(test_log);
    }

    test_find_peer_by_wg_key();
    test_get_peer_endpoint();
    test_ping_pong_roundtrip();
    test_incoming_ping_responds_pong();
    test_pong_wrong_txid_fail_closed();

    if (failures) {
        printf("\nDISCO TESTS: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("\nDISCO TESTS: ALL PASS\n");
    return 0;
}