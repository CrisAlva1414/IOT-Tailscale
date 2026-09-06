/*
 * tsnode-wg — WireGuard data plane core implementation.
 *
 * Protocol flow mirrors wireguard-go device/noise-protocol.go @ master
 * (fetched 2026-08-24), reimplemented in C per AGENTS.md §6 (attribution
 * here; no code copied). Message layouts and every constant verified
 * against that source plus device/noise-types.go, cookie.go and
 * receive.go. Deviations are documented inline and in the header.
 *
 * Security posture (AGENTS.md §2.2): all inbound bytes are hostile;
 * every length is validated before use; MACs compared constant-time;
 * authentication happens BEFORE any state mutation (replay window,
 * timestamps); failures zeroize staged secrets.
 */

#include "wg.h"

#include <string.h>

#include "../crypto/blake2s.h"
#include "../crypto/hmac_blake2s.h"

/* Port layer logging (not available in host tests) */
#if __has_include("tsnode_port.h")
#include "tsnode_port.h"
#define TAG "wg"
#else
/* Host-test stub: variadic macros that accept zero or more args */
#define TSNODE_LOGE(tag, ...) ((void)0)
#define TSNODE_LOGI(tag, ...) ((void)0)
#define TSNODE_LOGW(tag, ...) ((void)0)
#endif

/* ---- Compile-time layout assertions (fail the build if constants
 * drift from the wire format — cheap insurance per AGENTS.md §5.6) ---- */

#define WG_STATIC_ASSERT(name, cond) \
    typedef char name[(cond) ? 1 : -1]

WG_STATIC_ASSERT(wg_initiation_len, TSNODE_WG_INITIATION_LEN == 148);
WG_STATIC_ASSERT(wg_response_len, TSNODE_WG_RESPONSE_LEN == 92);

/* Verified against wireguard-go noise-types.go message layouts:
 * initiation: type(4) sender(4) eph(32) static(48) ts(28) mac1(16)
 * mac2(16); response: type(4) sender(4) receiver(4) eph(32) empty(16)
 * mac1(16) mac2(16). */
#define WG_OFF_TYPE 0u
#define WG_OFF_SENDER 4u
#define WG_OFF_RECEIVER 8u
#define WG_INIT_OFF_EPHEMERAL 8u
#define WG_INIT_OFF_STATIC 40u     /* encrypted: pubkey + tag */
#define WG_INIT_OFF_TIMESTAMP 88u  /* encrypted: TAI64N + tag */
#define WG_RESP_OFF_EPHEMERAL 12u
#define WG_RESP_OFF_EMPTY 44u      /* encrypted empty: tag only */
#define WG_TRANSPORT_OFF_COUNTER 8u
#define WG_TRANSPORT_OFF_DATA 16u

/* WireGuard labels and constants (cookie.go / noise-protocol.go). */
static const char wg_mac1_label[] = "mac1----";
static const char wg_construction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char wg_identifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";

/* ---- Small helpers ---- */

/* Constant-time equality; never short-circuits on content. */
static bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_u64le(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    }
}

static uint64_t get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8u * i);
    }
    return v;
}

/* mixHash(h, data): h = HASH(h || data). */
static void mix_hash(uint8_t h[TSNODE_WG_KEY_LEN], const uint8_t *data,
                     size_t len)
{
    tsnode_blake2s_ctx ctx;
    tsnode_blake2s_init(&ctx, TSNODE_BLAKE2S_OUTBYTES);
    tsnode_blake2s_update(&ctx, h, TSNODE_WG_KEY_LEN);
    tsnode_blake2s_update(&ctx, data, len);
    tsnode_blake2s_final(&ctx, h, TSNODE_WG_KEY_LEN);
}

/*
 * mixKey variants over the running chain key. Both take the chain key
 * in-place via an internal temp so callers never deal with input/output
 * aliasing (mirrors wireguard-go handshake.mixKey semantics).
 */
static void mix_key1(uint8_t ck[TSNODE_WG_KEY_LEN], const uint8_t *data,
                     size_t len)
{
    uint8_t next[TSNODE_WG_KEY_LEN];
    tsnode_hkdf_blake2s_1(next, ck, data, len);
    memcpy(ck, next, TSNODE_WG_KEY_LEN);
    memset(next, 0, sizeof(next));
}

static void mix_key2(uint8_t ck[TSNODE_WG_KEY_LEN], uint8_t key[TSNODE_WG_KEY_LEN],
                     const uint8_t *data, size_t len)
{
    uint8_t next[TSNODE_WG_KEY_LEN];
    tsnode_hkdf_blake2s_2(next, key, ck, data, len);
    memcpy(ck, next, TSNODE_WG_KEY_LEN);
    memset(next, 0, sizeof(next));
}

/* Zero nonce used by every handshake AEAD op (single-use keys make it
 * safe — same construction as wireguard-go WithZeroNonce). */
static void zero_nonce(uint8_t nonce[12])
{
    memset(nonce, 0, 12);
}

/*
 * Initial handshake state (noise-protocol.go InitialChainKey /
 * InitialHash): ck = HASH(construction), h = mixHash(ck, identifier).
 */
static void initial_state(uint8_t ck[TSNODE_WG_KEY_LEN],
                          uint8_t h[TSNODE_WG_KEY_LEN])
{
    tsnode_blake2s(ck, TSNODE_WG_KEY_LEN, (const uint8_t *)wg_construction,
                   sizeof(wg_construction) - 1u);
    memcpy(h, ck, TSNODE_WG_KEY_LEN);
    mix_hash(h, (const uint8_t *)wg_identifier, sizeof(wg_identifier) - 1u);
}

/* MAC1 over everything before the trailing mac1||mac2 block
 * (cookie.go CheckMAC1: keyed BLAKE2s with 16-byte digest). Callers
 * pass compile-time-known message sizes; the guard keeps the helper
 * safe regardless. */
static void compute_mac1(const uint8_t mac1_key[TSNODE_WG_KEY_LEN],
                         const uint8_t *msg, size_t msg_len,
                         uint8_t out_mac[TSNODE_WG_MAC_LEN])
{
    if (msg_len < 2u * TSNODE_WG_MAC_LEN) {
        memset(out_mac, 0, TSNODE_WG_MAC_LEN);
        return;
    }
    (void)tsnode_blake2s_keyed(out_mac, TSNODE_WG_MAC_LEN, mac1_key,
                               TSNODE_BLAKE2S_KEYBYTES, msg,
                               msg_len - 2u * TSNODE_WG_MAC_LEN);
}

static void add_macs(const tsnode_wg_peer_t *peer, uint8_t *msg,
                     size_t msg_len)
{
    compute_mac1(peer->mac1_key, msg, msg_len,
                 msg + msg_len - 2u * TSNODE_WG_MAC_LEN);
    /* mac2 stays zeros: v1 neither answers challenges nor consumes
     * replies (documented limitation in wg.h). */
    memset(msg + msg_len - TSNODE_WG_MAC_LEN, 0, TSNODE_WG_MAC_LEN);
}

static bool verify_mac1(const uint8_t mac1_key[TSNODE_WG_KEY_LEN],
                        const uint8_t *msg, size_t msg_len)
{
    uint8_t expected[TSNODE_WG_MAC_LEN];
    const uint8_t *got = msg + msg_len - 2u * TSNODE_WG_MAC_LEN;

    compute_mac1(mac1_key, msg, msg_len, expected);
    bool ok = ct_equal(expected, got, TSNODE_WG_MAC_LEN);
    memset(expected, 0, sizeof(expected));
    return ok;
}

/* Compute mac1_key = HASH("mac1----" || static_pub) for a given public
 * key. Used by responder to verify MAC1, and by initiator to create it. */
static void compute_mac1_key(uint8_t out[TSNODE_WG_KEY_LEN],
                             const uint8_t static_pub[TSNODE_WG_KEY_LEN])
{
    uint8_t labeled[TSNODE_WG_MAC_INPUT_LABEL_LEN + TSNODE_WG_KEY_LEN];
    memcpy(labeled, wg_mac1_label, sizeof(wg_mac1_label) - 1u);
    memcpy(labeled + sizeof(wg_mac1_label) - 1u, static_pub,
           TSNODE_WG_KEY_LEN);
    tsnode_blake2s(out, TSNODE_WG_KEY_LEN, labeled, sizeof(labeled));
}

/* Strictly-greater lexicographic compare (TAI64N is big-endian and the
 * requirement is timestamp > last seen — noise-protocol.go). */
static bool timestamp_greater(const uint8_t a[TSNODE_WG_TIMESTAMP_LEN],
                              const uint8_t b[TSNODE_WG_TIMESTAMP_LEN])
{
    return memcmp(a, b, TSNODE_WG_TIMESTAMP_LEN) > 0;
}

static void clamp_key(uint8_t key[TSNODE_WG_KEY_LEN])
{
    key[0] &= 248u;
    key[31] = (uint8_t)((key[31] & 127u) | 64u);
}

/* ---- Session helpers ---- */

static uint32_t alloc_index(tsnode_wg_device_t *dev)
{
    for (unsigned attempt = 0; attempt < 4096u; attempt++) {
        dev->next_index++;
        if (dev->next_index == 0) {
            continue; /* keep indices nonzero */
        }
        bool taken = false;
        for (unsigned i = 0; i < TSNODE_WG_MAX_PEERS; i++) {
            const tsnode_wg_peer_t *p = &dev->peers[i];
            if (!p->used) {
                continue;
            }
            if ((p->session.valid && p->session.local_index == dev->next_index) ||
                (p->hs_state != TSNODE_WG_HS_IDLE &&
                 p->hs_local_index == dev->next_index)) {
                taken = true;
                break;
            }
        }
        if (!taken) {
            return dev->next_index;
        }
    }
    return 0; /* caller fails closed */
}

/* BeginSymmetricSession (noise-protocol.go): KDF2(ck, nil); initiator
 * sends with t0 and receives with t1, responder the reverse. */
static void session_install(tsnode_wg_peer_t *peer,
                            uint32_t local_index, uint32_t remote_index,
                            bool we_are_initiator, uint64_t now_ms)
{
    tsnode_wg_session_t *s = &peer->session;
    uint8_t t0[TSNODE_WG_KEY_LEN], t1[TSNODE_WG_KEY_LEN];

    tsnode_hkdf_blake2s_2(t0, t1, peer->hs_chain_key, NULL, 0);

    s->valid = true;
    s->local_index = local_index;
    s->remote_index = remote_index;
    if (we_are_initiator) {
        memcpy(s->send_key, t0, TSNODE_WG_KEY_LEN);
        memcpy(s->recv_key, t1, TSNODE_WG_KEY_LEN);
    } else {
        memcpy(s->send_key, t1, TSNODE_WG_KEY_LEN);
        memcpy(s->recv_key, t0, TSNODE_WG_KEY_LEN);
    }
    s->send_counter = 0;
    s->established_at_ms = now_ms;
    tsnode_wg_replay_init(&s->replay);

    memset(t0, 0, sizeof(t0));
    memset(t1, 0, sizeof(t1));
}

static void hs_clear_secrets(tsnode_wg_peer_t *peer)
{
    memset(peer->hs_hash, 0, sizeof(peer->hs_hash));
    memset(peer->hs_chain_key, 0, sizeof(peer->hs_chain_key));
    memset(peer->hs_local_eph_priv, 0, sizeof(peer->hs_local_eph_priv));
    memset(peer->hs_remote_eph_pub, 0, sizeof(peer->hs_remote_eph_pub));
    memset(peer->hs_presumed_key, 0, sizeof(peer->hs_presumed_key));
    peer->hs_state = TSNODE_WG_HS_IDLE;
    peer->hs_local_index = 0;
    peer->hs_remote_index = 0;
}

/* ---- Lifecycle ---- */

tsnode_err_t tsnode_wg_device_init(tsnode_wg_device_t *dev,
                                   uint8_t private_key[TSNODE_WG_KEY_LEN],
                                   const tsnode_wg_crypto_t *crypto)
{
    if (dev == NULL || private_key == NULL || crypto == NULL ||
        crypto->dh == NULL || crypto->pubkey == NULL ||
        crypto->aead_seal == NULL || crypto->aead_open == NULL ||
        crypto->random == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    memset(dev, 0, sizeof(*dev));
    clamp_key(private_key);
    memcpy(dev->private_key, private_key, TSNODE_WG_KEY_LEN);
    tsnode_err_t err = crypto->pubkey(dev->public_key, dev->private_key);
    if (err != TSNODE_OK) {
        memset(dev->private_key, 0, sizeof(dev->private_key));
        return err;
    }
    dev->crypto = crypto;
    dev->next_index = 0x40000000u; /* arbitrary nonzero start */
    dev->initialized = true;
    return TSNODE_OK;
}

int tsnode_wg_peer_add(tsnode_wg_device_t *dev,
                       const tsnode_wg_peer_cfg_t *cfg)
{
    if (dev == NULL || !dev->initialized || cfg == NULL) {
        return -1;
    }

    /* Reject all-zero public keys (never valid remote identities). */
    static const uint8_t zeros[TSNODE_WG_KEY_LEN] = {0};
    if (ct_equal(cfg->public_key, zeros, TSNODE_WG_KEY_LEN)) {
        return -1;
    }

    int slot = -1;
    for (unsigned i = 0; i < TSNODE_WG_MAX_PEERS; i++) {
        const tsnode_wg_peer_t *p = &dev->peers[i];
        if (!p->used) {
            if (slot < 0) {
                slot = (int)i;
            }
            continue;
        }
        if (ct_equal(p->cfg.public_key, cfg->public_key, TSNODE_WG_KEY_LEN)) {
            return -1; /* duplicate peer public key */
        }
    }
    if (slot < 0) {
        return -1;
    }

    tsnode_wg_peer_t *p = &dev->peers[slot];
    memset(p, 0, sizeof(*p));
    p->used = true;
    p->cfg = *cfg;

    tsnode_err_t err = dev->crypto->dh(p->ss_static, dev->private_key,
                                       p->cfg.public_key);
    if (err != TSNODE_OK) {
        memset(p, 0, sizeof(*p)); /* wipes ss_static on small-order DH */
        return -1;
    }

    /* cookie.go CookieChecker.Init: unkeyed HASH(label || pubkey). */
    compute_mac1_key(p->mac1_key, p->cfg.public_key);
    static const char cookie_label[] = "cookie--";
    uint8_t labeled[sizeof(cookie_label) - 1u + TSNODE_WG_KEY_LEN];
    memcpy(labeled, cookie_label, sizeof(cookie_label) - 1u);
    memcpy(labeled + sizeof(cookie_label) - 1u, p->cfg.public_key,
           TSNODE_WG_KEY_LEN);
    tsnode_blake2s(p->cookie_key, TSNODE_WG_KEY_LEN, labeled, sizeof(labeled));

    memset(labeled, 0, sizeof(labeled));
    return slot;
}

/* ---- Outbound initiation (CreateMessageInitiation) ---- */

tsnode_err_t tsnode_wg_create_initiation(
    tsnode_wg_device_t *dev, int peer_idx,
    const uint8_t timestamp[TSNODE_WG_TIMESTAMP_LEN],
    uint8_t out[TSNODE_WG_INITIATION_LEN])
{
    if (dev == NULL || !dev->initialized || peer_idx < 0 ||
        peer_idx >= (int)TSNODE_WG_MAX_PEERS || timestamp == NULL ||
        out == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    tsnode_wg_peer_t *peer = &dev->peers[peer_idx];
    if (!peer->used) {
        return TSNODE_ERR_INVALID_ARG;
    }

    const tsnode_wg_crypto_t *cr = dev->crypto;
    uint8_t ck[TSNODE_WG_KEY_LEN], h[TSNODE_WG_KEY_LEN];
    uint8_t k[TSNODE_WG_KEY_LEN], shared[TSNODE_WG_KEY_LEN];
    uint8_t eph_pub[TSNODE_WG_KEY_LEN], nonce[12];
    uint32_t local_index;

    /* Fresh ephemeral; on any failure abort without staging state —
     * an ephemeral must never be reused across attempts. */
    hs_clear_secrets(peer);
    /* Use keygen instead of random()+pubkey() to guarantee the key pair
     * passes mbedTLS validation (RFC 7748 clamping + bit 254 set). */
    if (cr->keygen(peer->hs_local_eph_priv, eph_pub) != TSNODE_OK) {
        TSNODE_LOGE(TAG, "WG init: keygen failed");
        hs_clear_secrets(peer);
        return TSNODE_ERR_CRYPTO;
    }
    if (cr->dh(shared, peer->hs_local_eph_priv, peer->cfg.public_key) !=
        TSNODE_OK) {
        TSNODE_LOGE(TAG, "WG init: DH(eph,remote) failed");
        hs_clear_secrets(peer);
        return TSNODE_ERR_CRYPTO;
    }

    local_index = alloc_index(dev);
    if (local_index == 0) {
        TSNODE_LOGE(TAG, "WG init: alloc_index failed");
        hs_clear_secrets(peer);
        return TSNODE_ERR_INVALID_STATE;
    }
    TSNODE_LOGI(TAG, "WG init: crypto OK, index=%lu", (unsigned long)local_index);

    /* Serialize fixed fields first; crypto below writes ciphertext in
     * place and mixes it into the transcript as it goes. */
    memset(out, 0, TSNODE_WG_INITIATION_LEN);
    put_u32le(out + WG_OFF_TYPE, TSNODE_WG_MSG_TYPE_HANDSHAKE_INITIATION);
    put_u32le(out + WG_OFF_SENDER, local_index);
    memcpy(out + WG_INIT_OFF_EPHEMERAL, eph_pub, TSNODE_WG_KEY_LEN);

    initial_state(ck, h);
    mix_hash(h, peer->cfg.public_key, TSNODE_WG_KEY_LEN);

    /* mixKey(eph_pub); mixHash(eph_pub) */
    mix_key1(ck, out + WG_INIT_OFF_EPHEMERAL, TSNODE_WG_KEY_LEN);
    mix_hash(h, out + WG_INIT_OFF_EPHEMERAL, TSNODE_WG_KEY_LEN);

    /* ee: mixKey(DH(ephemeral_private, remote_static)) */
    mix_key2(ck, k, shared, TSNODE_WG_KEY_LEN);

    /* Encrypt our static public key under zero nonce, AAD = h. */
    zero_nonce(nonce);
    tsnode_err_t err = cr->aead_seal(out + WG_INIT_OFF_STATIC, k, nonce, h,
                                     TSNODE_WG_KEY_LEN, dev->public_key,
                                     TSNODE_WG_KEY_LEN);
    if (err != TSNODE_OK) {
        TSNODE_LOGE(TAG, "WG init: AEAD seal static failed: %d", err);
        hs_clear_secrets(peer);
        return err;
    }
    mix_hash(h, out + WG_INIT_OFF_STATIC,
             TSNODE_WG_KEY_LEN + TSNODE_WG_TAG_LEN);

    /* ss: mixKey(precomputed DH(static_private, remote_static)). */
    mix_key2(ck, k, peer->ss_static, TSNODE_WG_KEY_LEN);

    /* Encrypt the caller-supplied timestamp under zero nonce, AAD = h. */
    zero_nonce(nonce);
    err = cr->aead_seal(out + WG_INIT_OFF_TIMESTAMP, k, nonce, h,
                        TSNODE_WG_KEY_LEN, timestamp,
                        TSNODE_WG_TIMESTAMP_LEN);
    if (err != TSNODE_OK) {
        hs_clear_secrets(peer);
        return err;
    }
    mix_hash(h, out + WG_INIT_OFF_TIMESTAMP,
             TSNODE_WG_TIMESTAMP_LEN + TSNODE_WG_TAG_LEN);

    add_macs(peer, out, TSNODE_WG_INITIATION_LEN);

    /* Stage state for consume_response(). */
    peer->hs_state = TSNODE_WG_HS_INIT_CREATED;
    peer->hs_local_index = local_index;
    peer->hs_remote_index = 0;
    memcpy(peer->hs_hash, h, TSNODE_WG_KEY_LEN);
    memcpy(peer->hs_chain_key, ck, TSNODE_WG_KEY_LEN);

    memset(k, 0, sizeof(k));
    memset(shared, 0, sizeof(shared));
    memset(eph_pub, 0, sizeof(eph_pub));
    return TSNODE_OK;
}

/* ---- Inbound initiation (ConsumeMessageInitiation) ---- */

tsnode_err_t tsnode_wg_consume_initiation(tsnode_wg_device_t *dev,
                                          const uint8_t *pkt, size_t len,
                                          int *peer_idx_out)
{
    if (dev == NULL || !dev->initialized || pkt == NULL ||
        peer_idx_out == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (len != TSNODE_WG_INITIATION_LEN ||
        get_u32le(pkt + WG_OFF_TYPE) !=
            TSNODE_WG_MSG_TYPE_HANDSHAKE_INITIATION) {
        return TSNODE_ERR_INVALID_ARG;
    }

    const tsnode_wg_crypto_t *cr = dev->crypto;
    uint8_t ck[TSNODE_WG_KEY_LEN], h[TSNODE_WG_KEY_LEN];
    uint8_t k[TSNODE_WG_KEY_LEN], shared[TSNODE_WG_KEY_LEN];
    uint8_t remote_static[TSNODE_WG_KEY_LEN];
    uint8_t timestamp[TSNODE_WG_TIMESTAMP_LEN], nonce[12];

    initial_state(ck, h);
    /* Responder mixes its OWN public key first (noise-protocol.go:
     * handshake.mixHash(device.staticIdentity.publicKey)). */
    mix_hash(h, dev->public_key, TSNODE_WG_KEY_LEN);
    mix_hash(h, pkt + WG_INIT_OFF_EPHEMERAL, TSNODE_WG_KEY_LEN);
    mix_key1(ck, pkt + WG_INIT_OFF_EPHEMERAL, TSNODE_WG_KEY_LEN);

    if (cr->dh(shared, dev->private_key, pkt + WG_INIT_OFF_EPHEMERAL) !=
        TSNODE_OK) {
        return TSNODE_ERR_CRYPTO;
    }
    mix_key2(ck, k, shared, TSNODE_WG_KEY_LEN);

    /* Open the claimed remote static key before any peer lookup. */
    zero_nonce(nonce);
    if (cr->aead_open(remote_static, k, nonce, h, TSNODE_WG_KEY_LEN,
                      pkt + WG_INIT_OFF_STATIC,
                      TSNODE_WG_KEY_LEN + TSNODE_WG_TAG_LEN) != TSNODE_OK) {
        memset(k, 0, sizeof(k));
        return TSNODE_ERR_CRYPTO;
    }
    mix_hash(h, pkt + WG_INIT_OFF_STATIC,
             TSNODE_WG_KEY_LEN + TSNODE_WG_TAG_LEN);

    /* Match against configured peers, then verify MAC1. */
    tsnode_wg_peer_t *peer = NULL;
    int peer_idx = -1;
    for (unsigned i = 0; i < TSNODE_WG_MAX_PEERS; i++) {
        tsnode_wg_peer_t *p = &dev->peers[i];
        if (p->used &&
            ct_equal(p->cfg.public_key, remote_static, TSNODE_WG_KEY_LEN)) {
            peer_idx = (int)i;
            peer = p;
            break;
        }
    }
    if (peer == NULL) {
        memset(k, 0, sizeof(k));
        memset(remote_static, 0, sizeof(remote_static));
        return TSNODE_ERR_CRYPTO;
    }
    {
        uint8_t own_mac1[TSNODE_WG_KEY_LEN];
        compute_mac1_key(own_mac1, dev->public_key);
        if (!verify_mac1(own_mac1, pkt, TSNODE_WG_INITIATION_LEN)) {
            memset(k, 0, sizeof(k));
            memset(remote_static, 0, sizeof(remote_static));
            return TSNODE_ERR_CRYPTO;
        }
    }

    /* ss step uses the precomputed static-static secret. */
    mix_key2(ck, k, peer->ss_static, TSNODE_WG_KEY_LEN);

    zero_nonce(nonce);
    if (cr->aead_open(timestamp, k, nonce, h, TSNODE_WG_KEY_LEN,
                      pkt + WG_INIT_OFF_TIMESTAMP,
                      TSNODE_WG_TIMESTAMP_LEN + TSNODE_WG_TAG_LEN) !=
        TSNODE_OK) {
        memset(k, 0, sizeof(k));
        memset(remote_static, 0, sizeof(remote_static));
        return TSNODE_ERR_CRYPTO;
    }
    mix_hash(h, pkt + WG_INIT_OFF_TIMESTAMP,
             TSNODE_WG_TIMESTAMP_LEN + TSNODE_WG_TAG_LEN);

    /* Anti-replay: strictly newer than anything seen before. Store the
     * accepted value immediately so a crash cannot re-enable replays
     * of older initiations. */
    bool ts_ok =
        !peer->have_timestamp || timestamp_greater(timestamp,
                                                   peer->last_timestamp);
    if (ts_ok) {
        memcpy(peer->last_timestamp, timestamp, TSNODE_WG_TIMESTAMP_LEN);
        peer->have_timestamp = true;
    }
    memset(timestamp, 0, sizeof(timestamp));
    if (!ts_ok) {
        memset(k, 0, sizeof(k));
        memset(remote_static, 0, sizeof(remote_static));
        return TSNODE_ERR_CRYPTO;
    }

    /* Stage responder state; index allocation happens in
     * create_response() like wireguard-go. */
    peer->hs_state = TSNODE_WG_HS_INIT_CONSUMED;
    peer->hs_local_index = 0;
    peer->hs_remote_index = get_u32le(pkt + WG_OFF_SENDER);
    memcpy(peer->hs_hash, h, TSNODE_WG_KEY_LEN);
    memcpy(peer->hs_chain_key, ck, TSNODE_WG_KEY_LEN);
    memcpy(peer->hs_remote_eph_pub, pkt + WG_INIT_OFF_EPHEMERAL,
           TSNODE_WG_KEY_LEN);
    *peer_idx_out = peer_idx;

    memset(k, 0, sizeof(k));
    memset(shared, 0, sizeof(shared));
    memset(remote_static, 0, sizeof(remote_static));
    return TSNODE_OK;
}

/* ---- Outbound response (CreateMessageResponse) ---- */

tsnode_err_t tsnode_wg_create_response(tsnode_wg_device_t *dev, int peer_idx,
                                       uint64_t now_ms,
                                       uint8_t out[TSNODE_WG_RESPONSE_LEN])
{
    if (dev == NULL || !dev->initialized || peer_idx < 0 ||
        peer_idx >= (int)TSNODE_WG_MAX_PEERS || out == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    tsnode_wg_peer_t *peer = &dev->peers[peer_idx];
    if (!peer->used || peer->hs_state != TSNODE_WG_HS_INIT_CONSUMED) {
        return TSNODE_ERR_INVALID_STATE;
    }

    const tsnode_wg_crypto_t *cr = dev->crypto;
    uint8_t ck[TSNODE_WG_KEY_LEN], h[TSNODE_WG_KEY_LEN];
    uint8_t k[TSNODE_WG_KEY_LEN], tau[TSNODE_WG_KEY_LEN];
    uint8_t ee[TSNODE_WG_KEY_LEN], se[TSNODE_WG_KEY_LEN];
    uint8_t eph_priv[TSNODE_WG_KEY_LEN], eph_pub[TSNODE_WG_KEY_LEN];
    uint8_t nonce[12];
    uint32_t local_index;

    /* Ephemeral via keygen (no random()+pubkey()): mbedTLS rechaza escalares
     * de 256 bits (bit 255 puesto) con BAD_INPUT_DATA — una clave aleatoria
     * cruda lo tiene con p=1/2, así que create_response fallaba de forma
     * intermitente al responder handshakes entrantes (observado en hardware:
     * "ecp_mul pubkey failed: -0x4c80" en RX init del notebook). keygen
     * genera escalar clampeado RFC 7748 (bit 255 en 0, bit 254 en 1) de la
     * misma forma que create_initiation, que sí pudo establecer sesiones. */
    if (cr->keygen(eph_priv, eph_pub) != TSNODE_OK ||
        cr->dh(ee, eph_priv, peer->hs_remote_eph_pub) != TSNODE_OK ||
        cr->dh(se, eph_priv, peer->cfg.public_key) != TSNODE_OK) {
        hs_clear_secrets(peer);
        return TSNODE_ERR_CRYPTO;
    }

    local_index = alloc_index(dev);
    if (local_index == 0) {
        hs_clear_secrets(peer);
        return TSNODE_ERR_INVALID_STATE;
    }

    memset(out, 0, TSNODE_WG_RESPONSE_LEN);
    put_u32le(out + WG_OFF_TYPE, TSNODE_WG_MSG_TYPE_HANDSHAKE_RESPONSE);
    put_u32le(out + WG_OFF_SENDER, local_index);
    put_u32le(out + WG_OFF_RECEIVER, peer->hs_remote_index);
    memcpy(out + WG_RESP_OFF_EPHEMERAL, eph_pub, TSNODE_WG_KEY_LEN);

    /* Continue from the staged initiator-transcript state. */
    memcpy(ck, peer->hs_chain_key, TSNODE_WG_KEY_LEN);
    memcpy(h, peer->hs_hash, TSNODE_WG_KEY_LEN);

    mix_hash(h, out + WG_RESP_OFF_EPHEMERAL, TSNODE_WG_KEY_LEN);
    mix_key1(ck, out + WG_RESP_OFF_EPHEMERAL, TSNODE_WG_KEY_LEN);

    /* ee then se, both computed under our fresh ephemeral. */
    mix_key1(ck, ee, TSNODE_WG_KEY_LEN);
    mix_key1(ck, se, TSNODE_WG_KEY_LEN);

    /* PSK step: KDF3 -> (chain_key, tau, key); mixHash(tau). */
    tsnode_hkdf_blake2s_3(ck, tau, k, ck, peer->cfg.preshared_key,
                          TSNODE_WG_KEY_LEN);
    mix_hash(h, tau, TSNODE_WG_KEY_LEN);

    /* Encrypt an empty payload: tag-only output, AAD = h. */
    zero_nonce(nonce);
    tsnode_err_t err = cr->aead_seal(out + WG_RESP_OFF_EMPTY, k, nonce, h,
                                     TSNODE_WG_KEY_LEN, NULL, 0u);
    if (err != TSNODE_OK) {
        hs_clear_secrets(peer);
        return err;
    }
    mix_hash(h, out + WG_RESP_OFF_EMPTY, TSNODE_WG_TAG_LEN);

    add_macs(peer, out, TSNODE_WG_RESPONSE_LEN);

    /* Responder installs the session immediately (wireguard-go calls
     * BeginSymmetricSession right after creating the response). */
    uint32_t remote_index = peer->hs_remote_index;
    memcpy(peer->hs_chain_key, ck, TSNODE_WG_KEY_LEN);
    session_install(peer, local_index, remote_index, false, now_ms);
    hs_clear_secrets(peer);

    memset(k, 0, sizeof(k));
    memset(tau, 0, sizeof(tau));
    memset(ee, 0, sizeof(ee));
    memset(se, 0, sizeof(se));
    memset(eph_priv, 0, sizeof(eph_priv));
    memset(eph_pub, 0, sizeof(eph_pub));
    return TSNODE_OK;
}

/* ---- Inbound response (ConsumeMessageResponse) ---- */

tsnode_err_t tsnode_wg_consume_response(tsnode_wg_device_t *dev,
                                        const uint8_t *pkt, size_t len,
                                        uint64_t now_ms, int *peer_idx_out)
{
    if (dev == NULL || !dev->initialized || pkt == NULL ||
        peer_idx_out == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (len != TSNODE_WG_RESPONSE_LEN ||
        get_u32le(pkt + WG_OFF_TYPE) !=
            TSNODE_WG_MSG_TYPE_HANDSHAKE_RESPONSE) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* Route by our staged handshake index. */
    uint32_t receiver = get_u32le(pkt + WG_OFF_RECEIVER);
    tsnode_wg_peer_t *peer = NULL;
    int peer_idx = -1;
    for (unsigned i = 0; i < TSNODE_WG_MAX_PEERS; i++) {
        tsnode_wg_peer_t *p = &dev->peers[i];
        if (p->used && p->hs_state == TSNODE_WG_HS_INIT_CREATED &&
            p->hs_local_index == receiver) {
            peer = p;
            peer_idx = (int)i;
            break;
        }
    }
    if (peer == NULL) {
        return TSNODE_ERR_CRYPTO;
    }
    {
        uint8_t own_mac1[TSNODE_WG_KEY_LEN];
        compute_mac1_key(own_mac1, dev->public_key);
        if (!verify_mac1(own_mac1, pkt, TSNODE_WG_RESPONSE_LEN)) {
            return TSNODE_ERR_CRYPTO;
        }
    }

    const tsnode_wg_crypto_t *cr = dev->crypto;
    uint8_t ck[TSNODE_WG_KEY_LEN], h[TSNODE_WG_KEY_LEN];
    uint8_t k[TSNODE_WG_KEY_LEN], tau[TSNODE_WG_KEY_LEN];
    uint8_t ee[TSNODE_WG_KEY_LEN], se[TSNODE_WG_KEY_LEN];
    uint8_t empty[16], nonce[12];

    memcpy(ck, peer->hs_chain_key, TSNODE_WG_KEY_LEN);
    memcpy(h, peer->hs_hash, TSNODE_WG_KEY_LEN);

    mix_hash(h, pkt + WG_RESP_OFF_EPHEMERAL, TSNODE_WG_KEY_LEN);
    mix_key1(ck, pkt + WG_RESP_OFF_EPHEMERAL, TSNODE_WG_KEY_LEN);

    /* ee: DH(staged ephemeral private, their fresh ephemeral). */
    if (cr->dh(ee, peer->hs_local_eph_priv,
               pkt + WG_RESP_OFF_EPHEMERAL) != TSNODE_OK) {
        hs_clear_secrets(peer);
        return TSNODE_ERR_CRYPTO;
    }
    mix_key1(ck, ee, TSNODE_WG_KEY_LEN);

    /* se: DH(our static private, their fresh ephemeral). */
    if (cr->dh(se, dev->private_key, pkt + WG_RESP_OFF_EPHEMERAL) !=
        TSNODE_OK) {
        hs_clear_secrets(peer);
        return TSNODE_ERR_CRYPTO;
    }
    mix_key1(ck, se, TSNODE_WG_KEY_LEN);

    tsnode_hkdf_blake2s_3(ck, tau, k, ck, peer->cfg.preshared_key,
                          TSNODE_WG_KEY_LEN);
    mix_hash(h, tau, TSNODE_WG_KEY_LEN);

    zero_nonce(nonce);
    if (cr->aead_open(empty, k, nonce, h, TSNODE_WG_KEY_LEN,
                      pkt + WG_RESP_OFF_EMPTY, TSNODE_WG_TAG_LEN) !=
        TSNODE_OK) {
        hs_clear_secrets(peer);
        return TSNODE_ERR_CRYPTO;
    }
    mix_hash(h, pkt + WG_RESP_OFF_EMPTY, TSNODE_WG_TAG_LEN);

    uint32_t local_index = peer->hs_local_index;
    uint32_t remote_index = get_u32le(pkt + WG_OFF_SENDER);
    memcpy(peer->hs_chain_key, ck, TSNODE_WG_KEY_LEN);
    session_install(peer, local_index, remote_index, true, now_ms);
    hs_clear_secrets(peer);
    *peer_idx_out = peer_idx;

    memset(k, 0, sizeof(k));
    memset(tau, 0, sizeof(tau));
    memset(ee, 0, sizeof(ee));
    memset(se, 0, sizeof(se));
    memset(empty, 0, sizeof(empty));
    return TSNODE_OK;
}

/* ---- Transport data ---- */

bool tsnode_wg_peer_has_session(const tsnode_wg_device_t *dev, int peer_idx)
{
    if (dev == NULL || !dev->initialized || peer_idx < 0 ||
        peer_idx >= (int)TSNODE_WG_MAX_PEERS) {
        return false;
    }
    const tsnode_wg_peer_t *peer = &dev->peers[peer_idx];
    return peer->used && peer->session.valid;
}

tsnode_err_t tsnode_wg_encap(tsnode_wg_device_t *dev, int peer_idx,
                             const uint8_t *payload, size_t len,
                             uint64_t now_ms, uint8_t *out, size_t out_cap,
                             size_t *out_len)
{
    if (dev == NULL || !dev->initialized || peer_idx < 0 ||
        peer_idx >= (int)TSNODE_WG_MAX_PEERS || out == NULL ||
        out_len == NULL || (payload == NULL && len > 0)) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (len > TSNODE_WG_INNER_MAX ||
        out_cap < TSNODE_WG_TRANSPORT_OVERHEAD + len) {
        return TSNODE_ERR_INVALID_ARG;
    }
    tsnode_wg_peer_t *peer = &dev->peers[peer_idx];
    tsnode_wg_session_t *s = &peer->session;
    if (!peer->used || !s->valid) {
        return TSNODE_ERR_INVALID_STATE;
    }

    put_u32le(out + WG_OFF_TYPE, TSNODE_WG_MSG_TYPE_TRANSPORT_DATA);
    put_u32le(out + WG_OFF_SENDER, s->remote_index);
    put_u64le(out + WG_TRANSPORT_OFF_COUNTER, s->send_counter);

    uint8_t nonce[12];
    nonce[0] = nonce[1] = nonce[2] = nonce[3] = 0;
    put_u64le(nonce + 4, s->send_counter);
    tsnode_err_t err = dev->crypto->aead_seal(
        out + WG_TRANSPORT_OFF_DATA, s->send_key, nonce, NULL, 0u, payload,
        len);
    if (err != TSNODE_OK) {
        return err;
    }

    s->send_counter++;
    /* Refresh the liveness snapshot; expiry policy stays client-side. */
    s->established_at_ms = now_ms;
    *out_len = TSNODE_WG_TRANSPORT_OVERHEAD + len;
    return TSNODE_OK;
}

tsnode_err_t tsnode_wg_decap(tsnode_wg_device_t *dev, const uint8_t *pkt,
                             size_t len, uint8_t *payload_out,
                             size_t payload_cap, size_t *payload_len,
                             int *peer_idx_out)
{
    if (dev == NULL || !dev->initialized || pkt == NULL ||
        payload_out == NULL || payload_len == NULL ||
        peer_idx_out == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (len < TSNODE_WG_TRANSPORT_OVERHEAD ||
        get_u32le(pkt + WG_OFF_TYPE) != TSNODE_WG_MSG_TYPE_TRANSPORT_DATA) {
        return TSNODE_ERR_INVALID_ARG;
    }

    size_t ct_len = len - WG_TRANSPORT_OFF_DATA;
    if (ct_len < TSNODE_WG_TAG_LEN) {
        return TSNODE_ERR_INVALID_ARG;
    }
    size_t pt_len = ct_len - TSNODE_WG_TAG_LEN;
    if (pt_len > TSNODE_WG_INNER_MAX || payload_cap < pt_len) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* Find the session by our local index (transport header: receiver @4). */
    uint32_t receiver = get_u32le(pkt + WG_OFF_SENDER);
    tsnode_wg_peer_t *peer = NULL;
    int peer_idx = -1;
    for (unsigned i = 0; i < TSNODE_WG_MAX_PEERS; i++) {
        tsnode_wg_peer_t *p = &dev->peers[i];
        if (p->used && p->session.valid &&
            p->session.local_index == receiver) {
            peer_idx = (int)i;
            peer = p;
            break;
        }
    }
    if (peer == NULL) {
        return TSNODE_ERR_CRYPTO; /* unknown index: drop silently */
    }

    /* Authenticate BEFORE touching the replay window — a forged packet
     * must never be able to consume window state (order verified
     * against wireguard-go receive.go: decryption failure skips the
     * filter update entirely). */
    uint64_t counter = get_u64le(pkt + WG_TRANSPORT_OFF_COUNTER);
    uint8_t nonce[12];
    nonce[0] = nonce[1] = nonce[2] = nonce[3] = 0;
    put_u64le(nonce + 4, counter);
    tsnode_err_t err = dev->crypto->aead_open(
        payload_out, peer->session.recv_key, nonce, NULL, 0u,
        pkt + WG_TRANSPORT_OFF_DATA, ct_len);
    if (err != TSNODE_OK) {
        return err;
    }

    if (!tsnode_wg_replay_check_and_update(&peer->session.replay, counter,
                                           TSNODE_WG_REJECT_AFTER_MESSAGES)) {
        return TSNODE_ERR_REPLAY;
    }

    *payload_len = pt_len;
    *peer_idx_out = peer_idx;
    return TSNODE_OK;
}

/* ---- Cryptokey routing (IPv4, whitepaper §7.1 simplified) ---- */

static unsigned mask_prefix_len(uint32_t mask)
{
    unsigned bits = 0;
    while (bits < 32 && (mask & (1u << (31u - bits))) != 0) {
        bits++;
    }
    return bits;
}

int tsnode_wg_route(tsnode_wg_device_t *dev, uint32_t dst_ip)
{
    if (dev == NULL || !dev->initialized) {
        return -1;
    }

    int best = -1;
    unsigned best_bits = 0;
    for (unsigned i = 0; i < TSNODE_WG_MAX_PEERS; i++) {
        const tsnode_wg_peer_t *p = &dev->peers[i];
        if (!p->used) {
            continue;
        }
        if ((dst_ip & p->cfg.allowed_mask) ==
            (p->cfg.allowed_ip & p->cfg.allowed_mask)) {
            unsigned bits = mask_prefix_len(p->cfg.allowed_mask);
            if (best < 0 || bits > best_bits) {
                best = (int)i;
                best_bits = bits;
            }
        }
    }
    return best;
}
