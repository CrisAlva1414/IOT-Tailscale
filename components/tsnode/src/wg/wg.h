/*
 * tsnode-wg — minimal WireGuard data plane core (ADR-0008).
 *
 * Scope of this module (self-contained, no I/O, no heap):
 *   - Noise_IKpsk2 handshake: create/consume initiation + response.
 *   - Transport data encryption/decryption (ChaCha20-Poly1305, LE64
 *     counter nonce) with anti-replay filtering (wg/replay.c).
 *   - Cryptokey routing for IPv4 allowed-ips matching.
 *
 * Explicitly OUT of v1 scope (documented limitations, see session log
 * 2026-08-24 and ADR-0008):
 *   - Cookie replies (mac2): messages always carry mac2 = zeros, which
 *     is valid; peers only demand a valid mac2 under load. Consuming
 *     cookie replies needs XChaCha20 (HChaCha20), deferred to its own
 *     increment before any deployment outside controlled networks.
 *   - Session rekey policy (REKEY_AFTER_* timers) and keepalive
 *     scheduling: client-layer policy on top of this core.
 *   - Single active session per peer: completing a handshake replaces
 *     the previous one immediately. In-flight packets encrypted under
 *     the old session during rekey are dropped (brief loss window),
 *     not buffered. Accepted tradeoff for v1 footprint.
 *
 * All protocol constants below were verified against primary sources
 * (wireguard-go device sources @ master, fetched 2026-08-24; WireGuard
 * whitepaper §5.4) — AGENTS.md §5.6. No value is assumed.
 *
 * Pure C11, no platform headers, injectable crypto (ADR-0008 D3/D4).
 */

#ifndef TSNODE_WG_H
#define TSNODE_WG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tsnode_err.h"
#include "replay.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Protocol constants (wireguard-go device/noise-types.go) ---- */

#define TSNODE_WG_KEY_LEN 32u          /* Curve25519 key / chain key size */
#define TSNODE_WG_TAG_LEN 16u          /* Poly1305 tag */
#define TSNODE_WG_TIMESTAMP_LEN 12u    /* TAI64N */
#define TSNODE_WG_MAC_LEN 16u          /* mac1/mac2 */
#define TSNODE_WG_MAC_INPUT_LABEL_LEN 8u

#define TSNODE_WG_MSG_TYPE_HANDSHAKE_INITIATION 1u
#define TSNODE_WG_MSG_TYPE_HANDSHAKE_RESPONSE 2u
#define TSNODE_WG_MSG_TYPE_COOKIE_REPLY 3u
#define TSNODE_WG_MSG_TYPE_TRANSPORT_DATA 4u

/* Message sizes incl. mac1+mac2 (noise-types.go message sizes). */
#define TSNODE_WG_INITIATION_LEN 148u
#define TSNODE_WG_RESPONSE_LEN 92u
#define TSNODE_WG_TRANSPORT_HEADER_LEN 16u
#define TSNODE_WG_TRANSPORT_OVERHEAD \
    (TSNODE_WG_TRANSPORT_HEADER_LEN + TSNODE_WG_TAG_LEN)

/* Maximum inner packet this core accepts/produces (compile-time cap,
 * ADR-0008 D6). Client layers must not exceed it; typical IoT payloads
 * are far below. */
#ifndef TSNODE_WG_INNER_MAX
#define TSNODE_WG_INNER_MAX 1280u
#endif

/* Whitepaper §6.2: reject counters beyond this (wireguard-go
 * RejectAfterMessages = 1<<64 - 1<<13 - 1). */
#define TSNODE_WG_REJECT_AFTER_MESSAGES \
    (UINT64_MAX - (UINT64_C(1) << 13) - UINT64_C(1))

/* Max peers fixed at compile time (static allocation, ADR-0008 D3). */
#ifndef TSNODE_WG_MAX_PEERS
#define TSNODE_WG_MAX_PEERS 4u
#endif

/* ---- Injectable crypto surface (ADR-0008 D3) ---- */

typedef struct tsnode_wg_crypto {
    /* X25519 shared secret; returns TSNODE_ERR_CRYPTO if the result is
     * all-zero (small-order input) — callers must treat that as fatal. */
    tsnode_err_t (*dh)(uint8_t shared[TSNODE_WG_KEY_LEN],
                       const uint8_t priv[TSNODE_WG_KEY_LEN],
                       const uint8_t pub[TSNODE_WG_KEY_LEN]);
    /* X25519 public key derivation from a private key. */
    tsnode_err_t (*pubkey)(uint8_t pub[TSNODE_WG_KEY_LEN],
                           const uint8_t priv[TSNODE_WG_KEY_LEN]);
    /* ChaCha20-Poly1305 seal: out_ct = ct || tag (ct_len = pt_len +
     * TSNODE_WG_TAG_LEN written by caller contract: out buffer must be
     * at least pt_len + tag). aad may be NULL when aad_len == 0. */
    tsnode_err_t (*aead_seal)(uint8_t *out_ct, const uint8_t key[32],
                              const uint8_t nonce[12], const uint8_t *aad,
                              size_t aad_len, const uint8_t *pt,
                              size_t pt_len);
    /* ChaCha20-Poly1305 open: ct includes trailing tag; out_pt receives
     * exactly ct_len - tag bytes. Any failure = authentication failure. */
    tsnode_err_t (*aead_open)(uint8_t *out_pt, const uint8_t key[32],
                              const uint8_t nonce[12], const uint8_t *aad,
                              size_t aad_len, const uint8_t *ct,
                              size_t ct_len);
    /* Fill out with len cryptographically-strong random bytes (ephemeral
     * key generation). Core stays clock/RNG-free (ADR-0008 D4). */
    tsnode_err_t (*random)(uint8_t *out, size_t len);
    /* Generate a valid X25519 keypair. The private key is clamped per
     * RFC 7748 §5 and passes mbedTLS validation. Use this instead of
     * random()+pubkey() for ephemeral key generation. */
    tsnode_err_t (*keygen)(uint8_t priv[32], uint8_t pub[32]);
    /* Secure memory zeroization. Portable alternative to
     * mbedtls_platform_zeroize that works on any platform. */
    void (*zeroize)(void *ptr, size_t len);
} tsnode_wg_crypto_t;

/* Production backend (mbedTLS via x25519_wrapper); host tests supply
 * their own doubles. Declared here so clients don't need a private
 * header. */
const tsnode_wg_crypto_t *tsnode_wg_crypto_mbedtls(void);
/* Host test backend (TweetNaCl + RFC 8439 test AEAD, deterministic
 * RNG) — test-only, never linked into firmware. */
const tsnode_wg_crypto_t *tsnode_wg_crypto_host(void);
/* Re-seeds the deterministic LCG so handshake tests are reproducible. */
void tsnode_test_host_rng_seed(uint64_t seed);

/* ---- Peer configuration ---- */

typedef struct tsnode_wg_peer_cfg {
    uint8_t public_key[TSNODE_WG_KEY_LEN]; /* remote static public key */
    uint8_t preshared_key[TSNODE_WG_KEY_LEN]; /* all-zero == none */
    /* IPv4 cryptokey route: packets to (dst & mask) == allowed_ip are
     * routed to this peer. One prefix per peer in v1. */
    uint32_t allowed_ip;   /* host byte order */
    uint32_t allowed_mask; /* host byte order, e.g. 0xFFFFFF00u */
} tsnode_wg_peer_cfg_t;

/* ---- Handshake state machine (per peer) ---- */

typedef enum {
    TSNODE_WG_HS_IDLE = 0,
    TSNODE_WG_HS_INIT_CREATED,  /* we sent initiation, await response */
    TSNODE_WG_HS_INIT_CONSUMED, /* responder staged initiation */
} tsnode_wg_hs_state_t;

/* ---- Established session (per peer, single slot — see header note) ---- */

typedef struct tsnode_wg_session {
    bool valid;
    uint32_t local_index;  /* our routing tag for this session */
    uint32_t remote_index; /* peer's routing tag (from their msgs) */
    uint8_t send_key[TSNODE_WG_KEY_LEN];
    uint8_t recv_key[TSNODE_WG_KEY_LEN];
    uint64_t send_counter;
    tsnode_wg_replay_t replay;
    uint64_t established_at_ms; /* caller-supplied clock snapshot */
} tsnode_wg_session_t;

/* ---- Device / peer structures (all static, ADR-0008 D3) ---- */

typedef struct tsnode_wg_peer {
    bool used;
    tsnode_wg_peer_cfg_t cfg;
    uint8_t ss_static[TSNODE_WG_KEY_LEN]; /* DH(local_priv, peer_pub) */
    uint8_t mac1_key[TSNODE_WG_KEY_LEN]; /* HASH("mac1----"||peer_pub) */
    uint8_t cookie_key[TSNODE_WG_KEY_LEN]; /* HASH("cookie--"||peer_pub) */
    uint8_t last_timestamp[TSNODE_WG_TIMESTAMP_LEN];
    bool have_timestamp;

    /* In-progress handshake state (cleared after use/failure). */
    tsnode_wg_hs_state_t hs_state;
    uint32_t hs_local_index;
    uint32_t hs_remote_index;
    uint8_t hs_hash[TSNODE_WG_KEY_LEN];
    uint8_t hs_chain_key[TSNODE_WG_KEY_LEN];
    uint8_t hs_local_eph_priv[TSNODE_WG_KEY_LEN];
    uint8_t hs_remote_eph_pub[TSNODE_WG_KEY_LEN];
    uint8_t hs_presumed_key[TSNODE_WG_KEY_LEN];

    tsnode_wg_session_t session;
} tsnode_wg_peer_t;

typedef struct tsnode_wg_device {
    bool initialized;
    uint8_t private_key[TSNODE_WG_KEY_LEN];
    uint8_t public_key[TSNODE_WG_KEY_LEN];
    const tsnode_wg_crypto_t *crypto;
    tsnode_wg_peer_t peers[TSNODE_WG_MAX_PEERS];
    uint32_t next_index; /* monotonic sender-index allocator, != 0 */
} tsnode_wg_device_t;

/* ---- Lifecycle ---- */

/*
 * Initialize device with a 32-byte private key. Derives the public key
 * through the injected crypto and clamps the private key in place
 * (wireguard-go noise-protocol.go: sk[0]&=248, sk[31]=(sk[31]&127)|64 —
 * callers passing keys generated elsewhere get identical behavior).
 */
tsnode_err_t tsnode_wg_device_init(tsnode_wg_device_t *dev,
                                   uint8_t private_key[TSNODE_WG_KEY_LEN],
                                   const tsnode_wg_crypto_t *crypto);

/* Register a peer (public key must be unique). Returns peer index or
 * -1 if full/duplicate/invalid args. Computes static-static DH and MAC
 * keys once here. */
int tsnode_wg_peer_add(tsnode_wg_device_t *dev,
                       const tsnode_wg_peer_cfg_t *cfg);

/* Remove a peer by public key (ADR-0021, PeersRemoved del stream de map).
 * Wipes the whole slot (derived keys, handshake and session state). Peer
 * slots are never reordered: client-side arrays indexed by peer index stay
 * aligned. Idempotent: removing a peer that is not present returns OK. */
tsnode_err_t tsnode_wg_peer_remove(tsnode_wg_device_t *dev,
                                   const uint8_t pubkey[TSNODE_WG_KEY_LEN]);

/* ---- Outbound handshake ---- */

/*
 * Build a 148-byte initiation for peer_idx. timestamp must be TAI64N
 * (or any strictly-increasing 12-byte value) supplied by the caller —
 * the core has no clock (ADR-0008 D4). On success the peer enters
 * HS_INIT_CREATED and awaits tsnode_wg_consume_response().
 */
tsnode_err_t tsnode_wg_create_initiation(tsnode_wg_device_t *dev,
                                         int peer_idx,
                                         const uint8_t timestamp[TSNODE_WG_TIMESTAMP_LEN],
                                         uint8_t out[TSNODE_WG_INITIATION_LEN]);

/* Build a 92-byte response after a successful consume_initiation. */
tsnode_err_t tsnode_wg_create_response(tsnode_wg_device_t *dev,
                                       int peer_idx,
                                       uint64_t now_ms,
                                       uint8_t out[TSNODE_WG_RESPONSE_LEN]);

/* ---- Inbound handshake ---- */

/*
 * Validate + stage an initiation. On success returns the peer index and
 * stages HS_INIT_CONSUMED; call tsnode_wg_create_response() next.
 * Fails closed (TSNODE_ERR_CRYPTO) on any MAC/AEAD/timestamp failure or
 * unknown sender.
 */
tsnode_err_t tsnode_wg_consume_initiation(tsnode_wg_device_t *dev,
                                          const uint8_t *pkt, size_t len,
                                          int *peer_idx_out);

/*
 * Complete our own handshake using a response to a prior
 * create_initiation(). Establishes the session on success. Fails
 * closed on any validation error (state, receiver index, MAC, AEAD).
 */
tsnode_err_t tsnode_wg_consume_response(tsnode_wg_device_t *dev,
                                        const uint8_t *pkt, size_t len,
                                        uint64_t now_ms, int *peer_idx_out);

/* ---- Transport data ---- */

/* True if the peer has a usable (valid, non-expired-by-policy) session.
 * Expiry policy beyond replay limits is client-layer. */
bool tsnode_wg_peer_has_session(const tsnode_wg_device_t *dev, int peer_idx);

/*
 * Encrypt one inner packet into an encapsulated transport-data message:
 * out needs len + TSNODE_WG_TRANSPORT_OVERHEAD bytes. Uses and advances
 * the session send counter. Empty payload (len 0) produces the WG
 * keepalive (32 bytes).
 */
tsnode_err_t tsnode_wg_encap(tsnode_wg_device_t *dev, int peer_idx,
                             const uint8_t *payload, size_t len, uint64_t now_ms,
                             uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * Decrypt an inbound transport-data message. On success fills
 * payload_out (up to TSNODE_WG_INNER_MAX) and reports the peer index.
 * Replay duplicates return TSNODE_ERR_REPLAY and must be dropped by
 * the caller (not a protocol failure).
 */
tsnode_err_t tsnode_wg_decap(tsnode_wg_device_t *dev, const uint8_t *pkt,
                             size_t len, uint8_t *payload_out,
                             size_t payload_cap, size_t *payload_len,
                             int *peer_idx_out);

/* ---- Cryptokey routing (IPv4) ---- */

/*
 * Resolve which configured peer should receive a packet addressed to
 * dst_ip (host byte order) per allowed_ip/mask prefixes. Returns -1 if
 * no peer matches (caller decides: drop or initiate discovery).
 */
int tsnode_wg_route(tsnode_wg_device_t *dev, uint32_t dst_ip);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_WG_H */
