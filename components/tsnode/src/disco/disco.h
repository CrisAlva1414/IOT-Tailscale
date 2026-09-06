/*
 * Disco protocol: minimal implementation for NAT traversal (ADR-0014).
 *
 * Scope: STUN client + crypto_box PING/PONG + hole puncher.
 * Explicitly OUT of scope: DERP relay, CallMeMaybe via DERP, IPv6.
 *
 * Pure C11, no platform headers (ADR-0006). All I/O via port layer.
 * Crypto via NaCl crypto_box (XSalsa20-Poly1305, ADR-0015), with X25519
 * injected from the WireGuard crypto backend.
 */

#ifndef TSNODE_DISCO_H
#define TSNODE_DISCO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tsnode_err.h"
#include "tsnode_port.h"

/* Forward declaration for injectable crypto backend */
struct tsnode_wg_crypto;
typedef struct tsnode_wg_crypto tsnode_wg_crypto_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Protocol constants ---- */

#define TSNODE_DISCO_MAGIC_LEN     6u
#define TSNODE_DISCO_KEY_LEN       32u
#define TSNODE_DISCO_NONCE_LEN     24u
#define TSNODE_DISCO_TXID_LEN      12u
#define TSNODE_DISCO_PING_MIN_LEN  46u   /* type(1)+ver(1)+txid(12)+nodekey(32) = 46 */
#define TSNODE_DISCO_PONG_LEN      32u   /* type(1)+ver(1)+txid(12)+ip16(16)+port(2) */
#define TSNODE_DISCO_MACBYTES      16u   /* Poly1305 tag */
#define TSNODE_DISCO_MAX_PKT       256u

#define TSNODE_DISCO_MAX_PEERS     8u
#define TSNODE_DISCO_MAX_ENDPOINTS 16u
#define TSNODE_DISCO_MAX_RETRIES   5u
#define TSNODE_DISCO_RETRY_MS      3000u
#define TSNODE_DISCO_STUN_INTERVAL_MS 30000u
#define TSNODE_DISCO_KEEPALIVE_MS  20000u

/* Disco message types */
typedef enum {
    TSNODE_DISCO_PING          = 0x01,
    TSNODE_DISCO_PONG          = 0x02,
    TSNODE_DISCO_CALL_ME_MAYBE = 0x03,
} tsnode_disco_msg_type_t;

/* Disco keypair (X25519) */
typedef struct {
    uint8_t pub[TSNODE_DISCO_KEY_LEN];
    uint8_t priv[TSNODE_DISCO_KEY_LEN];
} tsnode_disco_keypair_t;

/* Peer disco state */
typedef struct {
    uint8_t wg_pubkey[32];
    uint8_t disco_pubkey[TSNODE_DISCO_KEY_LEN];
    struct {
        uint32_t ip;
        uint16_t port;
    } endpoints[TSNODE_DISCO_MAX_ENDPOINTS];
    int n_endpoints;
    uint64_t last_pong_ms;
    bool direct_path_ok;
    /* Endpoint (IP:port) desde el que este peer respondió PONG. Esta es la
     * ruta directa REAL confirmada (p.ej. el LAN del peer), que suele diferir
     * de endpoints[0] (el público del MapResponse). El data plane WG debe
     * usar esta para el handshake. */
    uint32_t direct_ip;
    uint16_t direct_port;
    uint8_t pending_txid[TSNODE_DISCO_TXID_LEN];
    int retry_count;
} tsnode_disco_peer_t;

/* STUN result */
typedef struct {
    uint32_t public_ip;
    uint16_t public_port;
    bool discovered;
} tsnode_disco_stun_result_t;

/* Disco state (top-level) */
typedef struct {
    tsnode_disco_keypair_t my_kp;
    uint8_t my_wg_pubkey[32];
    tsnode_disco_peer_t peers[TSNODE_DISCO_MAX_PEERS];
    int n_peers;
    tsnode_disco_stun_result_t stun;
    uint64_t last_stun_ms;
} tsnode_disco_state_t;

/* ---- Lifecycle ---- */

/*
 * Initialize disco subsystem. Generates X25519 keypair.
 * wg_pubkey: our WireGuard public key (included in PING messages).
 * crypto: injectable crypto backend for X25519 operations.
 */
tsnode_err_t tsnode_disco_init(tsnode_disco_state_t *st,
                               const uint8_t wg_pubkey[32],
                               const tsnode_wg_crypto_t *crypto);

/*
 * Load disco keypair from NVS. If not found, generates new one and persists.
 * crypto: injectable crypto backend for key generation.
 */
tsnode_err_t tsnode_disco_load_or_generate(tsnode_disco_state_t *st,
                                           const uint8_t wg_pubkey[32],
                                           const tsnode_wg_crypto_t *crypto);

/*
 * Get our disco public key (for MapRequest).
 */
const uint8_t *tsnode_disco_get_pubkey(const tsnode_disco_state_t *st);

/* ---- Peer management ---- */

/*
 * Register a peer from MapResponse data.
 * wg_pubkey: peer's WireGuard public key.
 * disco_pubkey: peer's disco public key.
 * endpoints: array of IP:port endpoints.
 * n_eps: number of endpoints.
 */
tsnode_err_t tsnode_disco_add_peer(tsnode_disco_state_t *st,
                                   const uint8_t wg_pubkey[32],
                                   const uint8_t disco_pubkey[32],
                                   const uint32_t *endpoint_ips,
                                   const uint16_t *endpoint_ports,
                                   int n_eps);

/*
 * Find a peer by its WireGuard public key.
 * Returns the peer index, or -1 if not found / invalid args.
 */
int tsnode_disco_find_peer_by_wg_key(const tsnode_disco_state_t *st,
                                     const uint8_t wg_pubkey[32]);

/* ---- Packet handling ---- */

/*
 * Check if a raw UDP packet looks like a disco message.
 * Returns true if the first 6 bytes match the disco magic.
 */
bool tsnode_disco_is_disco_packet(const uint8_t *pkt, size_t len);

/*
 * Check if a raw UDP packet is a STUN Binding Success Response.
 * Detected via RFC 5389 magic cookie at offset 4..7 and message type 0x0101.
 */
bool tsnode_disco_is_stun_response(const uint8_t *pkt, size_t len);

/*
 * Handle an incoming disco UDP packet.
 * pkt/len: raw UDP payload.
 * src_ip/src_port: sender address.
 * udp_sock: the shared UDP socket for sending responses.
 * crypto: injectable crypto backend for NaCl crypto_box.
 */
tsnode_err_t tsnode_disco_handle_packet(tsnode_disco_state_t *st,
                                        const uint8_t *pkt, size_t len,
                                        uint32_t src_ip, uint16_t src_port,
                                        tsnode_port_udp_socket_t *udp_sock,
                                        const tsnode_wg_crypto_t *crypto);

/*
 * Send a disco PING to a specific peer endpoint.
 * udp_sock: the shared UDP socket for sending.
 * crypto: injectable crypto backend.
 */
tsnode_err_t tsnode_disco_send_ping(tsnode_disco_state_t *st, int peer_idx,
                                    tsnode_port_udp_socket_t *udp_sock,
                                    const tsnode_wg_crypto_t *crypto);

/*
 * Parse a STUN Binding Success Response and extract our public endpoint.
 * resp/len: the raw STUN response payload.
 */
tsnode_err_t tsnode_disco_stun_parse_response(tsnode_disco_state_t *st,
                                              const uint8_t *resp, size_t len);

/*
 * Poll for periodic tasks: STUN requests, retry PINGs, keepalives.
 * Should be called every ~100ms from main loop.
 * stun_server_ip/stun_server_port: DERP STUN server endpoint.
 * udp_sock: the shared UDP socket for sending.
 * crypto: injectable crypto backend.
 */
tsnode_err_t tsnode_disco_poll(tsnode_disco_state_t *st,
                               uint32_t stun_server_ip,
                               uint16_t stun_server_port,
                               tsnode_port_udp_socket_t *udp_sock,
                               const tsnode_wg_crypto_t *crypto);

/*
 * Get the best known endpoint for a peer (for WireGuard initiation).
 * Returns true if a direct path is available and fills ip/port.
 */
bool tsnode_disco_get_peer_endpoint(const tsnode_disco_state_t *st,
                                    int peer_idx,
                                    uint32_t *ip_out, uint16_t *port_out);

/*
 * Get the STUN-discovered public endpoint for this node.
 * Returns true (and fills ip/port) if STUN discovery has succeeded.
 * Used by the MapRequest builder to report the endpoint reachable from
 * the internet instead of the local WiFi IP (GOAL-3).
 */
bool tsnode_disco_get_stun_endpoint(const tsnode_disco_state_t *st,
                                    uint32_t *ip_out, uint16_t *port_out);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_DISCO_H */
