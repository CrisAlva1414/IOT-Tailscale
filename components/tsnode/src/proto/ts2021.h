/*
 * ts2021: cliente Noise IK + capa de registros para ts2021.
 *
 * Este archivo es C puro: sin headers de plataforma (ADR-0006).
 * Cipher suite: Noise_IK_25519_ChaChaPoly_BLAKE2s
 * Fuente primaria: tailscale/tailscale control/controlbase/
 */

#ifndef TSNODE_TS2021_H
#define TSNODE_TS2021_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tsnode_err.h"
#include "tsnode_port.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Cipher suite name (verified from handshake.go) */
#define NOISE_PROTOCOL_NAME "Noise_IK_25519_ChaChaPoly_BLAKE2s"

/* Connection context after successful handshake */
typedef struct {
    uint8_t tx_key[32];              /* ChaCha20-Poly1305 tx key */
    uint8_t rx_key[32];              /* ChaCha20-Poly1305 rx key */
    uint64_t tx_counter;             /* Outgoing nonce counter */
    uint64_t rx_counter;             /* Incoming nonce counter */
    tsnode_port_socket_t *sock;      /* Underlying TCP socket */
    bool established;                /* true after Split() */
    /* Read-ahead buffer: leftover bytes from HTTP read consumed before
     * the record layer was established.  The record layer reads from
     * this buffer first, then from the socket. */
    uint8_t prebuf[512];             /* Pre-buffered data */
    size_t prebuf_len;               /* Valid bytes in prebuf */
    uint32_t recv_timeout_ms;        /* Per-record recv timeout (ms) */
} ts2021_conn_t;

/*
 * Noise IK handshake state for split handshake (HTTP upgrade flow).
 * Used when the initiation must be sent in an HTTP header before
 * the TCP connection is fully available.
 */
typedef struct {
    uint8_t handshake_hash[32];      /* Current handshake hash */
    uint8_t chaining_key[32];        /* Current chaining key */
    uint8_t eph_priv[32];            /* Ephemeral private key */
    uint8_t eph_pub[32];             /* Ephemeral public key */
    uint8_t machine_key_priv[32];    /* Machine private key (copy) */
    uint8_t control_key_pub[32];     /* Control server public key (copy) */
    uint16_t protocol_version;       /* Protocol version */
    bool initiated;                  /* true after initiate */
} ts2021_handshake_state_t;

/*
 * Generate Noise IK initiation message (101 bytes) for HTTP upgrade header.
 * The initiation is returned in `init_out` (must be at least 101 bytes).
 * State is saved in `state` for later completion via _complete().
 */
tsnode_err_t ts2021_handshake_initiate(
    ts2021_handshake_state_t *state,
    uint8_t init_out[101],
    const uint8_t machine_key_priv[32],
    const uint8_t control_key_pub[32],
    uint16_t protocol_version);

/*
 * Complete Noise IK handshake after receiving server response.
 * Call this after HTTP 101 Switching Protocols with the 51-byte response.
 * On success, conn is populated with session keys.
 */
tsnode_err_t ts2021_handshake_complete(
    ts2021_conn_t *conn,
    const ts2021_handshake_state_t *state,
    const uint8_t response[51],
    tsnode_port_socket_t *sock);

/*
 * Perform Noise IK handshake as client.
 * Sends initiation, receives response, derives session keys.
 *
 * Requires: machine_key_priv (32 bytes), control_key_pub (32 bytes),
 *           protocol_version (1 for ts2021), connected socket.
 *
 * On success, conn is populated with session keys and counters.
 */
tsnode_err_t ts2021_handshake_client(ts2021_conn_t *conn,
                                     const uint8_t machine_key_priv[32],
                                     const uint8_t control_key_pub[32],
                                     uint16_t protocol_version,
                                     tsnode_port_socket_t *sock);

/*
 * Send encrypted record (type=4 + length + ciphertext + tag).
 * Data is encrypted with tx_key and tx_counter.
 */
tsnode_err_t ts2021_record_send(ts2021_conn_t *conn, const uint8_t *data,
                                size_t len);

/*
 * Receive and decrypt one record.
 * Reads type/length header, decrypts with rx_key and rx_counter.
 * buf must be large enough for the plaintext (max 4093 bytes).
 */
tsnode_err_t ts2021_record_recv(ts2021_conn_t *conn, uint8_t *buf,
                                size_t buf_size, size_t *out_len);

/*
 * Close connection and clean up. Idempotent.
 */
void ts2021_conn_close(ts2021_conn_t *conn);

/*
 * Inject leftover bytes from the HTTP read into the connection's read buffer.
 * These bytes will be consumed by the next ts2021_record_recv() calls.
 * Must be called before any record_recv (i.e., after handshake_complete).
 */
void ts2021_conn_prebuffer(ts2021_conn_t *conn, const uint8_t *data,
                            size_t len);

/*
 * Set per-record recv timeout in milliseconds.  Default is 10000 (10s),
 * suitable for interactive exchanges.  Long-poll endpoints (e.g.
 * /machine/map) need a longer timeout (300s) because the server holds the
 * connection open for up to several minutes waiting for state changes.
 */
void ts2021_set_recv_timeout(ts2021_conn_t *conn, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_TS2021_H */
