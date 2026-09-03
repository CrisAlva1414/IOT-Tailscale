/*
 * nacl_box.h — NaCl crypto_box construction (XSalsa20-Poly1305 + HSalsa20
 * shared-key derivation) for the disco protocol (ADR-0015).
 *
 * Reimplements the golang.org/x/crypto/nacl/box construction that
 * Tailscale's disco uses (types/key/disco.go):
 *
 *   Precompute(shared, peerPub, priv):
 *       tmp = X25519(priv, peerPub)
 *       HSalsa20(shared, zeros[16], tmp, sigma)
 *
 *   SealAfterPrecomputation(out, msg, nonce[24], shared):
 *       secretbox.Seal(msg, nonce, shared)   // XSalsa20 + Poly1305
 *       -> out = "tag(16) || msg"
 *
 * The output byte layout is interoperable with NaCl "crypto_box" and with
 * Go's secretbox (the 32-byte zero prefix and 16-byte zero slot that the
 * low-level NaCl API exposes are managed internally here; the public API
 * below is the clean "plaintext || tag" form used by Tailscale).
 *
 * X25519 is injected via a function pointer (same backend used by the
 * WireGuard core, ADR-0008 D3); Salsa20/HSalsa20 and Poly1305 come from
 * the vendored third_party/salsa20poly1305 primitives. Pure C11.
 */
#ifndef TSNODE_NACL_BOX_H
#define TSNODE_NACL_BOX_H

#include <stddef.h>
#include <stdint.h>

#include "tsnode_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Overhead added by the box: 16-byte Poly1305 authenticator. */
#define TSNODE_NACL_BOX_TAG_LEN 16u
#define TSNODE_NACL_BOX_NONCE_LEN 24u
#define TSNODE_NACL_BOX_KEY_LEN 32u

/* X25519 shared-secret backend. Implementations must return
 * TSNODE_ERR_CRYPTO when the result is the all-zero sentinel
 * (small-order input). This is the same contract as
 * tsnode_wg_crypto_t::dh (wg.h). */
typedef tsnode_err_t (*tsnode_nacl_box_dh_fn)(uint8_t shared[32],
                                              const uint8_t priv[32],
                                              const uint8_t pub[32]);

/*
 * Derive the precomputed crypto_box shared key from a peer public key and
 * our private key: box_key = HSalsa20(X25519(priv, pub), zeros16, sigma).
 * This is box.Precompute (types/key/disco.go). Callers should cache the
 * result per peer; the DH dominates the cost.
 */
tsnode_err_t tsnode_nacl_box_beforenm(uint8_t box_key[32],
                                      const uint8_t my_priv[32],
                                      const uint8_t peer_pub[32],
                                      tsnode_nacl_box_dh_fn dh);

/*
 * Seal a message with a precomputed box key and a 24-byte nonce.
 * Writes "plain || tag(16)" to out (out must hold plain_len + 16 bytes).
 * out_len is set to plain_len + 16 on success.
 */
tsnode_err_t tsnode_nacl_box_seal_afternm(uint8_t *out, size_t *out_len,
                                          const uint8_t *plain,
                                          size_t plain_len,
                                          const uint8_t nonce[24],
                                          const uint8_t box_key[32]);

/*
 * Open a box produced by seal_afternm. On success writes exactly
 * box_len - 16 bytes of plaintext to plain (must hold at least that many)
 * and sets *plain_len. Any authentication failure returns
 * TSNODE_ERR_CRYPTO without modifying the plaintext buffer.
 */
tsnode_err_t tsnode_nacl_box_open_afternm(uint8_t *plain, size_t *plain_len,
                                          const uint8_t *box, size_t box_len,
                                          const uint8_t nonce[24],
                                          const uint8_t box_key[32]);

/*
 * Convenience: derive the shared key then seal. out must hold
 * plain_len + 16 bytes.
 */
tsnode_err_t tsnode_nacl_box_seal(uint8_t *out, size_t *out_len,
                                  const uint8_t *plain, size_t plain_len,
                                  const uint8_t nonce[24],
                                  const uint8_t my_priv[32],
                                  const uint8_t peer_pub[32],
                                  tsnode_nacl_box_dh_fn dh);

/*
 * Convenience: derive the shared key then open. box must be valid
 * (>= 16 bytes); any authentication failure returns TSNODE_ERR_CRYPTO.
 */
tsnode_err_t tsnode_nacl_box_open(uint8_t *plain, size_t *plain_len,
                                  const uint8_t *box, size_t box_len,
                                  const uint8_t nonce[24],
                                  const uint8_t my_priv[32],
                                  const uint8_t sender_pub[32],
                                  tsnode_nacl_box_dh_fn dh);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_NACL_BOX_H */
