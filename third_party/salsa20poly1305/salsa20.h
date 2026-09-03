/*
 * salsa20.h — Salsa20 / HSalsa20 / XSalsa20 stream cipher (vendored).
 *
 * This is a focused extraction of the Salsa20 family from TweetNaCl
 * (https://tweetnacl.cr.yp.to/), the audited public-domain reference
 * implementation by Daniel J. Bernstein, Bernard van Gastel, Wesley
 * Janssen, Tanja Lange, Peter Schwabe, and Sjaak Smetsers.
 *
 * It exposes exactly the primitives this project needs to reproduce the
 * NaCl crypto_box construction used by Tailscale's disco protocol
 * (see docs/adr/0015-nacl-box-crypto.md and third_party/README.md).
 */
#ifndef TSNODE_VENDOR_SALSA20_H
#define TSNODE_VENDOR_SALSA20_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Salsa20 64-byte block core; in = 16-byte input (nonce+block counter),
 * k = 32-byte key, c = 16-byte constant ("expand 32-byte k"). */
int vsalsa20_core(uint8_t out[64], const uint8_t in[16],
                  const uint8_t k[32], const uint8_t c[16]);

/* HSalsa20: 16-byte input, 32-byte key -> 32-byte output. Used to fold a
 * 24-byte nonce + 32-byte key into a 32-byte subkey (and, with a zero
 * input, to derive the precomputed crypto_box shared key). */
int vhsalsa20_core(uint8_t out[32], const uint8_t in[16],
                   const uint8_t k[32], const uint8_t c[16]);

/* XSalsa20 stream: generates d bytes of keystream for a 24-byte nonce n
 * and 32-byte key k. */
int vxsalsa20(uint8_t *out, size_t d, const uint8_t *n,
              const uint8_t k[32]);

/* XSalsa20 encryption/XOR; c = m XOR keystream (m may be NULL for
 * keystream-only). Handles any length. n points at a 24-byte nonce. */
int vxsalsa20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t *n, const uint8_t k[32]);

/* Salsa20/20 encryption/XOR with the raw 16-byte nonce (no HSalsa20
 * fold). Only the first 8 bytes of n are consumed (Salsa20 nonce).
 * Provided for completeness/testing of the primitive. */
int vsalsa20_xor(uint8_t *out, const uint8_t *in, size_t len,
                 const uint8_t *n, const uint8_t k[32]);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_VENDOR_SALSA20_H */
