/*
 * poly1305.h — Poly1305 one-time authenticator (vendored).
 *
 * Focused extraction of TweetNaCl's crypto_onetimeauth (public domain,
 * https://tweetnacl.cr.yp.to/). For the challenge of a message with the
 * given 32-byte one-time key, per RFC 8439 / D.J. Bernstein's spec.
 */
#ifndef TSNODE_VENDOR_POLY1305_H
#define TSNODE_VENDOR_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Writes the 16-byte Poly1305 authenticator of msg[0..len) to mac. */
void vpoly1305(uint8_t mac[16], const uint8_t *msg, size_t len,
               const uint8_t key[32]);

/* Constant-time authenticator comparison. Returns non-zero if a != b. */
int vpoly1305_verify(const uint8_t a[16], const uint8_t b[16]);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_VENDOR_POLY1305_H */
