/*
 * nacl_box.c — NaCl crypto_box construction for the disco protocol
 * (ADR-0015). See nacl_box.h for the construction summary.
 *
 * The secretbox algorithm reproduced here is the reference NaCl
 * "crypto_secretbox" (XSalsa20-Poly1305) as implemented by Go's
 * secretbox package (golang.org/x/crypto/nacl/secretbox) and TweetNaCl,
 * which are byte-interoperable. Construction (per box.Precompute /
 * secretbox.Seal):
 *
 *   box_key = HSalsa20( X25519(priv, pub), zeros[16], sigma )
 *   subkey  = HSalsa20( nonce[0:16], box_key, sigma )
 *   stream  = Salsa20/20( nonce[16:24] || block_counter, subkey )
 *   poly1305_key = first 32 bytes of XSalsa20(zeros, nonce, box_key)
 *   ciphertext   = msg XOR stream
 *   out          = Poly1305(ciphertext, poly1305_key) || ciphertext
 *
 * The 32-byte zero prefix and 16-byte zero slot of the internal NaCl
 * convention are handled internally; the public API exposes the clean
 * "tag(16) || plaintext" form that Tailscale's disco sends on the wire.
 */
#include "nacl_box.h"

#include <string.h>

#include "salsa20.h"
#include "poly1305.h"

/* 16 zero bytes used as the HSalsa20 input when folding the X25519
 * shared secret into the precomputed box key (box.Precompute). */
static const uint8_t box_zero[16] = { 0 };

/* TSNODE_NACL_BOX_MAX_MSG bounds the internal scratch buffer. Disco
 * payloads are tiny (< TSNODE_DISCO_MAX_PKT) but this module is kept
 * decoupled; the caller must not exceed it. Guarded defensively below. */
#define TSNODE_NACL_BOX_MAX_MSG (64u + 16u)   /* PING/PONG + slack */

tsnode_err_t tsnode_nacl_box_beforenm(uint8_t box_key[32],
                                      const uint8_t my_priv[32],
                                      const uint8_t peer_pub[32],
                                      tsnode_nacl_box_dh_fn dh)
{
    uint8_t shared[32];
    tsnode_err_t err;

    if (box_key == NULL || my_priv == NULL || peer_pub == NULL ||
        dh == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    err = dh(shared, my_priv, peer_pub);
    if (err != TSNODE_OK) {
        return err;
    }

    /* HSalsa20 with a zero 16-byte input folds the 32-byte DH result into
     * the 32-byte precomputed key (golang box.Precompute). */
    (void)vhsalsa20_core(box_key, box_zero, shared,
                         (const uint8_t *)"expand 32-byte k");

    memset(shared, 0, sizeof(shared));
    return TSNODE_OK;
}

tsnode_err_t tsnode_nacl_box_seal_afternm(uint8_t *out, size_t *out_len,
                                           const uint8_t *plain,
                                           size_t plain_len,
                                           const uint8_t nonce[24],
                                           const uint8_t box_key[32])
{
    uint8_t pad[32 + TSNODE_NACL_BOX_MAX_MSG]; /* 32 zero prefix + msg */
    uint8_t tag[16];

    if (out == NULL || out_len == NULL || plain == NULL || nonce == NULL ||
        box_key == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (plain_len > TSNODE_NACL_BOX_MAX_MSG) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* Build the NaCl internal message with a 32-byte zero prefix. */
    memset(pad, 0, 32);
    memcpy(pad + 32, plain, plain_len);

    /* XSalsa20 encrypt the padded buffer in place. */
    (void)vxsalsa20_xor(pad, pad, 32 + plain_len, nonce, box_key);

    /* Poly1305 key = first 32 bytes (encrypted zeros); tag covers the
     * ciphertext (pad[32 ..]) exactly as the reference. */
    vpoly1305(tag, pad + 32, plain_len, pad);

    /* Output format: tag(16) || ciphertext(plain_len).
     * This matches the NaCl/Go convention used by Tailscale disco. */
    memcpy(out, tag, sizeof(tag));
    memcpy(out + sizeof(tag), pad + 32, plain_len);

    *out_len = sizeof(tag) + plain_len;

    memset(pad, 0, sizeof(pad));
    memset(tag, 0, sizeof(tag));
    return TSNODE_OK;
}

tsnode_err_t tsnode_nacl_box_open_afternm(uint8_t *plain, size_t *plain_len,
                                           const uint8_t *box, size_t box_len,
                                           const uint8_t nonce[24],
                                           const uint8_t box_key[32])
{
    uint8_t pad[32 + TSNODE_NACL_BOX_MAX_MSG];
    uint8_t expect_tag[16];
    uint8_t got_tag[16];
    size_t msg_len;

    if (plain == NULL || plain_len == NULL || box == NULL || nonce == NULL ||
        box_key == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (box_len < TSNODE_NACL_BOX_TAG_LEN) {
        return TSNODE_ERR_CRYPTO;
    }

    /* Input format: tag(16) || ciphertext(msg_len).
     * Extract the received tag and ciphertext pointer. */
    memcpy(got_tag, box, TSNODE_NACL_BOX_TAG_LEN);
    const uint8_t *ciphertext = box + TSNODE_NACL_BOX_TAG_LEN;
    msg_len = box_len - TSNODE_NACL_BOX_TAG_LEN;
    if (msg_len > TSNODE_NACL_BOX_MAX_MSG) {
        return TSNODE_ERR_CRYPTO;
    }

    /* Verify the authenticator before releasing any plaintext (fail
     * closed, AGENTS.md §2.2). The Poly1305 key is the XSalsa20 of the
     * 32-byte zero prefix (== first 32 keystream bytes), independent of
     * the message, so derive it directly. */
    (void)vxsalsa20_xor(pad, NULL, 32, nonce, box_key); /* keystream pad[0:32] */
    vpoly1305(expect_tag, ciphertext, msg_len, pad);
    if (vpoly1305_verify(expect_tag, got_tag) != 0) {
        memset(pad, 0, sizeof(pad));
        return TSNODE_ERR_CRYPTO;
    }

    /* Decrypt: rebuild the NaCl internal layout and XSalsa20-decrypt. */
    memset(pad, 0, 32);
    memcpy(pad + 32, ciphertext, msg_len);
    (void)vxsalsa20_xor(pad, pad, 32 + msg_len, nonce, box_key);
    memcpy(plain, pad + 32, msg_len);
    *plain_len = msg_len;

    memset(pad, 0, sizeof(pad));
    memset(expect_tag, 0, sizeof(expect_tag));
    memset(got_tag, 0, sizeof(got_tag));
    return TSNODE_OK;
}

tsnode_err_t tsnode_nacl_box_seal(uint8_t *out, size_t *out_len,
                                  const uint8_t *plain, size_t plain_len,
                                  const uint8_t nonce[24],
                                  const uint8_t my_priv[32],
                                  const uint8_t peer_pub[32],
                                  tsnode_nacl_box_dh_fn dh)
{
    uint8_t box_key[32];
    tsnode_err_t err;

    err = tsnode_nacl_box_beforenm(box_key, my_priv, peer_pub, dh);
    if (err != TSNODE_OK) {
        return err;
    }
    err = tsnode_nacl_box_seal_afternm(out, out_len, plain, plain_len,
                                       nonce, box_key);
    memset(box_key, 0, sizeof(box_key));
    return err;
}

tsnode_err_t tsnode_nacl_box_open(uint8_t *plain, size_t *plain_len,
                                  const uint8_t *box, size_t box_len,
                                  const uint8_t nonce[24],
                                  const uint8_t my_priv[32],
                                  const uint8_t sender_pub[32],
                                  tsnode_nacl_box_dh_fn dh)
{
    uint8_t box_key[32];
    tsnode_err_t err;

    err = tsnode_nacl_box_beforenm(box_key, my_priv, sender_pub, dh);
    if (err != TSNODE_OK) {
        return err;
    }
    err = tsnode_nacl_box_open_afternm(plain, plain_len, box, box_len,
                                       nonce, box_key);
    memset(box_key, 0, sizeof(box_key));
    return err;
}
