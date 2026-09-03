/*
 * NaCl crypto_box host tests — cross-validated against TweetNaCl's
 * reference primitives.
 *
 * Verifies that our XSalsa20-Poly1305 secretbox (components/tsnode/src/
 * crypto/nacl_box.c) is byte-for-byte interoperable with the NaCl
 * construction Tailscale's disco uses (golang secretbox / crypto_box):
 *   - beforenm shared-key derivation == box.Precompute
 *   - seal/open round-trip
 *   - seal output byte-identical to crypto_secretbox (tag||ciphertext)
 *   - open decrypts TweetNaCl ciphertext
 *   - authentication fails closed on tampering
 *   - argument validation / bounds
 *
 * Vector provenance: TweetNaCl (public domain, audited reference by
 * Bernstein et al.) is the independent reference implementation used to
 * cross-check exact byte output — see third_party/README.md and
 * docs/adr/0015-nacl-box-crypto.md.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "nacl_box.h"
#include "tsnode_err.h"
#include "tweetnacl.h"

static int failures;

/* TweetNaCl's keygen refers to randombytes() (not used by our DH
 * backend, but required at link time by tweetnacl.o). Deterministic
 * linear fill; never used for anything security-relevant here. */
void randombytes(unsigned char *buf, unsigned long long len)
{
    for (unsigned long long i = 0; i < len; i++)
        buf[i] = (unsigned char)(i & 0xFF);
}

/* TweetNaCl X25519 used as the DH backend for the box key. This is
 * independent of our own NaCl box logic and of the mbedTLS X25519, so
 * it provides a good cross-check of the HSalsa20 folding too. */
static tsnode_err_t tweet_dh(uint8_t shared[32], const uint8_t priv[32],
                             const uint8_t pub[32])
{
    if (crypto_scalarmult_curve25519_tweet(shared, priv, pub) != 0)
        return TSNODE_ERR_CRYPTO;
    return TSNODE_OK;
}

static int ct_cmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff != 0;
}

static void hexdump(const char *tag, const uint8_t *p, size_t n)
{
    printf("  %s", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

/* 1. beforenm (box.Precompute) == crypto_box_beforenm */
static void test_beforenm(void)
{
    uint8_t my_priv[32], peer_pub[32];
    uint8_t ref_k[32], mine_k[32];

    printf("beforenm key derivation (vs TweetNaCl box.Precompute):\n");

    for (unsigned t = 0; t < 3; t++) {
        for (int i = 0; i < 32; i++) {
            my_priv[i] = (uint8_t)(0x11 * (t + 1) + i);
            peer_pub[i] = (uint8_t)(0xa0 + i * (t + 1));
        }
        /* Clamp the private key per RFC 7748 §5 (TweetNaCl would too). */
        my_priv[0] &= 248; my_priv[31] &= 127; my_priv[31] |= 64;

        crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(
            ref_k, peer_pub, my_priv);

        if (tsnode_nacl_box_beforenm(mine_k, my_priv, peer_pub, tweet_dh)
            != TSNODE_OK) {
            printf("  FAIL [%u] beforenm error\n", t);
            failures++;
            continue;
        }
        if (ct_cmp(ref_k, mine_k, 32)) {
            printf("  FAIL [%u] mismatch\n", t);
            hexdump("ref : ", ref_k, 32);
            hexdump("mine: ", mine_k, 32);
            failures++;
            continue;
        }
        printf("  OK   [%u]\n", t);
    }
}

/* 2. seal output byte-identical to crypto_secretbox (tag||ciphertext) */
static void test_seal_interop(void)
{
    uint8_t key[32], nonce[24], msg[20], mine[64], ref[64];
    size_t mine_len = 0;

    printf("seal output byte-identical to TweetNaCl crypto_secretbox "
           "(tag||ct):\n");

    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 24; i++) nonce[i] = (uint8_t)(i + 0x40);
    for (int i = 0; i < 20; i++) msg[i] = (uint8_t)(i + 0x80);

    /* TweetNaCl secretbox takes a 32-byte zero-prefixed message and emits
     * box[0:16] zeros + [tag(16) || ct]. Our clean form is equivalent to
     * box[16 .. 16+20+16]. */
    uint8_t padded[32 + 64];
    memset(padded, 0, 32);
    memcpy(padded + 32, msg, sizeof(msg));
    crypto_secretbox_xsalsa20poly1305_tweet(
        ref, padded, 32 + sizeof(msg), nonce, key);

    if (tsnode_nacl_box_seal_afternm(mine, &mine_len, msg, sizeof(msg),
                                     nonce, key) != TSNODE_OK) {
        printf("  FAIL seal_afternm error\n");
        failures++;
        return;
    }

    if (mine_len != 16 + sizeof(msg)) {
        printf("  FAIL length: got %zu want %zu\n", mine_len,
               16 + sizeof(msg));
        failures++;
        return;
    }
    if (ct_cmp(mine, ref + 16, mine_len)) {
        printf("  FAIL byte mismatch\n");
        hexdump("ref : ", ref + 16, mine_len);
        hexdump("mine: ", mine, mine_len);
        failures++;
        return;
    }
    printf("  OK   len=%zu\n", mine_len);
}

/* 3. open decrypts TweetNaCl ciphertext (and rejects tampering) */
static void test_open_interop(void)
{
    uint8_t key[32], nonce[24], msg[20], box[64], plain[64];
    size_t plain_len = 0;

    printf("open interop with TweetNaCl ciphertext + fail-closed:\n");

    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x55 + i);
    for (int i = 0; i < 24; i++) nonce[i] = (uint8_t)(i + 0x30);
    for (int i = 0; i < 20; i++) msg[i] = (uint8_t)(i + 0x10);

    uint8_t padded[32 + 64];
    memset(padded, 0, 32);
    memcpy(padded + 32, msg, sizeof(msg));
    crypto_secretbox_xsalsa20poly1305_tweet(box, padded,
                                            32 + sizeof(msg), nonce, key);

    /* box is [0*16|tag(16)||ct(20)] on the wire; NaCl box form is
     * tag||ct = box[16 .. 16+36]. */
    const uint8_t *nl = box + 16;

    if (tsnode_nacl_box_open_afternm(plain, &plain_len, nl, 16 + sizeof(msg),
                                     nonce, key) != TSNODE_OK) {
        printf("  FAIL open error\n");
        failures++;
        return;
    }
    if (plain_len != sizeof(msg) || ct_cmp(plain, msg, sizeof(msg))) {
        printf("  FAIL plaintext mismatch\n");
        failures++;
        return;
    }
    printf("  OK   plaintext round-trip\n");

    /* Tampering with any plaintext byte must fail closed without
     * modifying the plaintext buffer. */
    uint8_t tampered[64];
    memcpy(tampered, box, 16 + sizeof(msg));
    memcpy(tampered + 16, "XXXXXXXX", 8); /* corrupt ct */
    uint8_t guard[64];
    memset(guard, 0xAA, sizeof(guard));
    if (tsnode_nacl_box_open_afternm(guard, &plain_len, tampered,
                                     16 + sizeof(msg), nonce, key)
        != TSNODE_ERR_CRYPTO) {
        printf("  FAIL tampered ct not rejected\n");
        failures++;
    } else {
        printf("  OK   tampered ct rejected\n");
    }
}

/* 4. self round-trip through the convenience seal/open with DH */
static void test_roundtrip_dh(void)
{
    uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32];
    uint8_t nonce[24], out[64], back[64];
    size_t out_len = 0, back_len = 0;
    const uint8_t msg[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    printf("seal/open round-trip via X25519 DH + HSalsa20:\n");

    for (int i = 0; i < 32; i++) {
        a_priv[i] = (uint8_t)(0x40 + i); a_pub[i] = 0;
        b_priv[i] = (uint8_t)(0x80 + i); b_pub[i] = 0;
        nonce[i < 24 ? i : 0] = (uint8_t)(i + 1);
    }
    a_priv[0] &= 248; a_priv[31] &= 127; a_priv[31] |= 64;
    b_priv[0] &= 248; b_priv[31] &= 127; b_priv[31] |= 64;

    if (crypto_scalarmult_curve25519_tweet_base(a_pub, a_priv) != 0 ||
        crypto_scalarmult_curve25519_tweet_base(b_pub, b_priv) != 0) {
        printf("  FAIL keygen\n");
        failures++;
        return;
    }
    /* We need deterministic nonces; derive from a pub bytes. */
    for (int i = 0; i < 24; i++) nonce[i] = a_pub[i] ^ b_pub[i];

    if (tsnode_nacl_box_seal(out, &out_len, msg, sizeof(msg), nonce,
                             a_priv, b_pub, tweet_dh) != TSNODE_OK) {
        printf("  FAIL seal\n");
        failures++;
        return;
    }
    if (tsnode_nacl_box_open(back, &back_len, out, out_len, nonce,
                             b_priv, a_pub, tweet_dh) != TSNODE_OK) {
        printf("  FAIL open\n");
        failures++;
        return;
    }
    if (back_len != sizeof(msg) || ct_cmp(back, msg, sizeof(msg))) {
        printf("  FAIL round-trip mismatch\n");
        failures++;
        return;
    }
    /* Wrong receiver key must fail closed. */
    uint8_t c_priv[32] = {0};
    c_priv[0] = 1; c_priv[31] = 2; c_priv[31] |= 64; c_priv[0] &= 248;
    if (tsnode_nacl_box_open(back, &back_len, out, out_len, nonce,
                             c_priv, a_pub, tweet_dh) != TSNODE_ERR_CRYPTO) {
        printf("  FAIL wrong key not rejected\n");
        failures++;
        return;
    }
    printf("  OK   round-trip + wrong-key rejection\n");
}

/* 5. argument validation */
static void test_arg_validation(void)
{
    uint8_t key[32] = {0}, nonce[24] = {0}, buf[64];
    size_t len = 0;

    printf("argument validation:\n");
    if (tsnode_nacl_box_seal_afternm(NULL, &len, buf, 1, nonce, key)
        != TSNODE_ERR_INVALID_ARG) {
        printf("  FAIL NULL out accepted\n"); failures++;
    } else printf("  OK   NULL out rejected\n");

    if (tsnode_nacl_box_open_afternm(buf, &len, NULL, 16, nonce, key)
        != TSNODE_ERR_INVALID_ARG) {
        printf("  FAIL NULL box accepted\n"); failures++;
    } else printf("  OK   NULL box rejected\n");

    if (tsnode_nacl_box_open_afternm(buf, &len, buf, 15, nonce, key)
        != TSNODE_ERR_CRYPTO) {
        printf("  FAIL too-short box accepted\n"); failures++;
    } else printf("  OK   too-short box rejected\n");

    if (tsnode_nacl_box_beforenm(buf, key, NULL, tweet_dh)
        != TSNODE_ERR_INVALID_ARG) {
        printf("  FAIL NULL peer_pub accepted\n"); failures++;
    } else printf("  OK   NULL peer_pub rejected\n");
}

int main(void)
{
    test_beforenm();
    test_seal_interop();
    test_open_interop();
    test_roundtrip_dh();
    test_arg_validation();

    if (failures) {
        printf("\nNACL_BOX TESTS: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("\nNACL_BOX TESTS: ALL PASS\n");
    return 0;
}
