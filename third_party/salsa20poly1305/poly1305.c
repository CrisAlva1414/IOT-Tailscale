/*
 * poly1305.c — Poly1305 one-time authenticator (vendored).
 *
 * Faithful port of TweetNaCl's crypto_onetimeauth (public domain,
 * https://tweetnacl.cr.yp.to/). The arithmetic reproduces the reference
 * implementation exactly so the output is byte-compatible.
 */
#include "poly1305.h"

typedef uint32_t u32;

static void add1305(u32 *h, const u32 *c)
{
    u32 j, u = 0;
    for (j = 0; j < 17; j++) {
        u += h[j] + c[j];
        h[j] = u & 255;
        u >>= 8;
    }
}

static const u32 minusp[17] = {
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
};

void vpoly1305(uint8_t mac[16], const uint8_t *msg, size_t n,
               const uint8_t key[32])
{
    u32 s, i, j, u, x[17], r[17], h[17], c[17], g[17];

    for (j = 0; j < 17; j++) r[j] = h[j] = 0;
    for (j = 0; j < 16; j++) r[j] = key[j];
    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;

    while (n > 0) {
        for (j = 0; j < 17; j++) c[j] = 0;
        for (j = 0; (j < 16) && (j < n); j++) c[j] = msg[j];
        c[j] = 1;
        msg += j;
        n -= j;
        add1305(h, c);
        for (i = 0; i < 17; i++) {
            x[i] = 0;
            for (j = 0; j < 17; j++) {
                x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
            }
        }
        for (i = 0; i < 17; i++) h[i] = x[i];
        u = 0;
        for (j = 0; j < 16; j++) {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u & 3;
        u = 5 * (u >> 2);
        for (j = 0; j < 16; j++) {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u;
    }

    for (j = 0; j < 17; j++) g[j] = h[j];
    add1305(h, minusp);
    s = -(h[16] >> 7);
    for (j = 0; j < 17; j++) h[j] ^= s & (g[j] ^ h[j]);

    for (j = 0; j < 16; j++) c[j] = key[j + 16];
    c[16] = 0;
    add1305(h, c);
    for (j = 0; j < 16; j++) mac[j] = (uint8_t)h[j];
}

int vpoly1305_verify(const uint8_t a[16], const uint8_t b[16])
{
    uint32_t d = 0;
    int i;
    /* Constant-time authenticator comparison: XOR every byte into a single
     * accumulator, then make one branchless decision on the accumulated
     * value (contrast with memcmp, which short-circuits on early bytes). */
    for (i = 0; i < 16; i++) d |= ((uint32_t)a[i]) ^ ((uint32_t)b[i]);
    return d == 0 ? 0 : 1;
}
