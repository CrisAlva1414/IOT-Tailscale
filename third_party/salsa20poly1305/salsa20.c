/*
 * salsa20.c — Salsa20 / HSalsa20 / XSalsa20 stream cipher (vendored).
 *
 * Faithful port of the Salsa20 core and XSalsa20 stream functions from
 * TweetNaCl (public domain, https://tweetnacl.cr.yp.to/), referenced in
 * salsa20.h. The byte layout and additions match the original exactly so
 * the output is byte-compatible with the reference implementation.
 *
 * Only the Salsa20 family is included here; X25519 and Poly1305 live in
 * their own vendored TU (salsa20poly1305/poly1305.c + the injected
 * X25519 backend), see third_party/README.md.
 */
#include "salsa20.h"

typedef uint32_t u32;
typedef uint64_t u64;

static u32 rotl(u32 x, int c)
{
    return (x << c) | (x >> (32 - c));
}

static void load32_pair(u32 out[16], const uint8_t in[16],
                        const uint8_t k[32], const uint8_t c[16])
{
    int i;
    for (i = 0; i < 4; i++) {
        out[5 * i] = ((u32)c[4 * i + 3] << 24) | ((u32)c[4 * i + 2] << 16) |
                     ((u32)c[4 * i + 1] << 8) | (u32)c[4 * i];
        out[1 + i] = ((u32)k[4 * i + 3] << 24) | ((u32)k[4 * i + 2] << 16) |
                     ((u32)k[4 * i + 1] << 8) | (u32)k[4 * i];
        out[6 + i] = ((u32)in[4 * i + 3] << 24) | ((u32)in[4 * i + 2] << 16) |
                     ((u32)in[4 * i + 1] << 8) | (u32)in[4 * i];
        out[11 + i] = ((u32)k[16 + 4 * i + 3] << 24) |
                      ((u32)k[16 + 4 * i + 2] << 16) |
                      ((u32)k[16 + 4 * i + 1] << 8) | (u32)k[16 + 4 * i];
    }
}

static void store32(uint8_t *out, u32 v)
{
    out[0] = (uint8_t)(v);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
}

/* h == 0: full Salsa20 block (64-byte output).
 * h == 1: HSalsa20 half (32-byte output, no feed-forward on constants). */
static int core_half(uint8_t *out, const uint8_t in[16], const uint8_t k[32],
                     const uint8_t c[16], int h)
{
    u32 w[16], x[16], y[16], t[4];
    int i, j, m;

    load32_pair(x, in, k, c);
    for (i = 0; i < 16; i++) y[i] = x[i];

    for (i = 0; i < 20; i++) {   /* 20 rounds = Salsa20/20 */
        for (j = 0; j < 4; j++) {
            for (m = 0; m < 4; m++) t[m] = x[(5 * j + 4 * m) % 16];
            t[1] ^= rotl(t[0] + t[3], 7);
            t[2] ^= rotl(t[1] + t[0], 9);
            t[3] ^= rotl(t[2] + t[1], 13);
            t[0] ^= rotl(t[3] + t[2], 18);
            for (m = 0; m < 4; m++) w[4 * j + (j + m) % 4] = t[m];
        }
        for (m = 0; m < 16; m++) x[m] = w[m];
    }

    if (h) {
        for (i = 0; i < 16; i++) x[i] += y[i];
        for (i = 0; i < 4; i++) {
            x[5 * i] -= ((u32)c[4 * i + 3] << 24) | ((u32)c[4 * i + 2] << 16) |
                        ((u32)c[4 * i + 1] << 8) | (u32)c[4 * i];
            x[6 + i] -= ((u32)in[4 * i + 3] << 24) |
                        ((u32)in[4 * i + 2] << 16) |
                        ((u32)in[4 * i + 1] << 8) | (u32)in[4 * i];
        }
        for (i = 0; i < 4; i++) {
            store32(out + 4 * i, x[5 * i]);
            store32(out + 16 + 4 * i, x[6 + i]);
        }
    } else {
        for (i = 0; i < 16; i++) store32(out + 4 * i, x[i] + y[i]);
    }
    return 0;
}

int vsalsa20_core(uint8_t out[64], const uint8_t in[16],
                  const uint8_t k[32], const uint8_t c[16])
{
    return core_half(out, in, k, c, 0);
}

int vhsalsa20_core(uint8_t out[32], const uint8_t in[16],
                   const uint8_t k[32], const uint8_t c[16])
{
    return core_half(out, in, k, c, 1);
}

static const uint8_t ts_sigma[16] = "expand 32-byte k";

int vsalsa20_xor(uint8_t *out, const uint8_t *in, size_t len,
                 const uint8_t *n, const uint8_t k[32])
{
    uint8_t z[16], x[64];
    u32 u, i;

    if (len == 0) return 0;
    for (i = 0; i < 16; i++) z[i] = 0;
    for (i = 0; i < 8; i++) z[i] = n[i];

    while (len >= 64) {
        vsalsa20_core(x, z, k, ts_sigma);
        for (i = 0; i < 64; i++) out[i] = (in ? in[i] : 0) ^ x[i];
        u = 1;
        for (i = 8; i < 16; i++) {
            u += z[i];
            z[i] = (uint8_t)u;
            u >>= 8;
        }
        len -= 64;
        out += 64;
        if (in) in += 64;
    }
    if (len > 0) {
        vsalsa20_core(x, z, k, ts_sigma);
        for (i = 0; i < len; i++) out[i] = (in ? in[i] : 0) ^ x[i];
    }
    return 0;
}

int vxsalsa20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t *n, const uint8_t k[32])
{
    uint8_t s[32];
    vhsalsa20_core(s, n, k, ts_sigma);
    return vsalsa20_xor(out, in, len, n + 16, s);
}

int vxsalsa20(uint8_t *out, size_t len, const uint8_t *n,
              const uint8_t k[32])
{
    return vxsalsa20_xor(out, NULL, len, n, k);
}
