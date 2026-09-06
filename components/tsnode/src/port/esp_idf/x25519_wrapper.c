/*
 * X25519 raw operations — using mbedTLS ECP with Curve25519.
 *
 * Provides raw 32-byte X25519 operations needed by Noise IK.
 * Uses mbedTLS ECP module which is always available (no Everest needed).
 */

#include "x25519_wrapper.h"

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform_util.h"

#define TAG "x25519"

/* ESP-IDF entropy source for mbedTLS DRBG */
static int esp_entropy_func(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

/* Lazy-initialized DRBG for ECP operations that require f_rng */
static mbedtls_ctr_drbg_context s_ctr_drbg;
static bool s_rng_initialized;

static int ensure_rng(void)
{
    if (s_rng_initialized) return 0;
    mbedtls_ctr_drbg_init(&s_ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&s_ctr_drbg, esp_entropy_func, NULL,
                                     (const unsigned char *)"tsnode", 6);
    if (ret != 0) return -1;
    s_rng_initialized = true;
    return 0;
}

int tsnode_x25519_keygen(uint8_t priv_out[32], uint8_t pub_out[32])
{
    if (priv_out == NULL || pub_out == NULL) {
        return -1;
    }

    if (ensure_rng() != 0) return -1;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    /* Setup Curve25519 group */
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) goto cleanup;

    /* Generate keypair: d (private), Q (public) */
    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                    mbedtls_ctr_drbg_random, &s_ctr_drbg);
    if (ret != 0) goto cleanup;

    /* Export private key as little-endian 32 bytes */
    ret = mbedtls_mpi_write_binary_le(&d, priv_out, 32);
    if (ret != 0) goto cleanup;

    /* Export public key as little-endian 32 bytes (x-coordinate only for Curve25519) */
    size_t olen;
    ret = mbedtls_ecp_point_write_binary(&grp, &Q,
                                          MBEDTLS_ECP_PF_COMPRESSED,
                                          &olen, pub_out, 32);
    if (ret != 0) goto cleanup;

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    return (ret == 0) ? 0 : -1;
}

int tsnode_x25519_publickey(const uint8_t priv[32], uint8_t pub_out[32])
{
    if (priv == NULL || pub_out == NULL) {
        return -1;
    }

    if (ensure_rng() != 0) return -1;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) goto cleanup;

    /* Load key as little-endian (RFC 7748 wire format) */
    ret = mbedtls_mpi_read_binary_le(&d, priv, 32);
    if (ret != 0) goto cleanup;

    /* Clamp per RFC 7748 §5 via MPI operations.
     * Byte-level clamping alone is insufficient because mbedTLS
     * validates bitlen(d)-1 == 254, which requires bit 254 to be
     * explicitly set. We do all clamping at the MPI level to guarantee
     * the key passes mbedtls_ecp_check_privkey().
     * IMPORTANTE: mbedTLS también rechaza escalares con bit 255 puesto
     * (bitlen 256 -> BAD_INPUT_DATA -0x4c80, verificado empíricamente
     * con la misma versión de mbedTLS); una clave aleatoria cruda lo
     * tiene con p=1/2. Clear bit 255 completa el clamp RFC 7748 y hace
     * que recibir/derivar públicas desde privadas arbitrarias sea
     * determinista en vez de un coin-flip. */
    mbedtls_mpi_set_bit(&d, 0, 0);   /* clear bit 0 */
    mbedtls_mpi_set_bit(&d, 1, 0);   /* clear bit 1 */
    mbedtls_mpi_set_bit(&d, 2, 0);   /* clear bit 2 (cofactor clearing) */
    mbedtls_mpi_set_bit(&d, 254, 1); /* ensure bit 254 is set */
    mbedtls_mpi_set_bit(&d, 255, 0); /* clear bit 255: bitlen <= 255 (RFC 7748) */

    if (ensure_rng() != 0) { ret = -1; goto cleanup; }
    ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G,
                           mbedtls_ctr_drbg_random, &s_ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "ecp_mul pubkey failed: -0x%04x", -ret);
        goto cleanup;
    }

    size_t olen;
    ret = mbedtls_ecp_point_write_binary(&grp, &Q,
                                          MBEDTLS_ECP_PF_COMPRESSED,
                                          &olen, pub_out, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "point_write_binary failed: -0x%04x", -ret);
    }

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    return ret;
}

int tsnode_x25519_shared(uint8_t shared[32], const uint8_t priv[32],
                          const uint8_t pub[32])
{
    if (shared == NULL || priv == NULL || pub == NULL) {
        return -1;
    }

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point R;
    mbedtls_mpi d;
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&d);

    /* Setup Curve25519 group */
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) goto cleanup;

    /* Import private key from little-endian bytes (already clamped by
     * mbedTLS or by caller) */
    ret = mbedtls_mpi_read_binary_le(&d, priv, 32);
    if (ret != 0) goto cleanup;

    /* Clamp RFC 7748 §5 de forma defensiva: X25519 por definición clampea
     * su escalar, y mbedTLS rechaza (BAD_INPUT_DATA) escalares con bit 255
     * puesto o sin bit 254. Idempotente para claves ya clampeadas (todos
     * los callers actuales vienen de tsnode_x25519_keygen o NVS). */
    mbedtls_mpi_set_bit(&d, 0, 0);
    mbedtls_mpi_set_bit(&d, 1, 0);
    mbedtls_mpi_set_bit(&d, 2, 0);
    mbedtls_mpi_set_bit(&d, 254, 1);
    mbedtls_mpi_set_bit(&d, 255, 0);

    /* Import public key from compressed format */
    ret = mbedtls_ecp_point_read_binary(&grp, &Q, pub, 32);
    if (ret != 0) goto cleanup;

    /* Verify point is on curve */
    ret = mbedtls_ecp_check_pubkey(&grp, &Q);
    if (ret != 0) goto cleanup;

    /* Scalar multiplication: R = d * Q.
     * mbedTLS requires RNG for Curve25519 randomization. */
    if (ensure_rng() != 0) { ret = -1; goto cleanup; }
    ret = mbedtls_ecp_mul(&grp, &R, &d, &Q, mbedtls_ctr_drbg_random, &s_ctr_drbg);
    if (ret != 0) goto cleanup;

    /* Export x-coordinate as little-endian 32 bytes */
    size_t olen;
    ret = mbedtls_ecp_point_write_binary(&grp, &R,
                                          MBEDTLS_ECP_PF_COMPRESSED,
                                          &olen, shared, 32);
    if (ret != 0) goto cleanup;

    /* Check not point at infinity (all zeros) */
    uint8_t zero[32] = {0};
    if (memcmp(shared, zero, 32) == 0) {
        ret = -1;
    }

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&d);
    return (ret == 0) ? 0 : -1;
}
