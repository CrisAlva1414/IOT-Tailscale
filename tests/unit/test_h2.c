/*
 * Tests host-side del cliente HTTP/2 mínimo (ADR-0009).
 *
 * Compilan sin headers de plataforma: h2.c es C puro y el I/O se mockea
 * en memoria. Flags completos (-std=c11 -Wall -Wextra -Wpedantic -Werror)
 * según docs/format/c-style.md.
 *
 * Vectores HPACK V1/V2: generados con el probe Python validado byte a byte
 * contra controlplane.tailscale.com (sesión 2026-08-23). Si este test
 * falla, el encoder derivó de lo que producción ya aceptó.
 */

#include <stdio.h>
#include <string.h>

#include "h2.h"
#include "tsnode_map.h"

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
            tests_failed++;                                                \
        }                                                                  \
    } while (0)

#define RUN(fn)                                                            \
    do {                                                                   \
        int before = tests_failed;                                         \
        fn();                                                              \
        tests_run++;                                                       \
        if (tests_failed == before) printf("PASS %s\n", #fn);              \
    } while (0)

/* ---- Mock de I/O: "registros" plaintext en memoria ---- */

typedef struct {
    const uint8_t *in;      /* bytes concatenados que "envía" el server */
    const size_t *in_lens;  /* tamaño de cada registro simulado */
    size_t in_count;
    size_t in_total;        /* suma de in_lens */
    size_t in_next;
    size_t in_off;          /* offset dentro de in para el próximo registro */
    uint8_t out[65536];     /* todo lo que el cliente envió */
    size_t out_len;
} mock_io_t;

static tsnode_err_t m_send(void *ctx, const uint8_t *data, size_t len)
{
    mock_io_t *m = (mock_io_t *)ctx;
    if (m->out_len + len > sizeof(m->out)) return TSNODE_ERR_NO_MEMORY;
    memcpy(m->out + m->out_len, data, len);
    m->out_len += len;
    return TSNODE_OK;
}

static tsnode_err_t m_recv(void *ctx, uint8_t *buf, size_t cap,
                            size_t *out_len)
{
    mock_io_t *m = (mock_io_t *)ctx;
    if (m->in_next >= m->in_count) {
        *out_len = 0; /* EOF: conexión cerrada por el par */
        return TSNODE_OK;
    }
    size_t rec = m->in_lens[m->in_next];
    if (rec > cap) rec = cap; /* no debería ocurrir con caps correctos */
    memcpy(buf, m->in + m->in_off, rec);
    m->in_off += rec;
    m->in_next++;
    *out_len = rec;
    return TSNODE_OK;
}

/* ---- Helpers de construcción de frames ---- */

static size_t mk_frame(uint8_t *out, uint8_t type, uint8_t flags,
                       uint32_t sid, const uint8_t *payload, uint32_t len)
{
    out[0] = (uint8_t)(len >> 16);
    out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)len;
    out[3] = type;
    out[4] = flags;
    out[5] = (uint8_t)((sid >> 24) & 0x7fu);
    out[6] = (uint8_t)(sid >> 16);
    out[7] = (uint8_t)(sid >> 8);
    out[8] = (uint8_t)sid;
    if (len > 0 && payload != NULL) {
        memcpy(out + 9, payload, len);
    }
    return 9u + len;
}

/* SETTINGS real capturado del control plane de producción tras el upgrade
 * (36 bytes de payload): es lo primero que llega post-handshake. */
static const uint8_t PROD_SETTINGS_PAYLOAD[36] = {
    0x00, 0x05, 0x00, 0x10, 0x00, 0x00, /* MAX_FRAME_SIZE=1048576 */
    0x00, 0x03, 0x00, 0x00, 0x00, 0xFA, /* MAX_CONCURRENT_STREAMS=250 */
    0x00, 0x06, 0x00, 0x10, 0x01, 0x40, /* MAX_HEADER_LIST_SIZE */
    0x00, 0x01, 0x00, 0x00, 0x10, 0x00, /* HEADER_TABLE_SIZE=4096 */
    0x00, 0x04, 0x00, 0x10, 0x00, 0x00, /* INITIAL_WINDOW_SIZE */
    0x00, 0x09, 0x00, 0x00, 0x00, 0x01,
};

/* ---- Decodificación hex para los vectores HPACK ---- */

static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (hex[0] != '\0' && hex[1] != '\0' && n + 1 <= cap) {
        unsigned hi, lo;
        char c0 = hex[0], c1 = hex[1];
        hi = (c0 >= '0' && c0 <= '9') ? (unsigned)(c0 - '0')
                                      : (unsigned)(c0 - 'a' + 10);
        lo = (c1 >= '0' && c1 <= '9') ? (unsigned)(c1 - '0')
                                      : (unsigned)(c1 - 'a' + 10);
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

/* Vector V1: POST /machine/register con header ts-lb (probe h2, producción). */
static const char VECTOR_REGISTER_HEX[] =
    "8387011a636f6e74726f6c706c616e652e7461696c7363616c652e636f6d"
    "04112f6d616368696e652f7265676973746572"
    "000574732d6c62"
    "48"
    "6e6f64656b65793a34336639633830353962363134363634306634653734"
    "353365363165313962643937633964393734393437366366363236393164"
    "373862303338663731313639"
    "0f10106170706c69636174696f6e2f6a736f6e";

/* Vector V2: POST /machine/map sin ts-lb (probe h2 --map, producción). */
static const char VECTOR_MAP_HEX[] =
    "8387011a636f6e74726f6c706c616e652e7461696c7363616c652e636f6d"
    "040c2f6d616368696e652f6d6170"
    "0f10106170706c69636174696f6e2f6a736f6e";

static void test_hpack_register_vector(void)
{
    uint8_t buf[512];
    size_t len = 0;
    tsnode_err_t err = h2_build_request_headers(
        buf, sizeof(buf), "controlplane.tailscale.com", "/machine/register",
        "nodekey:43f9c8059b6146640f4e7453e61e19bd97c9d9749476cf62691d78b038"
        "f71169",
        &len);
    CHECK(err == TSNODE_OK);

    uint8_t expected[512];
    size_t expected_len =
        unhex(VECTOR_REGISTER_HEX, expected, sizeof(expected));
    CHECK(len == expected_len);
    CHECK(memcmp(buf, expected, expected_len) == 0);
}

static void test_hpack_map_vector(void)
{
    uint8_t buf[512];
    size_t len = 0;
    tsnode_err_t err = h2_build_request_headers(
        buf, sizeof(buf), "controlplane.tailscale.com", "/machine/map", NULL,
        &len);
    CHECK(err == TSNODE_OK);

    uint8_t expected[512];
    size_t expected_len = unhex(VECTOR_MAP_HEX, expected, sizeof(expected));
    CHECK(len == expected_len);
    CHECK(memcmp(buf, expected, expected_len) == 0);
}

static void test_hpack_input_limits(void)
{
    uint8_t buf[512];
    size_t len = 0;
    char big_path[300];
    memset(big_path, 'a', sizeof(big_path) - 1);
    big_path[sizeof(big_path) - 1] = '\0';

    CHECK(h2_build_request_headers(buf, sizeof(buf),
                                    "controlplane.tailscale.com", big_path,
                                    NULL, &len) == TSNODE_ERR_INVALID_ARG);
    /* Buffer demasiado chico para el bloque completo. */
    CHECK(h2_build_request_headers(buf, 16, "controlplane.tailscale.com",
                                    "/machine/register", NULL,
                                    &len) == TSNODE_ERR_NO_MEMORY);
    CHECK(h2_build_request_headers(NULL, sizeof(buf), "h", "/p", NULL,
                                    &len) == TSNODE_ERR_INVALID_ARG);
}

/* ---- Round-trip completo con SETTINGS de producción ---- */

static void feed_prod_settings_and_response(mock_io_t *m,
                                             const char *body,
                                             int body_chunks)
{
    /* Construye la entrada del server: SETTINGS prod, HEADERS ":status 200",
     * DATA del body partido en N registros. */
    static uint8_t inbuf[8192];
    static size_t lens[64];
    size_t count = 0;
    size_t off = 0;

    uint8_t f[64];
    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    uint8_t status[1] = {H2_HPACK_STATUS_200};
    flen = mk_frame(f, 0x1, 0x4 /* END_HEADERS */, 1, status, 1);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    size_t body_len = strlen(body);
    size_t chunk = body_len / (size_t)(body_chunks > 0 ? body_chunks : 1);
    if (chunk == 0) chunk = 1;
    size_t sent = 0;
    while (sent < body_len) {
        size_t take = chunk;
        if (sent + take > body_len) take = body_len - sent;
        int last = (sent + take >= body_len);
        flen = mk_frame(f, 0x0, last ? 0x1 : 0x0, 1,
                        (const uint8_t *)body + sent, (uint32_t)take);
        memcpy(inbuf + off, f, flen);
        if (count < 64) lens[count++] = flen;
        off += flen;
        sent += take;
    }

    memset(m, 0, sizeof(*m));
    m->in = inbuf;
    m->in_lens = lens;
    m->in_count = count;
    m->in_total = off;
}

static void test_roundtrip_happy_path(void)
{
    mock_io_t m;
    feed_prod_settings_and_response(&m, "{\"MachineAuthorized\":true}",
                                     3);

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    tsnode_err_t err = h2_client_start(&h, &io);
    CHECK(err == TSNODE_OK);

    const char *req_body = "{\"Version\":145}";
    uint8_t resp[256];
    size_t resp_len = 0;
    err = h2_post(&h, "controlplane.tailscale.com", "/machine/register",
                  "nodekey:ab", (const uint8_t *)req_body,
                  strlen(req_body), resp, sizeof(resp) - 1, &resp_len);
    CHECK(err == TSNODE_OK);
    resp[resp_len] = '\0';
    CHECK(strcmp((char *)resp, "{\"MachineAuthorized\":true}") == 0);

    /* Verificaciones sobre lo enviado por el cliente. */
    CHECK(m.out_len > 24);
    CHECK(memcmp(m.out, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0);
    /* SETTINGS inicial propio: ENABLE_PUSH=0 (id 2, valor 0). */
    int found_enable_push = 0;
    for (size_t i = 24; i + 5 < m.out_len; i++) {
        if (m.out[i] == 0x00 && m.out[i + 1] == 0x02 &&
            m.out[i + 2] == 0x00 && m.out[i + 3] == 0x00 &&
            m.out[i + 4] == 0x00 && m.out[i + 5] == 0x00) {
            found_enable_push = 1;
            break;
        }
    }
    CHECK(found_enable_push);
}

static void test_split_records_byte_by_byte(void)
{
    /* Misma conversación pero entregada de a 1 byte por registro: el
     * acumulador debe rearmar los frames sin perder nada. */
    mock_io_t m;
    feed_prod_settings_and_response(&m, "ok", 1);

    static uint8_t split_in[8192];
    static size_t split_lens[8192];
    size_t n = 0;
    for (size_t i = 0; i < m.in_total; i++) {
        split_in[i] = m.in[i];
        split_lens[n++] = 1;
    }

    mock_io_t s;
    memset(&s, 0, sizeof(s));
    s.in = split_in;
    s.in_lens = split_lens;
    s.in_count = n;
    s.in_total = m.in_total;

    h2_conn_t h;
    h2_io_t io = { .ctx = &s, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);

    uint8_t resp[64];
    size_t resp_len = 0;
    CHECK(h2_post(&h, "controlplane.tailscale.com", "/machine/map", NULL,
                  (const uint8_t *)"{}", 2, resp, sizeof(resp) - 1,
                  &resp_len) == TSNODE_OK);
    resp[resp_len] = '\0';
    CHECK(strcmp((char *)resp, "ok") == 0);
}

static void test_goaway_fails(void)
{
    static uint8_t inbuf[128];
    static size_t lens[8];
    uint8_t f[64];
    size_t off = 0, count = 0;

    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    uint8_t goaway[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    flen = mk_frame(f, 0x7, 0x0, 0, goaway, 8);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = count;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    /* El start consume hasta el primer SETTINGS del par y retorna OK;
     * el GOAWAY posterior se detecta al procesar la respuesta del POST. */
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);

    uint8_t resp[64];
    size_t resp_len = 0;
    CHECK(h2_post(&h, "controlplane.tailscale.com", "/machine/register",
                  NULL, (const uint8_t *)"{}", 2, resp, sizeof(resp) - 1,
                  &resp_len) == TSNODE_ERR_NETWORK);
}

static void test_oversize_frame_rejected(void)
{
    static uint8_t inbuf[16];
    static size_t lens[2];
    /* Header con length 0x200000 (> H2_MAX_FRAME_PAYLOAD): rechazo antes
     * de intentar acumular el payload. */
    uint8_t bad_hdr[9] = {0x20, 0x00, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    memcpy(inbuf, bad_hdr, 9);
    lens[0] = 9;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = 1;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_ERR_NETWORK);
}

static void test_non_200_status_rejected(void)
{
    static uint8_t inbuf[256];
    static size_t lens[8];
    uint8_t f[64];
    size_t off = 0, count = 0;

    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    /* ":status 500" no es el índice estático 8 que exigimos. */
    uint8_t status500[1] = {0x8b};
    flen = mk_frame(f, 0x1, 0x5 /* END_HEADERS|END_STREAM */, 1, status500, 1);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = count;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);

    uint8_t resp[64];
    size_t resp_len = 0;
    CHECK(h2_post(&h, "controlplane.tailscale.com", "/machine/register",
                  NULL, (const uint8_t *)"{}", 2, resp, sizeof(resp) - 1,
                  &resp_len) == TSNODE_ERR_NETWORK);
}

static void test_hpack_leading_table_size_update_ok(void)
{
    /* Regresión HW 2026-09-03: el encoder HPACK Go del control plane
     * Tailscale emite un "dynamic table size update" (0x21 = size 1) ANTES
     * del ":status 200" indexado (0x88). Nuestro parser exigía 0x88 como
     * byte 0 del bloque y fallaba con NETWORK, rompiendo el /machine/register.
     * Verifica que se saltee el size update y se acepte el 200. */
    static uint8_t inbuf[256];
    static size_t lens[8];
    uint8_t f[64];
    size_t off = 0, count = 0;

    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    /* Bloque HPACK: 0x21 (table size update = 1) + 0x88 (:status 200). */
    uint8_t status[2] = {0x21, H2_HPACK_STATUS_200};
    flen = mk_frame(f, 0x1, 0x5 /* END_HEADERS|END_STREAM */, 1, status, 2);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = count;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);

    uint8_t resp[64];
    size_t resp_len = 0;
    CHECK(h2_post(&h, "controlplane.tailscale.com", "/machine/register",
                  NULL, (const uint8_t *)"{}", 2, resp, sizeof(resp) - 1,
                  &resp_len) == TSNODE_OK);
}

static void test_hpack_leading_table_size_update_non200_rejected(void)
{
    /* Mismo caso pero el status posterior NO es 200: debe seguir fallando
     * fail-closed, no enmascarar tamaño distinto. */
    static uint8_t inbuf[256];
    static size_t lens[8];
    uint8_t f[64];
    size_t off = 0, count = 0;

    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    /* 0x21 size update + 0x8b (:status 500). */
    uint8_t status[2] = {0x21, 0x8b};
    flen = mk_frame(f, 0x1, 0x5, 1, status, 2);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = count;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);

    uint8_t resp[64];
    size_t resp_len = 0;
    CHECK(h2_post(&h, "controlplane.tailscale.com", "/machine/register",
                  NULL, (const uint8_t *)"{}", 2, resp, sizeof(resp) - 1,
                  &resp_len) == TSNODE_ERR_NETWORK);
}

static void test_ping_gets_pong(void)
{
    static uint8_t inbuf[256];
    static size_t lens[8];
    uint8_t f[64];
    size_t off = 0, count = 0;

    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    uint8_t ping_payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    flen = mk_frame(f, 0x6, 0x0, 0, ping_payload, 8);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    uint8_t status[1] = {H2_HPACK_STATUS_200};
    flen = mk_frame(f, 0x1, 0x5, 1, status, 1);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = count;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);

    uint8_t resp[64];
    size_t resp_len = 0;
    /* El PING llega intercalado en la respuesta: el PONG sale durante el
     * procesamiento del POST. */
    CHECK(h2_post(&h, "controlplane.tailscale.com", "/machine/register",
                  NULL, (const uint8_t *)"{}", 2, resp, sizeof(resp) - 1,
                  &resp_len) == TSNODE_OK);

    int found_pong = 0;
    for (size_t i = 0; i + 17 <= m.out_len; i++) {
        if (m.out[i] == 0x00 && m.out[i + 1] == 0x00 && m.out[i + 2] == 0x08 &&
            m.out[i + 3] == 0x06 && m.out[i + 4] == 0x01 &&
            memcmp(m.out + i + 9, ping_payload, 8) == 0) {
            found_pong = 1;
            break;
        }
    }
    CHECK(found_pong);
}

/* Payload opaco del PING keepalive que envía h2_ping (h2.c). */
static const uint8_t PING_KEEPALIVE_PAYLOAD[8] =
    { 0x74, 0x73, 0x6e, 0x6f, 0x64, 0x65, 0x50, 0x31 };

static void test_h2_ping_gets_ack(void)
{
    /* Server responde a nuestro PING con un ACK que repite el payload. */
    static uint8_t inbuf[128];
    static size_t lens[4];
    uint8_t f[64];
    size_t off = 0, count = 0;

    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    flen = mk_frame(f, 0x6, 0x1 /* ACK */, 0, PING_KEEPALIVE_PAYLOAD, 8);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = count;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);
    CHECK(h2_ping(&h) == TSNODE_OK);

    /* Verificar que se envió un frame PING (type 0x6, sin ACK, stream 0) con
     * el payload del keepalive. */
    int found_ping = 0;
    for (size_t i = 0; i + 17 <= m.out_len; i++) {
        if (m.out[i] == 0x00 && m.out[i + 1] == 0x00 && m.out[i + 2] == 0x08 &&
            m.out[i + 3] == 0x06 && m.out[i + 4] == 0x00 &&
            m.out[i + 5] == 0x00 && m.out[i + 6] == 0x00 &&
            memcmp(m.out + i + 9, PING_KEEPALIVE_PAYLOAD, 8) == 0) {
            found_ping = 1;
            break;
        }
    }
    CHECK(found_ping);
}

static void test_h2_ping_server_ping_ponged(void)
{
    /* El servidor manda su propio PING (sin ACK) antes de ackear el nuestro:
     * el cliente debe responder PONG primero, luego ver el ACK y retornar OK. */
    static uint8_t inbuf[128];
    static size_t lens[4];
    uint8_t f[64];
    size_t off = 0, count = 0;

    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    uint8_t srv_ping[8] = {0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    flen = mk_frame(f, 0x6, 0x0, 0, srv_ping, 8);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    flen = mk_frame(f, 0x6, 0x1 /* ACK */, 0, PING_KEEPALIVE_PAYLOAD, 8);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = count;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);
    CHECK(h2_ping(&h) == TSNODE_OK);

    /* Debe haber salido un PONG (ACK) con el payload del PING del server. */
    int found_pong = 0;
    for (size_t i = 0; i + 17 <= m.out_len; i++) {
        if (m.out[i] == 0x00 && m.out[i + 1] == 0x00 && m.out[i + 2] == 0x08 &&
            m.out[i + 3] == 0x06 && m.out[i + 4] == 0x01 &&
            memcmp(m.out + i + 9, srv_ping, 8) == 0) {
            found_pong = 1;
            break;
        }
    }
    CHECK(found_pong);
}

static void test_h2_ping_eof_fails(void)
{
    /* Solo el SETTINGS, sin ACK: el EOF durante h2_ping debe propagarse
     * como NETWORK, nunca colgarse. */
    static uint8_t inbuf[64];
    static size_t lens[2];
    uint8_t f[64];
    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf, f, flen);
    lens[0] = flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = 1;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);
    CHECK(h2_ping(&h) == TSNODE_ERR_NETWORK);
}

static void test_h2_ping_unstarted_fails(void)
{
    h2_conn_t h;
    memset(&h, 0, sizeof(h));
    CHECK(h2_ping(&h) == TSNODE_ERR_INVALID_ARG);
}

static void test_unknown_frame_type_fails_closed(void)
{
    static uint8_t inbuf[256];
    static size_t lens[8];
    uint8_t f[64];
    size_t off = 0, count = 0;

    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    uint8_t weird[4] = {0xde, 0xad, 0xbe, 0xef};
    flen = mk_frame(f, 0x42, 0x0, 0, weird, 4);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    uint8_t status[1] = {H2_HPACK_STATUS_200};
    flen = mk_frame(f, 0x1, 0x5, 1, status, 1);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = count;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    /* Igual que GOAWAY: el frame desconocido llega tras el SETTINGS del
     * par, así que el fallo se manifiesta durante el POST. */
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);

    uint8_t resp[64];
    size_t resp_len = 0;
    CHECK(h2_post(&h, "controlplane.tailscale.com", "/machine/register",
                  NULL, (const uint8_t *)"{}", 2, resp, sizeof(resp) - 1,
                  &resp_len) == TSNODE_ERR_NETWORK);
}

static void test_response_overflow_fails(void)
{
    static uint8_t inbuf[256];
    static size_t lens[8];
    uint8_t f[64];
    size_t off = 0, count = 0;

    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    uint8_t status[1] = {H2_HPACK_STATUS_200};
    flen = mk_frame(f, 0x1, 0x4, 1, status, 1);
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    uint8_t data[16];
    memset(data, 'x', sizeof(data));
    flen = mk_frame(f, 0x0, 0x1, 1, data, sizeof(data));
    memcpy(inbuf + off, f, flen);
    lens[count++] = flen;
    off += flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = count;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);

    uint8_t resp[8]; /* deliberadamente más chico que el DATA */
    size_t resp_len = 0;
    CHECK(h2_post(&h, "controlplane.tailscale.com", "/machine/register",
                  NULL, (const uint8_t *)"{}", 2, resp, sizeof(resp) - 1,
                  &resp_len) == TSNODE_ERR_NO_MEMORY);
}

static void test_eof_mid_stream_fails(void)
{
    /* Solo el SETTINGS: el EOF durante el POST debe propagarse como
     * NETWORK, nunca colgarse. */
    static uint8_t inbuf[64];
    static size_t lens[2];
    uint8_t f[64];
    size_t flen = mk_frame(f, 0x4, 0x0, 0, PROD_SETTINGS_PAYLOAD,
                           sizeof(PROD_SETTINGS_PAYLOAD));
    memcpy(inbuf, f, flen);
    lens[0] = flen;

    mock_io_t m;
    memset(&m, 0, sizeof(m));
    m.in = inbuf;
    m.in_lens = lens;
    m.in_count = 1;

    h2_conn_t h;
    h2_io_t io = { .ctx = &m, .send_bytes = m_send, .recv_record = m_recv };
    CHECK(h2_client_start(&h, &io) == TSNODE_OK);

    uint8_t resp[64];
    size_t resp_len = 0;
    CHECK(h2_post(&h, "controlplane.tailscale.com", "/machine/register",
                  NULL, (const uint8_t *)"{}", 2, resp, sizeof(resp) - 1,
                  &resp_len) == TSNODE_ERR_NETWORK);
}

/* ---- Framing de tsp (/machine/map) ---- */

static void test_map_framed_valid(void)
{
    static uint8_t wire[128];
    const char *json = "{\"KeepAlive\":false}";
    size_t jlen = strlen(json);
    wire[0] = (uint8_t)(jlen & 0xff);
    wire[1] = (uint8_t)((jlen >> 8) & 0xff);
    wire[2] = 0;
    wire[3] = 0;
    memcpy(wire + 4, json, jlen);

    const uint8_t *out_json = NULL;
    size_t out_len = 0;
    tsnode_err_t err =
        tsnode_map_parse_framed(wire, 4 + jlen, &out_json, &out_len);
    CHECK(err == TSNODE_OK);
    CHECK(out_len == jlen);
    CHECK(memcmp(out_json, json, jlen) == 0);
}

static void test_map_framed_bad_length(void)
{
    uint8_t wire[16] = {0xff, 0x00, 0x00, 0x00, '{', '}'}; /* declara 255 */
    const uint8_t *json = NULL;
    size_t jlen = 0;
    CHECK(tsnode_map_parse_framed(wire, 6, &json, &jlen) ==
          TSNODE_ERR_NETWORK);
    CHECK(tsnode_map_parse_framed(wire, 3, &json, &jlen) ==
          TSNODE_ERR_NETWORK);
}

static void test_map_framed_zstd_detected(void)
{
    uint8_t wire[12] = {0x08, 0x00, 0x00, 0x00, 0x28, 0xB5, 0x2F,
                        0xFD, 0x00, 0x00, 0x00, 0x00};
    const uint8_t *json = NULL;
    size_t jlen = 0;
    CHECK(tsnode_map_parse_framed(wire, sizeof(wire), &json, &jlen) ==
          TSNODE_ERR_NOT_IMPLEMENTED);
}

/* ---- MapResponse parser tests (Self IP + Peer endpoints) ---- */

static void test_map_parse_self_addrs(void)
{
    /* Realistic MapResponse from Tailscale SaaS with Self.Addrs */
    const char *json =
        "{\"Self\":{"
        "\"ID\":12345,"
        "\"PublicKey\":\"nodekey:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233\","
        "\"HostInfo\":{\"OS\":\"linux\",\"Hostname\":\"esp32-test\"},"
        "\"Addrs\":[\"100.64.0.10/32\"]"
        "},"
        "\"Peers\":["
        "{"
        "\"Key\":\"nodekey:1122334455667788112233445566778811223344556677881122334455667788\","
        "\"HostInfo\":{\"Hostname\":\"nas\"},"
        "\"AllowedIPs\":[\"100.64.0.20/32\"],"
        "\"Endpoints\":[\"192.0.2.100:51820\"]"
        "}"
        "]}";

    tsnode_map_netmap_t netmap;
    tsnode_err_t err = tsnode_map_parse_response(&netmap, json, strlen(json));
    CHECK(err == TSNODE_OK);
    CHECK(strcmp(netmap.self_ip, "100.64.0.10") == 0);
    CHECK(netmap.peer_count == 1);
    CHECK(strcmp(netmap.peers[0].tailscale_ip, "100.64.0.20") == 0);
    CHECK(netmap.peers[0].n_endpoints == 1);
    CHECK(strcmp(netmap.peers[0].endpoints[0].ip, "192.0.2.100") == 0);
    CHECK(netmap.peers[0].endpoints[0].port == 51820);
}

static void test_map_parse_no_self_addrs(void)
{
    /* MapResponse without Self.Addrs (old format or error) — fallback should work */
    const char *json =
        "{\"Self\":{"
        "\"ID\":12345,"
        "\"PublicKey\":\"nodekey:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233\""
        "},"
        "\"Peers\":["
        "{"
        "\"Key\":\"nodekey:1122334455667788112233445566778811223344556677881122334455667788\","
        "\"AllowedIPs\":[\"100.64.0.20/32\"]"
        "}"
        "]}";

    tsnode_map_netmap_t netmap;
    tsnode_err_t err = tsnode_map_parse_response(&netmap, json, strlen(json));
    CHECK(err == TSNODE_OK);
    /* Fallback: first "100." found in AllowedIPs */
    CHECK(strcmp(netmap.self_ip, "100.64.0.20") == 0);
    CHECK(netmap.peer_count == 1);
}

static void test_map_parse_peer_endpoint_multi(void)
{
    /* Peer with multiple endpoints — all should be parsed (not just first) */
    const char *json =
        "{\"Self\":{"
        "\"Addrs\":[\"100.64.0.1/32\"]"
        "},"
        "\"Peers\":["
        "{"
        "\"Key\":\"nodekey:1122334455667788112233445566778811223344556677881122334455667788\","
        "\"AllowedIPs\":[\"100.64.0.2/32\"],"
        "\"Endpoints\":[\"192.0.2.100:41641\",\"203.0.113.5:41641\"]"
        "}"
        "]}";

    tsnode_map_netmap_t netmap;
    tsnode_err_t err = tsnode_map_parse_response(&netmap, json, strlen(json));
    CHECK(err == TSNODE_OK);
    CHECK(netmap.peers[0].n_endpoints == 2);
    CHECK(strcmp(netmap.peers[0].endpoints[0].ip, "192.0.2.100") == 0);
    CHECK(netmap.peers[0].endpoints[0].port == 41641);
    CHECK(strcmp(netmap.peers[0].endpoints[1].ip, "203.0.113.5") == 0);
    CHECK(netmap.peers[0].endpoints[1].port == 41641);
}

static void test_map_parse_peer_endpoint_cap(void)
{
    /* Peer with more endpoints than MAX — should cap at TSNODE_MAP_MAX_ENDPOINTS */
    char json[4096];
    /* Build an Endpoints array with MAX+2 entries */
    int n = snprintf(json, sizeof(json),
        "{\"Self\":{\"Addrs\":[\"100.64.0.1/32\"]},"
        "\"Peers\":[{"
        "\"Key\":\"nodekey:1122334455667788112233445566778811223344556677881122334455667788\","
        "\"AllowedIPs\":[\"100.64.0.2/32\"],"
        "\"Endpoints\":[");
    for (int i = 1; i <= TSNODE_MAP_MAX_ENDPOINTS + 2; i++) {
        n += snprintf(json + n, sizeof(json) - (size_t)n,
                      "\"10.0.0.%d:%d\"%s", i, i,
                      (i <= TSNODE_MAP_MAX_ENDPOINTS + 1) ? "," : "");
    }
    n += snprintf(json + n, sizeof(json) - (size_t)n, "]}]}");

    tsnode_map_netmap_t netmap;
    tsnode_err_t err = tsnode_map_parse_response(&netmap, json, strlen(json));
    CHECK(err == TSNODE_OK);
    CHECK(netmap.peers[0].n_endpoints == TSNODE_MAP_MAX_ENDPOINTS);
    CHECK(strcmp(netmap.peers[0].endpoints[TSNODE_MAP_MAX_ENDPOINTS - 1].ip,
                 "10.0.0.16") == 0);
    CHECK(netmap.peers[0].endpoints[TSNODE_MAP_MAX_ENDPOINTS - 1].port == 16);
}

static void test_map_parse_multi_peer_no_desync(void)
{
    /* Regression HW 2026-09-03: el parser histórico desalineaba peers cuando
     * un peer tenía Hostinfo con `{` anidado (Services/DERP), porque avanzaba
     * con strchr('{') en lugar de anclar por nodekey. Endpoints quedaban
     * mezclados entre peers. Este test reproduce la estructura real de
     * Tailscale (multi-peer, Hostinfo con array) y verifica que cada peer
     * retiene SU key/IP/endpoints sin corrimiento. */
    const char *json =
        "{\"Self\":{\"Addrs\":[\"100.64.0.1/32\"]},"
        "\"Peers\":["
        "{"
        "\"Key\":\"nodekey:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"AllowedIPs\":[\"100.64.0.2/32\"],"
        "\"Endpoints\":[\"203.0.113.10:1111\"],"
        "\"DERP\":\"127.3.3.40:11\","
        "\"Hostinfo\":{\"OS\":\"linux\",\"Hostname\":\"notebook\","
        "\"Services\":[{\"Proto\":\"peerapi4\",\"Port\":35850}]}"
        "},"
        "{"
        "\"Key\":\"nodekey:2222222222222222222222222222222222222222222222222222222222222222\","
        "\"AllowedIPs\":[\"100.64.0.3/32\"],"
        "\"Endpoints\":[\"203.0.113.20:2222\"],"
        "\"Hostinfo\":{\"OS\":\"android\",\"Hostname\":\"phone\"}"
        "},"
        "{"
        "\"Key\":\"nodekey:3333333333333333333333333333333333333333333333333333333333333333\","
        "\"AllowedIPs\":[\"100.64.0.4/32\"],"
        "\"Endpoints\":[\"203.0.113.30:3333\",\"10.0.0.30:3333\"],"
        "\"Hostinfo\":{\"OS\":\"linux\",\"Hostname\":\"orangepi\"}"
        "}"
        "]}";

    tsnode_map_netmap_t netmap;
    tsnode_err_t err = tsnode_map_parse_response(&netmap, json, strlen(json));
    CHECK(err == TSNODE_OK);
    CHECK(netmap.peer_count == 3);

    /* Peer 0: notebook */
    CHECK(strcmp(netmap.peers[0].tailscale_ip, "100.64.0.2") == 0);
    CHECK(strcmp(netmap.peers[0].host_name, "notebook") == 0);
    CHECK(netmap.peers[0].n_endpoints == 1);
    CHECK(strcmp(netmap.peers[0].endpoints[0].ip, "203.0.113.10") == 0);
    CHECK(netmap.peers[0].endpoints[0].port == 1111);

    /* Peer 1: phone */
    CHECK(strcmp(netmap.peers[1].tailscale_ip, "100.64.0.3") == 0);
    CHECK(strcmp(netmap.peers[1].host_name, "phone") == 0);
    CHECK(netmap.peers[1].n_endpoints == 1);
    CHECK(strcmp(netmap.peers[1].endpoints[0].ip, "203.0.113.20") == 0);
    CHECK(netmap.peers[1].endpoints[0].port == 2222);

    /* Peer 2: orangepi (2 endpoints) */
    CHECK(strcmp(netmap.peers[2].tailscale_ip, "100.64.0.4") == 0);
    CHECK(strcmp(netmap.peers[2].host_name, "orangepi") == 0);
    CHECK(netmap.peers[2].n_endpoints == 2);
    CHECK(strcmp(netmap.peers[2].endpoints[0].ip, "203.0.113.30") == 0);
    CHECK(strcmp(netmap.peers[2].endpoints[1].ip, "10.0.0.30") == 0);
    CHECK(netmap.peers[2].endpoints[1].port == 3333);
}

static void test_map_parse_peer_endpoint_lan_late(void)
{
    /* HW 2026-09-03: el endpoint LAN del notebook viene DESPUÉS de varios
     * endpoints docker 172.x en la lista. Con cap 4 se perdía y disco nunca
     * lo probaba. Verifica que con el cap ampliado el LAN se captura. */
    const char *json =
        "{\"Self\":{\"Addrs\":[\"100.64.0.1/32\"]},"
        "\"Peers\":[{"
        "\"Key\":\"nodekey:4444444444444444444444444444444444444444444444444444444444444444\","
        "\"AllowedIPs\":[\"100.64.0.5/32\"],"
        "\"Endpoints\":[\"201.188.179.2:41641\",\"172.17.0.1:41641\","
        "\"172.18.0.1:41641\",\"172.19.0.1:41641\",\"172.20.0.1:41641\","
        "\"172.21.0.1:41641\",\"172.22.0.1:41641\",\"172.23.0.1:41641\","
        "\"192.168.1.100:41641\"]"
        "}]}";

    tsnode_map_netmap_t netmap;
    tsnode_err_t err = tsnode_map_parse_response(&netmap, json, strlen(json));
    CHECK(err == TSNODE_OK);
    CHECK(netmap.peers[0].n_endpoints == 9);
    /* El endpoint LAN (índice 8) está capturado y accesible para disco */
    CHECK(strcmp(netmap.peers[0].endpoints[8].ip, "192.168.1.100") == 0);
    CHECK(netmap.peers[0].endpoints[8].port == 41641);
}

static void test_map_parse_peer_no_endpoints(void)
{
    /* Peer without endpoints — n_endpoints should be 0 (unreachable) */
    const char *json =
        "{\"Self\":{"
        "\"Addrs\":[\"100.64.0.1/32\"]"
        "},"
        "\"Peers\":["
        "{"
        "\"Key\":\"nodekey:1122334455667788112233445566778811223344556677881122334455667788\","
        "\"AllowedIPs\":[\"100.64.0.2/32\"]"
        "}"
        "]}";

    tsnode_map_netmap_t netmap;
    tsnode_err_t err = tsnode_map_parse_response(&netmap, json, strlen(json));
    CHECK(err == TSNODE_OK);
    CHECK(netmap.peers[0].n_endpoints == 0);
    CHECK(netmap.peers[0].online == false);
}

int main(void)
{
    RUN(test_hpack_register_vector);
    RUN(test_hpack_map_vector);
    RUN(test_hpack_input_limits);
    RUN(test_roundtrip_happy_path);
    RUN(test_split_records_byte_by_byte);
    RUN(test_goaway_fails);
    RUN(test_oversize_frame_rejected);
    RUN(test_non_200_status_rejected);
    RUN(test_hpack_leading_table_size_update_ok);
    RUN(test_hpack_leading_table_size_update_non200_rejected);
    RUN(test_ping_gets_pong);
    RUN(test_h2_ping_gets_ack);
    RUN(test_h2_ping_server_ping_ponged);
    RUN(test_h2_ping_eof_fails);
    RUN(test_h2_ping_unstarted_fails);
    RUN(test_unknown_frame_type_fails_closed);
    RUN(test_response_overflow_fails);
    RUN(test_eof_mid_stream_fails);
    RUN(test_map_framed_valid);
    RUN(test_map_framed_bad_length);
    RUN(test_map_framed_zstd_detected);
    RUN(test_map_parse_self_addrs);
    RUN(test_map_parse_no_self_addrs);
    RUN(test_map_parse_peer_endpoint_multi);
    RUN(test_map_parse_peer_endpoint_cap);
    RUN(test_map_parse_peer_no_endpoints);
    RUN(test_map_parse_multi_peer_no_desync);
    RUN(test_map_parse_peer_endpoint_lan_late);

    printf("%d/%d tests passed\n", tests_run - tests_failed, tests_run);
    return tests_failed == 0 ? 0 : 1;
}
