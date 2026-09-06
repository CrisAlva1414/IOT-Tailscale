/*
 * Cliente HTTP/2 mínimo sobre un transporte de registros ya cifrado
 * (implementación de ADR-0009).
 *
 * Subset implementado, fail-closed ante todo lo demás:
 *   - preface + SETTINGS inicial (ENABLE_PUSH=0) / ACK del SETTINGS del par
 *   - un stream secuencial por request: HEADERS (END_HEADERS) + DATA
 *     (END_STREAM), bodies de hasta H2_MAX_FRAME_PAYLOAD en un solo frame
 *   - HPACK de salida literal-without-indexing sin Huffman + índices
 *     estáticos; bytes idénticos a los vectores generados contra el control
 *     plane real (tests/unit/test_h2.c)
 *   - recepción: DATA del stream hasta END_STREAM; SETTINGS/PING se responden;
 *     WINDOW_UPDATE/PRIORITY ignorados; GOAWAY/RST/CONTINUATION/PADDED/
 *     PUSH_PROMISE/desconocidos → TSNODE_ERR_NETWORK
 *
 * C puro: sin headers de plataforma (ADR-0006) y sin logging — los códigos
 * de error son la interfaz; el llamador agrega contexto de log. El I/O se
 * inyecta vía h2_io_t para testear en host sin red ni Noise.
 *
 * Fuente primaria: golang.org/x/net/http2 (framing), tailscale/tailscale
 * control/ts2021/client.go (uso oficial).
 */

#include "h2.h"

#include <string.h>

/* ---- Tipos y flags de frames (RFC 7540 §6) ---- */

#define H2_FRAME_DATA          0x0u
#define H2_FRAME_HEADERS       0x1u
#define H2_FRAME_PRIORITY      0x2u
#define H2_FRAME_RST_STREAM    0x3u
#define H2_FRAME_SETTINGS      0x4u
#define H2_FRAME_PUSH_PROMISE  0x5u
#define H2_FRAME_PING          0x6u
#define H2_FRAME_GOAWAY        0x7u
#define H2_FRAME_WINDOW_UPDATE 0x8u
#define H2_FRAME_CONTINUATION  0x9u

#define H2_FLAG_END_STREAM  0x1u /* DATA/HEADERS */
#define H2_FLAG_ACK         0x1u /* SETTINGS/PING */
#define H2_FLAG_END_HEADERS 0x4u
#define H2_FLAG_PADDED      0x8u

/* Flags de HEADERS que no soportamos (padding y dependencia de prioridad):
 * fail-closed en vez de parsear a ciegas. */
#define H2_FLAGS_HEADERS_UNSUPPORTED ((uint8_t)(H2_FLAG_PADDED | 0x20u))

#define H2_HEADER_LEN 9u

/* SETTINGS_ENABLE_PUSH=0 (id 2): prohibimos push del servidor; con push
 * habilitado un PUSH_PROMISE nos mataría la conexión por fail-closed. */
#define H2_SETTINGS_ENABLE_PUSH_ID   0x0002u
#define H2_SETTINGS_ENABLE_PUSH_VAL  0x00000000u

#define SETTINGS_PAYLOAD_LEN 6u

#define H2_CLIENT_PREFACE \
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    uint32_t length;
    const uint8_t *payload; /* válido hasta consume_frame() */
} h2_frame_view_t;

typedef struct {
    uint8_t *resp;
    size_t resp_cap;
    size_t resp_len;
    uint32_t req_stream;
    bool seen_headers;
    bool done;
    /* Modo streaming (ADR-0021): si on_data != NULL, los payloads de DATA
     * se entregan al callback en lugar de acumularse en resp. */
    tsnode_err_t (*on_data)(const uint8_t *data, size_t len, void *ctx);
    void *on_data_ctx;
} h2_resp_ctx_t;

/* ---- Helpers de envío ---- */

static tsnode_err_t send_all(const h2_io_t *io, const uint8_t *data,
                             size_t len)
{
    while (len > 0) {
        size_t chunk = (len > H2_MAX_RECORD_PLAINTEXT)
                           ? H2_MAX_RECORD_PLAINTEXT
                           : len;
        tsnode_err_t err = io->send_bytes(io->ctx, data, chunk);
        if (err != TSNODE_OK) return err;
        data += chunk;
        len -= chunk;
    }
    return TSNODE_OK;
}

static void put_frame_header(uint8_t out[H2_HEADER_LEN], uint8_t type,
                             uint8_t flags, uint32_t stream_id,
                             uint32_t length)
{
    out[0] = (uint8_t)(length >> 16);
    out[1] = (uint8_t)(length >> 8);
    out[2] = (uint8_t)length;
    out[3] = type;
    out[4] = flags;
    /* Bit reservado (MSB del stream id) siempre 0 desde cliente. */
    out[5] = (uint8_t)((stream_id >> 24) & 0x7fu);
    out[6] = (uint8_t)(stream_id >> 16);
    out[7] = (uint8_t)(stream_id >> 8);
    out[8] = (uint8_t)stream_id;
}

static tsnode_err_t send_settings_ack(h2_conn_t *h)
{
    uint8_t f[H2_HEADER_LEN];
    put_frame_header(f, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, 0);
    return send_all(&h->io, f, sizeof(f));
}

static tsnode_err_t send_pong(h2_conn_t *h, const uint8_t *payload,
                              uint32_t len)
{
    uint8_t hdr[H2_HEADER_LEN];
    put_frame_header(hdr, H2_FRAME_PING, H2_FLAG_ACK, 0, len);
    tsnode_err_t err = send_all(&h->io, hdr, sizeof(hdr));
    if (err != TSNODE_OK) return err;
    return send_all(&h->io, payload, len);
}

/* ---- Acumulación de registros entrantes ---- */

static tsnode_err_t pull_record(h2_conn_t *h)
{
    if (h->acc_len >= sizeof(h->acc)) {
        /* Inalcanzable si consume_frame se usa parejo con peek_frame:
         * el frame más grande calza justo en acc. Si pasa, es bug nuestro. */
        return TSNODE_ERR_NO_MEMORY;
    }
    size_t space = sizeof(h->acc) - h->acc_len;
    size_t got = 0;
    tsnode_err_t err = h->io.recv_record(h->io.ctx, h->acc + h->acc_len,
                                          space, &got);
    if (err != TSNODE_OK) return err;
    if (got == 0) {
        /* EOF del par con stream pendiente. Los registros Noise de longitud
         * cero (legales como padding) se consumen dentro del callback recv:
         * aquí 0 significa únicamente conexión cerrada. */
        return TSNODE_ERR_NETWORK;
    }
    h->acc_len += got;
    return TSNODE_OK;
}

static tsnode_err_t acc_ensure(h2_conn_t *h, size_t need)
{
    while (h->acc_len < need) {
        tsnode_err_t err = pull_record(h);
        if (err != TSNODE_OK) return err;
    }
    return TSNODE_OK;
}

static tsnode_err_t peek_frame(h2_conn_t *h, h2_frame_view_t *view)
{
    tsnode_err_t err = acc_ensure(h, H2_HEADER_LEN);
    if (err != TSNODE_OK) return err;

    uint32_t length = ((uint32_t)h->acc[0] << 16) |
                      ((uint32_t)h->acc[1] << 8) |
                      (uint32_t)h->acc[2];
    if (length > H2_MAX_FRAME_PAYLOAD) {
        /* Nunca advertiseamos más grande; un length mayor solo puede ser
         * hostil o un par roto (ADR-0009 D3). */
        return TSNODE_ERR_NETWORK;
    }

    err = acc_ensure(h, H2_HEADER_LEN + length);
    if (err != TSNODE_OK) return err;

    view->length = length;
    view->type = h->acc[3];
    view->flags = h->acc[4];
    view->stream_id = ((uint32_t)(h->acc[5] & 0x7fu) << 24) |
                      ((uint32_t)h->acc[6] << 16) |
                      ((uint32_t)h->acc[7] << 8) |
                      (uint32_t)h->acc[8];
    view->payload = h->acc + H2_HEADER_LEN;
    return TSNODE_OK;
}

static void consume_frame(h2_conn_t *h, const h2_frame_view_t *view)
{
    size_t total = H2_HEADER_LEN + view->length;
    memmove(h->acc, h->acc + total, h->acc_len - total);
    h->acc_len -= total;
}

/* ---- HPACK de salida (literal sin indexing, sin Huffman) ---- */

static bool buf_put(uint8_t *buf, size_t cap, size_t *pos,
                    const uint8_t *data, size_t len)
{
    if (*pos + len > cap) return false;
    memcpy(buf + *pos, data, len);
    *pos += len;
    return true;
}

static bool buf_put_byte(uint8_t *buf, size_t cap, size_t *pos, uint8_t b)
{
    return buf_put(buf, cap, pos, &b, 1);
}

/* Prefijo de índice para "literal without indexing" con nombre indexado.
 * idx < 15: 0000iiii en un byte; idx >= 15: 00001111 + varint 7-bit (idx-15).
 * Nuestros índices (1, 4, 31) caben siempre en dos bytes máximo. */
static bool put_name_index(uint8_t *buf, size_t cap, size_t *pos,
                           unsigned idx)
{
    if (idx < 15) return buf_put_byte(buf, cap, pos, (uint8_t)idx);
    if (idx - 15 >= 127) return false;
    return buf_put_byte(buf, cap, pos, 0x0f) &&
           buf_put_byte(buf, cap, pos, (uint8_t)(idx - 15));
}

static bool put_hpack_string(uint8_t *buf, size_t cap, size_t *pos,
                             const char *s)
{
    size_t len = strlen(s);
    if (len >= 127) return false; /* authority/path/lb acotados por diseño */
    if (!buf_put_byte(buf, cap, pos, (uint8_t)len)) return false;
    return buf_put(buf, cap, pos, (const uint8_t *)s, len);
}

tsnode_err_t h2_build_request_headers(uint8_t *buf, size_t cap,
                                      const char *authority, const char *path,
                                      const char *lb_value, size_t *out_len)
{
    if (buf == NULL || authority == NULL || path == NULL || out_len == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (strlen(authority) > 255 || strlen(path) > 255 ||
        (lb_value != NULL && strlen(lb_value) > 255)) {
        return TSNODE_ERR_INVALID_ARG;
    }

    size_t pos = 0;
    /* Orden fijo: :method, :scheme, :authority, :path, [ts-lb], content-type.
     * Debe coincidir byte a byte con los vectores V1/V2 del test. */
    if (!buf_put_byte(buf, cap, &pos, 0x83)) goto no_mem; /* :method POST (3) */
    if (!buf_put_byte(buf, cap, &pos, 0x87)) goto no_mem; /* :scheme https (7) */
    if (!put_name_index(buf, cap, &pos, 1)) goto no_mem;  /* :authority */
    if (!put_hpack_string(buf, cap, &pos, authority)) goto no_mem;
    if (!put_name_index(buf, cap, &pos, 4)) goto no_mem;  /* :path */
    if (!put_hpack_string(buf, cap, &pos, path)) goto no_mem;
    if (lb_value != NULL) {
        if (!buf_put_byte(buf, cap, &pos, 0x00)) goto no_mem; /* nombre nuevo */
        if (!put_hpack_string(buf, cap, &pos, "ts-lb")) goto no_mem;
        if (!put_hpack_string(buf, cap, &pos, lb_value)) goto no_mem;
    }
    if (!put_name_index(buf, cap, &pos, 31)) goto no_mem; /* content-type */
    if (!put_hpack_string(buf, cap, &pos, "application/json")) goto no_mem;

    *out_len = pos;
    return TSNODE_OK;

no_mem:
    return TSNODE_ERR_NO_MEMORY;
}

/* ---- Manejo de frames recibidos ---- */

/*
 * Verifica que el bloque HPACK de una respuesta arranque con ":status 200"
 * indexado (0x88). RFC 7541 §4.2 permite que el bloque venga precedido de
 * UNO O MÁS "dynamic table size update" (0b001xxxxx) antes del primer header
 * real; el encoder Go de Tailscale emite uno de tamaño 1 al arrancar cada
 * bloque (verificado en hardware 2026-09-03), rompiendo la asunción previa
 * de que 0x88 era el byte 0. Por eso los saltamos acá y exigimos 0x88 justo
 * después. Cualquier otro encabezado antes del ":status" → fail-closed.
 *
 * Devuelve true si el bloque comienza (tras skip de size-update) con el
 * ":status 200" indexado; false en cualquier otro caso.
 */
static bool hpack_starts_with_status_200(const uint8_t *blk, size_t len)
{
    if (blk == NULL || len < 1) return false;

    size_t pos = 0;
    /* Skip leading dynamic table size updates (RFC 7541 §4.2):
     * primer byte 0b001xxxxx; si los 5 bits bajos son 0x1F, continúa en
     * varint de 7 bits (bytes con bit alto seteado). */
    for (;;) {
        uint8_t b = blk[pos];
        if ((b & 0xE0u) != 0x20u) break;   /* no es size update → parar */
        pos++;
        if ((b & 0x1Fu) == 0x1Fu) {        /* varint de 5 bits completo */
            while (pos < len && (blk[pos] & 0x80u)) pos++;
            if (pos >= len) return false;  /* varint truncado: hostil */
        }
        if (pos >= len) return false;
    }

    if (pos >= len) return false;
    return blk[pos] == H2_HPACK_STATUS_200;
}

static tsnode_err_t handle_frame(h2_conn_t *h, const h2_frame_view_t *f,
                                 h2_resp_ctx_t *rc)
{
    switch (f->type) {
    case H2_FRAME_SETTINGS:
        if (!(f->flags & H2_FLAG_ACK)) {
            return send_settings_ack(h);
        }
        return TSNODE_OK;

    case H2_FRAME_PING:
        if (f->length != 8 || f->stream_id != 0) return TSNODE_ERR_NETWORK;
        if (!(f->flags & H2_FLAG_ACK)) {
            return send_pong(h, f->payload, f->length);
        }
        return TSNODE_OK;

    case H2_FRAME_WINDOW_UPDATE:
    case H2_FRAME_PRIORITY:
        return TSNODE_OK;

    case H2_FRAME_GOAWAY:
        /* El servidor cierra la conexión; en este subset no hay recovery.
         * El caller loguea el fallo genérico (sin datos del frame). */
        return TSNODE_ERR_NETWORK;

    case H2_FRAME_DATA:
        if (rc == NULL || !rc->seen_headers) return TSNODE_ERR_NETWORK;
        if (f->stream_id != rc->req_stream) return TSNODE_ERR_NETWORK;
        if (f->flags & H2_FLAG_PADDED) return TSNODE_ERR_NETWORK;
        if (rc->on_data != NULL) {
            /* Modo streaming: el callback consume el payload (que puede ser
             * un fragmento de mensaje). El callback es el dueño del framing. */
            tsnode_err_t derr = rc->on_data(f->payload, f->length,
                                            rc->on_data_ctx);
            if (derr != TSNODE_OK) return derr;
        } else {
            if ((size_t)f->length > rc->resp_cap - rc->resp_len) {
                /* Overflow de respuesta → error explícito, nunca truncado
                 * silencioso (AGENTS.md §4). Caller dimensiona según ADR-0009 D3. */
                return TSNODE_ERR_NO_MEMORY;
            }
            memcpy(rc->resp + rc->resp_len, f->payload, f->length);
            rc->resp_len += f->length;
        }
        if (f->flags & H2_FLAG_END_STREAM) rc->done = true;
        return TSNODE_OK;

    case H2_FRAME_HEADERS:
        if (rc == NULL) return TSNODE_ERR_NETWORK;
        if (f->stream_id != rc->req_stream) return TSNODE_ERR_NETWORK;
        if (f->flags & H2_FLAGS_HEADERS_UNSUPPORTED) {
            return TSNODE_ERR_NETWORK;
        }
        if (!(f->flags & H2_FLAG_END_HEADERS)) {
            /* Sin CONTINUATION: headers que no calzan en un frame son
             * rechazadas (ADR-0009 D1). */
            return TSNODE_ERR_NETWORK;
        }
        if (!rc->seen_headers) {
            rc->seen_headers = true;
            /* Exigimos ":status 200" como header indexado de tabla estática
             * (idx 8). El bloque puede venir precedido de dynamic table size
             * updates (RFC 7541 §4.2; el encoder Go emite uno de tamaño 1),
             * que se saltan en hpack_starts_with_status_200. Cualquier otro
             * status o encoding → error. */
            if (!hpack_starts_with_status_200(f->payload, f->length)) {
                return TSNODE_ERR_NETWORK;
            }
            if (f->flags & H2_FLAG_END_STREAM) rc->done = true;
            return TSNODE_OK;
        }
        /* Trailers tras DATA: solo válidos si cierran el stream. */
        if (f->flags & H2_FLAG_END_STREAM) {
            rc->done = true;
            return TSNODE_OK;
        }
        return TSNODE_ERR_NETWORK;

    default:
        /* RST_STREAM, PUSH_PROMISE, CONTINUATION, tipos desconocidos:
         * fail-closed (ADR-0009 D1/D3). */
        return TSNODE_ERR_NETWORK;
    }
}

tsnode_err_t h2_client_start(h2_conn_t *h, const h2_io_t *io)
{
    if (h == NULL || io == NULL || io->send_bytes == NULL ||
        io->recv_record == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    memset(h, 0, sizeof(*h));
    h->io = *io;
    h->next_stream_id = 1;

    /* Preface (exactamente 24 bytes) + SETTINGS inicial. */
    uint8_t hello[sizeof(H2_CLIENT_PREFACE) - 1 + H2_HEADER_LEN +
                  SETTINGS_PAYLOAD_LEN];
    memcpy(hello, H2_CLIENT_PREFACE, sizeof(H2_CLIENT_PREFACE) - 1);
    put_frame_header(hello + (sizeof(H2_CLIENT_PREFACE) - 1),
                     H2_FRAME_SETTINGS, 0, 0, SETTINGS_PAYLOAD_LEN);
    hello[sizeof(H2_CLIENT_PREFACE) - 1 + H2_HEADER_LEN] =
        (uint8_t)(H2_SETTINGS_ENABLE_PUSH_ID >> 8);
    hello[sizeof(H2_CLIENT_PREFACE) - 1 + H2_HEADER_LEN + 1] =
        (uint8_t)H2_SETTINGS_ENABLE_PUSH_ID;
    hello[sizeof(H2_CLIENT_PREFACE) - 1 + H2_HEADER_LEN + 2] =
        (uint8_t)(H2_SETTINGS_ENABLE_PUSH_VAL >> 24);
    hello[sizeof(H2_CLIENT_PREFACE) - 1 + H2_HEADER_LEN + 3] =
        (uint8_t)(H2_SETTINGS_ENABLE_PUSH_VAL >> 16);
    hello[sizeof(H2_CLIENT_PREFACE) - 1 + H2_HEADER_LEN + 4] =
        (uint8_t)(H2_SETTINGS_ENABLE_PUSH_VAL >> 8);
    hello[sizeof(H2_CLIENT_PREFACE) - 1 + H2_HEADER_LEN + 5] =
        (uint8_t)H2_SETTINGS_ENABLE_PUSH_VAL;

    tsnode_err_t err = send_all(&h->io, hello, sizeof(hello));
    if (err != TSNODE_OK) return err;

    /* Esperar el SETTINGS inicial del par, ackearlo. Frames de control
     * intercalados antes se procesan normal (el server suele mandar su
     * SETTINGS apenas acepta el upgrade, incluso antes de nuestro preface). */
    for (;;) {
        h2_frame_view_t f;
        err = peek_frame(h, &f);
        if (err != TSNODE_OK) return err;

        if (f.type == H2_FRAME_SETTINGS && !(f.flags & H2_FLAG_ACK)) {
            err = send_settings_ack(h);
            if (err != TSNODE_OK) return err;
            consume_frame(h, &f);
            break;
        }
        if (f.type == H2_FRAME_SETTINGS || f.type == H2_FRAME_PING ||
            f.type == H2_FRAME_WINDOW_UPDATE || f.type == H2_FRAME_PRIORITY) {
            err = handle_frame(h, &f, NULL);
            if (err != TSNODE_OK) return err;
            consume_frame(h, &f);
            continue;
        }
        return TSNODE_ERR_NETWORK;
    }

    h->started = true;
    return TSNODE_OK;
}

tsnode_err_t h2_post(h2_conn_t *h, const char *authority, const char *path,
                     const char *lb_value, const uint8_t *body,
                     size_t body_len, uint8_t *resp, size_t resp_cap,
                     size_t *resp_len)
{
    /* max_silent_pings=0: cualquier timeout de la capa de registros se
     * propaga como error, exactamente el comportamiento histórico de
     * h2_post (fail-closed). */
    return h2_post_keepalive(h, authority, path, lb_value, body, body_len,
                             resp, resp_cap, resp_len, 0);
}

tsnode_err_t h2_post_keepalive(h2_conn_t *h, const char *authority,
                               const char *path, const char *lb_value,
                               const uint8_t *body, size_t body_len,
                               uint8_t *resp, size_t resp_cap,
                               size_t *resp_len, uint32_t max_silent_pings)
{
    if (h == NULL || !h->started || authority == NULL || path == NULL ||
        body == NULL || resp == NULL || resp_len == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    /* Un solo frame DATA por diseño v1 (los bodies register/map son chicos);
     * bodies mayores exigen chunking + flow control que aún no implementamos
     * (ADR-0009 D3). */
    if (body_len > H2_MAX_FRAME_PAYLOAD) return TSNODE_ERR_INVALID_ARG;

    uint32_t stream_id = h->next_stream_id;
    h->next_stream_id += 2;

    /* HEADERS + bloque HPACK (calza holgado en ~350 bytes reales). */
    uint8_t hdr_block[512];
    size_t hdr_block_len;
    tsnode_err_t err = h2_build_request_headers(hdr_block, sizeof(hdr_block),
                                                 authority, path, lb_value,
                                                 &hdr_block_len);
    if (err != TSNODE_OK) return err;

    uint8_t head_frame[H2_HEADER_LEN + sizeof(hdr_block)];
    put_frame_header(head_frame, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS,
                     stream_id, (uint32_t)hdr_block_len);
    memcpy(head_frame + H2_HEADER_LEN, hdr_block, hdr_block_len);
    err = send_all(&h->io, head_frame, H2_HEADER_LEN + hdr_block_len);
    if (err != TSNODE_OK) return err;

    /* DATA con END_STREAM. */
    uint8_t data_hdr[H2_HEADER_LEN];
    put_frame_header(data_hdr, H2_FRAME_DATA, H2_FLAG_END_STREAM, stream_id,
                     (uint32_t)body_len);
    err = send_all(&h->io, data_hdr, sizeof(data_hdr));
    if (err != TSNODE_OK) return err;
    err = send_all(&h->io, body, body_len);
    if (err != TSNODE_OK) return err;

    h2_resp_ctx_t rc = {
        .resp = resp,
        .resp_cap = resp_cap,
        .resp_len = 0,
        .req_stream = stream_id,
        .seen_headers = false,
        .done = false,
    };

    /* Keepalive inline durante el long-poll (ADR-0020): un timeout de la
     * capa de registros (recv timeout configurado por el caller) dispara un
     * PING fire-and-forget en lugar de fallar, manteniendo así tráfico
     * saliente regular y el mapping NAT/firewall vivo. Contador de silencio:
     * si tras max_silent_pings timeouts consecutivos NO llegó ningún frame
     * (ni ACK a nuestros PINGs, ni DATA, ni SETTINGS), la conexión está
     * muerta en half-open → NETWORK (fail-closed, detección acotada). Un par
     * sano ACKea cada PING (RFC 7540 §6.7) y jamás alcanza el límite. */
    uint32_t silent_pings = 0;
    while (!rc.done) {
        h2_frame_view_t f;
        err = peek_frame(h, &f);
        if (err == TSNODE_ERR_TIMEOUT) {
            if (silent_pings >= max_silent_pings) {
                return TSNODE_ERR_NETWORK;
            }
            err = h2_ping_send(h);
            if (err != TSNODE_OK) return err;
            silent_pings++;
            continue;
        }
        if (err != TSNODE_OK) return err;
        err = handle_frame(h, &f, &rc);
        if (err != TSNODE_OK) return err;
        consume_frame(h, &f);
        /* Cualquier frame recibido (= algo llegó del par) despeja el
         * contador de silencio. */
        silent_pings = 0;
    }

    *resp_len = rc.resp_len;
    return TSNODE_OK;
}

tsnode_err_t h2_post_stream(h2_conn_t *h, const char *authority,
                            const char *path, const char *lb_value,
                            const uint8_t *body, size_t body_len,
                            tsnode_err_t (*on_data)(const uint8_t *data,
                                                    size_t len, void *ctx),
                            void *on_data_ctx, uint32_t max_silent_pings)
{
    if (h == NULL || !h->started || authority == NULL || path == NULL ||
        body == NULL || on_data == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (body_len > H2_MAX_FRAME_PAYLOAD) return TSNODE_ERR_INVALID_ARG;

    uint32_t stream_id = h->next_stream_id;
    h->next_stream_id += 2;

    /* HEADERS + bloque HPACK (calza holgado en ~350 bytes reales). */
    uint8_t hdr_block[512];
    size_t hdr_block_len;
    tsnode_err_t err = h2_build_request_headers(hdr_block, sizeof(hdr_block),
                                                 authority, path, lb_value,
                                                 &hdr_block_len);
    if (err != TSNODE_OK) return err;

    uint8_t head_frame[H2_HEADER_LEN + sizeof(hdr_block)];
    put_frame_header(head_frame, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS,
                     stream_id, (uint32_t)hdr_block_len);
    memcpy(head_frame + H2_HEADER_LEN, hdr_block, hdr_block_len);
    err = send_all(&h->io, head_frame, H2_HEADER_LEN + hdr_block_len);
    if (err != TSNODE_OK) return err;

    /* DATA con END_STREAM: el stream queda abierto del lado del server
     * (envía DATA continuos hasta que cierra él con RST/GOAWAY). */
    uint8_t data_hdr[H2_HEADER_LEN];
    put_frame_header(data_hdr, H2_FRAME_DATA, H2_FLAG_END_STREAM, stream_id,
                     (uint32_t)body_len);
    err = send_all(&h->io, data_hdr, sizeof(data_hdr));
    if (err != TSNODE_OK) return err;
    err = send_all(&h->io, body, body_len);
    if (err != TSNODE_OK) return err;

    h2_resp_ctx_t rc = {
        .resp = NULL,
        .resp_cap = 0,
        .resp_len = 0,
        .req_stream = stream_id,
        .seen_headers = false,
        .done = false,
        .on_data = on_data,
        .on_data_ctx = on_data_ctx,
    };

    /* Mismo loop de keepalive inline que h2_post_keepalive (ADR-0020): un
     * timeout de la capa de registros dispara un PING fire-and-forget; si
     * tras max_silent_pings timeouts consecutivos no llegó NINGÚN frame el
     * stream está muerto en half-open → NETWORK (fail-closed ≤100s). El
     * server sano manda keepalives ~1/min y ACKea cada PING. */
    uint32_t silent_pings = 0;
    while (!rc.done) {
        h2_frame_view_t f;
        err = peek_frame(h, &f);
        if (err == TSNODE_ERR_TIMEOUT) {
            if (silent_pings >= max_silent_pings) {
                return TSNODE_ERR_NETWORK;
            }
            err = h2_ping_send(h);
            if (err != TSNODE_OK) return err;
            silent_pings++;
            continue;
        }
        if (err != TSNODE_OK) return err;
        err = handle_frame(h, &f, &rc);
        if (err != TSNODE_OK) return err;
        consume_frame(h, &f);
        /* Cualquier frame recibido (= algo llegó del par) despeja el
         * contador de silencio. */
        silent_pings = 0;
    }

    return TSNODE_OK;
}

tsnode_err_t h2_ping_send(h2_conn_t *h)
{
    if (h == NULL || !h->started) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* Payload opaco de 8 bytes (RFC 7540 §6.7). No es criptográfico: sirve
     * para reconocer el ACK de *nuestro* PING, ya que el par lo repite tal
     * cual en la respuesta con ACK. Mantenerlo fijo por instancia de h2. */
    const uint8_t payload[8] = { 0x74, 0x73, 0x6e, 0x6f, 0x64, 0x65, 0x50, 0x31 };

    uint8_t hdr[H2_HEADER_LEN];
    put_frame_header(hdr, H2_FRAME_PING, 0, 0, 8);
    tsnode_err_t err = send_all(&h->io, hdr, sizeof(hdr));
    if (err != TSNODE_OK) return err;
    return send_all(&h->io, payload, sizeof(payload));
}

tsnode_err_t h2_ping(h2_conn_t *h)
{
    if (h == NULL || !h->started) {
        return TSNODE_ERR_INVALID_ARG;
    }

    tsnode_err_t err = h2_ping_send(h);
    if (err != TSNODE_OK) return err;

    /* Payload para comparar el ACK: el mismo que h2_ping_send acaba de
     * enviar (payload opaco fijo). */
    const uint8_t payload[8] = { 0x74, 0x73, 0x6e, 0x6f, 0x64, 0x65, 0x50, 0x31 };

    /* Esperar el ACK del par. Los timeouts llegan de la capa de registros
     * (SO_RCVTIMEO del port): no bloquea más que una lectura normal. */
    for (;;) {
        h2_frame_view_t f;
        err = peek_frame(h, &f);
        if (err != TSNODE_OK) return err;

        if (f.type == H2_FRAME_PING) {
            if (f.length != 8 || f.stream_id != 0) {
                return TSNODE_ERR_NETWORK;
            }
            if (f.flags & H2_FLAG_ACK) {
                /* ACK a nuestro PING (payload repetido): éxito. Un ACK con
                 * payload distinto es un peer malformado; lo descartamos y
                 * seguimos esperando el nuestro (sin daño ni riesgo). */
                if (memcmp(f.payload, payload, 8) == 0) {
                    consume_frame(h, &f);
                    return TSNODE_OK;
                }
                consume_frame(h, &f);
                continue;
            }
            /* Un PING del par (sin ACK): respondemos PONG como manda el spec
             * (RFC 7540 §6.7) y seguimos esperando nuestro ACK. */
            err = send_pong(h, f.payload, f.length);
            consume_frame(h, &f);
            if (err != TSNODE_OK) return err;
            continue;
        }

        /* Frames de control inofensivos durante el keepalive. */
        if (f.type == H2_FRAME_SETTINGS) {
            err = handle_frame(h, &f, NULL);
            consume_frame(h, &f);
            if (err != TSNODE_OK) return err;
            continue;
        }
        if (f.type == H2_FRAME_WINDOW_UPDATE || f.type == H2_FRAME_PRIORITY) {
            consume_frame(h, &f);
            continue;
        }

        /* GOAWAY, DATA fuera de stream, CONTINUATION o frames desconocidos:
         * sin recovery en este subset, fail-closed (ADR-0009 D1/D3). */
        return TSNODE_ERR_NETWORK;
    }
}
