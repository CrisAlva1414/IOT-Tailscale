/*
 * Cliente HTTP/2 mínimo sobre un transporte de registros ya cifrado
 * (ADR-0009). El control plane Tailscale habla HTTP/2 dentro del túnel
 * Noise ts2021; sin este layer el servidor descarta la conexión con
 * "bogus greeting" y nunca procesa register/map (verificado empíricamente,
 * sesión 2026-08-23).
 *
 * Subset implementado (fail-closed ante todo lo demás):
 *   - preface + SETTINGS / ACK
 *   - un stream secuencial por request (HEADERS END_HEADERS + DATA END_STREAM)
 *   - HPACK de salida: literal-without-indexing sin Huffman + índices estáticos
 *   - recepción: DATA del stream hasta END_STREAM; SETTINGS/PING/WINDOW_UPDATE;
 *     GOAWAY/RST/CONTINUATION → error
 *
 * Este archivo es C puro: sin headers de plataforma (ADR-0006). El I/O se
 * inyecta vía h2_io_t para poder testear en host sin red ni Noise.
 *
 * Fuente primaria: golang.org/x/net/http2 (framing), tailscale/tailscale
 * control/ts2021/client.go (uso que hace el cliente oficial).
 */

#ifndef TSNODE_H2_H
#define TSNODE_H2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tsnode_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Payload máximo por frame que aceptamos recibir (default spec; nunca
 * advertiseamos más vía SETTINGS). Frames mayores → error fail-closed. */
#define H2_MAX_FRAME_PAYLOAD 16384u

/* Capacidad del acumulador de plaintext entrante: un frame completo
 * (header 9 B + payload máximo). */
#define H2_ACC_CAP ((size_t)(H2_MAX_FRAME_PAYLOAD + 16))

/* Chunk máximo por llamada a send_bytes: calza exactamente en un registro
 * Noise (4096 - 3 header - 16 tag). Debe mantenerse en sync con ts2021.h. */
#define H2_MAX_RECORD_PLAINTEXT 4077u

/* Prefijo HPACK de ":status 200" (indexed header field, tabla estática idx 8).
 * Exigimos que el bloque HEADERS de respuesta empiece con este byte. */
#define H2_HPACK_STATUS_200 0x88u

/*
 * I/O inyectado. En firmware los callbacks cablean a la capa de registros
 * ts2021; en tests host, a colas en memoria.
 */
typedef struct {
    void *ctx;
    /* Envía bytes como uno o más registros cifrados. Retorna TSNODE_OK o
     * error de la capa inferior. */
    tsnode_err_t (*send_bytes)(void *ctx, const uint8_t *data, size_t len);
    /* Obtiene el próximo plaintext descifrado (un registro, hasta cap bytes).
     * *out_len == 0 solo si el par cerró la conexión (EOF limpio). */
    tsnode_err_t (*recv_record)(void *ctx, uint8_t *buf, size_t cap,
                                size_t *out_len);
} h2_io_t;

typedef struct {
    h2_io_t io;
    bool started;          /* preface + SETTINGS enviados y SETTINGS del
                            * servidor recibido/acked */
    uint32_t next_stream_id;
    uint8_t acc[H2_ACC_CAP];
    size_t acc_len;
} h2_conn_t;

/*
 * Inicia la conexión HTTP/2: envía preface + SETTINGS vacío y espera el
 * SETTINGS del servidor respondiendo su ACK. Bloquea vía io.recv_record
 * (los timeouts son los de la capa inferior).
 */
tsnode_err_t h2_client_start(h2_conn_t *h, const h2_io_t *io);

/*
 * POST con body JSON sobre un nuevo stream. La respuesta (concatenación de
 * los DATA frames del stream hasta END_STREAM) se copia a resp (cap
 * resp_cap); overflow → TSNODE_ERR_NO_MEMORY, nunca truncado silencioso.
 *
 * lb_value: valor opcional del header Ts-Lb ("nodekey:<hex>"), NULL si no
 * aplica. authority/path deben ser ASCII corto (≤ 255 bytes cada uno).
 */
tsnode_err_t h2_post(h2_conn_t *h, const char *authority, const char *path,
                     const char *lb_value, const uint8_t *body, size_t body_len,
                     uint8_t *resp, size_t resp_cap, size_t *resp_len);

/*
 * PING keepalive (frame PING, stream 0) con payload opaco fijo de 8 bytes.
 * Propósito (ADR-0009/ADR-0020): mantener viva la conexión HTTP/2/Noise/TCP
 * contra el control plane. El PING viaja como frame h2 dentro del túnel
 * cifrado y refresca el mapping NAT/firewall que de otro modo derriba la
 * conexión tras ~90s de idle.
 *
 * h2_ping_send(): envía el frame PING y retorna — no espera el ACK. Útil para
 * keepalive inline dentro de un long-poll (ADR-0020), donde el loop de
 * recepción consume el ACK del par como un frame normal.
 *
 * h2_ping(): envía el frame y espera el ACK con el mismo payload. Retorna
 * TSNODE_OK al recibir el ACK; en cualquier otro frame/error se propaga el
 * error de la capa inferior (NETWORK por EOF/GOAWAY/fallo de escritura,
 * TIMEOUT si el par no responde dentro del timeout de la capa de registros).
 */
tsnode_err_t h2_ping_send(h2_conn_t *h);
tsnode_err_t h2_ping(h2_conn_t *h);

/*
 * POST igual a h2_post() pero con keepalive inline durante el long-poll
 * (ADR-0020): si el recv de la capa de registros devuelve TSNODE_ERR_TIMEOUT
 * (idle mayor al recv timeout que el CALLER configuró vía la capa inferior),
 * se envía un PING fire-and-forget y se continúa esperando la respuesta, en
 * vez de fallar. Así el long-poll de /machine/map nunca queda en silencio de
 * salida (NAT/firewall) por más de max_silent_pings pings.
 *
 * max_silent_pings: si el par no recibe NINGÚN frame (ni DATA, ni ACK a
 * nuestros PINGs, ni SETTINGS) durante max_silent_pings timeouts consecutivos,
 * la conexión se considera muerta en half-open y se retorna
 * TSNODE_ERR_NETWORK (fail-closed, detección acotada). Un par sano ACKea cada
 * PING (RFC 7540 §6.7) y jamás alcanza el límite.
 */
tsnode_err_t h2_post_keepalive(h2_conn_t *h, const char *authority,
                               const char *path, const char *lb_value,
                               const uint8_t *body, size_t body_len,
                               uint8_t *resp, size_t resp_cap,
                               size_t *resp_len, uint32_t max_silent_pings);

/* Solo para tests: codifica el bloque HPACK del request. Orden fijo:
 * :method POST, :scheme https, :authority, :path, [ts-lb], content-type.
 * Vector de referencia generado contra producción (sesión 2026-08-23). */
tsnode_err_t h2_build_request_headers(uint8_t *buf, size_t cap,
                                      const char *authority, const char *path,
                                      const char *lb_value, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_H2_H */
