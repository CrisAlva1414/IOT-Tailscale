/*
 * Netmap: MapRequest/MapResponse sobre ts2021 (ADR-0008).
 *
 * POST /machine/map en modo polling (Stream=false).
 * Parser mínimo: extrae solo lo que el data plane necesita.
 *
 * Este archivo es C puro: sin headers de plataforma (ADR-0006).
 */

#ifndef TSNODE_MAP_H
#define TSNODE_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tsnode_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum peers we track (ESP32 memory constraint) */
#define TSNODE_MAP_MAX_PEERS 16

/* Maximum endpoints per peer (matches disco layer).
 * 16: peers con muchos endpoints (público + múltiples docker 172.x + LAN
 * privada) necesitan alcanzar el endpoint LAN que viene al final de la lista
 * (HW 2026-09-03: LAN del notebook en índice 8-15). Cap grande pero acotado;
 * ~16*18B = 288B/peer, borde aceptable en ESP32. */
#define TSNODE_MAP_MAX_ENDPOINTS 16

/* STUN server from DERP map */
typedef struct {
    uint32_t ip;
    uint16_t port;
    bool valid;
} tsnode_map_stun_t;

/* Parsed peer info (minimal subset of tailcfg.Node for data plane) */
typedef struct {
    uint8_t key[32];          /* WireGuard public key */
    char    host_name[64];    /* peer hostname */
    char    tailscale_ip[16]; /* "100.x.y.z" (first AllowedIP) */
    uint32_t allowed_ip;      /* host byte order, e.g. 0x64000001 = 100.0.0.1 */
    uint32_t allowed_mask;    /* host byte order, e.g. 0xFFFFFFFF = /32 */
    /* Multiple endpoints per peer (LAN private, public, etc.) */
    struct {
        char    ip[16];
        uint16_t port;
    } endpoints[TSNODE_MAP_MAX_ENDPOINTS];
    uint8_t  n_endpoints;     /* number of valid endpoints (0 = unreachable) */
    uint8_t  preshared_key[32]; /* PSK (all-zero = none) */
    uint8_t  disco_key[32];   /* Disco public key (all-zero = none) */
    bool     online;          /* currently connected */
} tsnode_map_peer_t;

/* Parsed netmap (minimal) */
typedef struct {
    tsnode_map_peer_t peers[TSNODE_MAP_MAX_PEERS];
    uint8_t  peer_count;
    char     self_ip[16];       /* our 100.x.y.z */
    uint8_t  self_node_key[32]; /* our node public key */
    tsnode_map_stun_t stun;    /* first STUN server from DERPMap */
    bool     dns_enabled;
} tsnode_map_netmap_t;

/*
 * Build MapRequest JSON into buf.
 * capability_version: Tailscale CurrentCapabilityVersion (145).
 * stream: false for polling mode (one response per request).
 * disco_key: our disco public key (32 bytes, zeroed if unused).
 * hostname: our node hostname.
 * endpoint_ip: our WireGuard UDP endpoint IP (0 = omit Endpoints).
 * endpoint_port: our WireGuard UDP listen port.
 */
tsnode_err_t tsnode_map_build_request(char *buf, size_t buf_size,
                                      size_t *out_len,
                                      const uint8_t node_key_pub[32],
                                      const uint8_t disco_key[32],
                                      const char *hostname,
                                      uint32_t capability_version,
                                      bool stream,
                                      uint32_t endpoint_ip,
                                      uint16_t endpoint_port);

/*
 * Parse MapResponse JSON into netmap (reemplazo total del contenido).
 * Minimal parser: extracts peers, self IP, node key.
 * Ignores DERP map, DNS config, and other fields.
 *
 * MapResponse can be large; json_len may be the full response.
 */
tsnode_err_t tsnode_map_parse_response(tsnode_map_netmap_t *netmap,
                                        const char *json, size_t json_len);

/*
 * Parsea el framing de tsp sobre /machine/map: [u32 LE length][payload]
 * (control/tsp/map.go). Sin "Compress" en nuestro MapRequest el payload es
 * JSON crudo; si llega con firma zstd retornamos TSNODE_ERR_NOT_IMPLEMENTED
 * (sería bug nuestro haber pedido compresión — ADR-0009 D2).
 *
 * json_out apunta DENTRO de wire (sin copia). Validación fail-closed:
 * length declarado debe coincidir exactamente con wire_len - 4.
 */
tsnode_err_t tsnode_map_parse_framed(const uint8_t *wire, size_t wire_len,
                                      const uint8_t **json_out,
                                      size_t *json_len_out);

/* ---- Streaming (ADR-0021) ---- */

/* Techo del buffer del splitter de stream. Un mensaje del stream (netmap
 * completo / delta) NO debe exceder esto: el length declarado por el par se
 * valida contra este cap fijo en compile time antes de acumular (input
 * hostil, AGENTS.md §4). 32 KiB == MAP_RESPONSE_BUF_SIZE histórico. */
#define TSNODE_MAP_STREAM_BUF 32768u

/* Máximo de peers removidos reportables en una llamada a
 * tsnode_map_apply_response (un PeersRemoved puede listar muchos; el array
 * de salida es del call site y este es su techo documentado). */
#define TSNODE_MAP_MAX_REMOVED TSNODE_MAP_MAX_PEERS

/* Splitter de mensajes del stream de /machine/map. Acumula bytes a través
 * de múltiples frames DATA del transporte (h2) y entrega los mensajes
 * completos uno a uno. El splitter vive en memoria estática del caller y la
 * referencia valida hasta la siguiente llamada feed()/next() (el mensaje
 * entregado apunta dentro de st->buf; su descarte se posterga a la próxima
 * llamada justamente para no invalidar la referencia antes de tiempo). */
typedef struct {
    uint8_t buf[TSNODE_MAP_STREAM_BUF];
    size_t len;       /* bytes válidos en buf */
    bool have_len;    /* ya leímos el u32 LE del mensaje en curso */
    uint32_t msg_len; /* length declarado del mensaje en curso */
    bool pending;     /* mensaje completo ya entregado, falta consumirlo */
} tsnode_map_stream_t;

/*
 * (Re)inicializa el splitter para un stream nuevo. Despeja cualquier resto
 * del stream anterior (fail-closed ante bytes viejos mezclados).
 */
void tsnode_map_stream_init(tsnode_map_stream_t *st);

/*
 * Acumula bytes recibidos. Puede completar cero o más mensajes (llamar a
 * next() hasta que diga que no hay). Falla closed (TSNODE_ERR_NETWORK /
 * TSNODE_ERR_NO_MEMORY) si un mensaje declarado excede el buffer o si la
 * trama es inválida.
 */
tsnode_err_t tsnode_map_stream_feed(tsnode_map_stream_t *st,
                                    const uint8_t *data, size_t len);

/*
 * Si hay un mensaje completo disponible, entrega el puntero (dentro de
 * st->buf, válido hasta la próxima feed()/next()) y lo consume del buffer.
 * *has_msg=false cuando falta data (sin consumir nada).
 */
tsnode_err_t tsnode_map_stream_next(tsnode_map_stream_t *st,
                                    const uint8_t **msg_out,
                                    size_t *msg_len_out, bool *has_msg);

/*
 * Aplica un mensaje del stream al netmap vivo (ADR-0021).
 *
 * Mensajes de netmap completo ("Peers" presente) reemplazan TODO el netmap
 * (*is_full=true). Mensajes delta ("PeersChanged"/"PeersRemoved"/
 * "OnlineChange") mutan el netmap existente (*is_full=false). KeepAlive es
 * no-op (is_full=false, no cambia nada).
 *
 * removed keys (raw 32 bytes): las claves de los peers removidos por
 * "PeersRemoved", para que el caller limpie el data plane (WG + disco).
 * Puede ser NULL si al caller no le importan; n_removed_out opcional.
 *
 * *peers_updated: true si algo cambió en la lista de peers (agregado,
 * actualizado o removido) — el caller re-aplica WG/disco.
 */
tsnode_err_t tsnode_map_apply_response(tsnode_map_netmap_t *netmap,
                                       const char *json, size_t json_len,
                                       bool *is_full, bool *peers_updated,
                                       uint8_t removed[][32], int *n_removed);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_MAP_H */
