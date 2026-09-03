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

/* Maximum endpoints per peer (matches disco layer) */
#define TSNODE_MAP_MAX_ENDPOINTS 4

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
 * Parse MapResponse JSON into netmap.
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

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_MAP_H */
