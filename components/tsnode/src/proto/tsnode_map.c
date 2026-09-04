/*
 * Netmap: MapRequest/MapResponse (ADR-0008).
 *
 * Minimal parser — extracts only what the ESP32 data plane needs.
 * No heap allocation. Scans JSON linearly for known field patterns.
 *
 * C puro: sin headers de plataforma (ADR-0006). Sin logging: el caller
 * agrega contexto con los resultados parseados (los JSON de respuesta
 * pueden contener datos de la tailnet que no deben ir a log por defecto).
 */

#include "tsnode_map.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Hex decoding ---- */

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(uint8_t *out, size_t out_len, const char *hex,
                        size_t hex_len)
{
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_digit(hex[i * 2]);
        int lo = hex_digit(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* ---- MapRequest builder ---- */

tsnode_err_t tsnode_map_build_request(char *buf, size_t buf_size,
                                      size_t *out_len,
                                      const uint8_t node_key_pub[32],
                                      const uint8_t disco_key[32],
                                      const char *hostname,
                                      uint32_t capability_version,
                                      bool stream,
                                      uint32_t endpoint_ip,
                                      uint16_t endpoint_port)
{
    if (buf == NULL || buf_size == 0 || out_len == NULL || node_key_pub == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    char nk_hex[65], dk_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(nk_hex + i * 2, 3, "%02x", node_key_pub[i]);
        snprintf(dk_hex + i * 2, 3, "%02x", disco_key[i]);
    }
    nk_hex[64] = '\0';
    dk_hex[64] = '\0';

    size_t pos = 0;
    int n;

    buf[pos++] = '{';

    n = snprintf(buf + pos, buf_size - pos, "\"Version\":%" PRIu32, capability_version);
    if (n < 0 || (size_t)n >= buf_size - pos) return TSNODE_ERR_NO_MEMORY;
    pos += n;

    buf[pos++] = ',';
    n = snprintf(buf + pos, buf_size - pos,
                 "\"NodeKey\":\"nodekey:%s\"", nk_hex);
    if (n < 0 || (size_t)n >= buf_size - pos) return TSNODE_ERR_NO_MEMORY;
    pos += n;

    buf[pos++] = ',';
    n = snprintf(buf + pos, buf_size - pos,
                 "\"DiscoKey\":\"discokey:%s\"", dk_hex);
    if (n < 0 || (size_t)n >= buf_size - pos) return TSNODE_ERR_NO_MEMORY;
    pos += n;

    buf[pos++] = ',';
    n = snprintf(buf + pos, buf_size - pos,
                 "\"Stream\":%s", stream ? "true" : "false");
    if (n < 0 || (size_t)n >= buf_size - pos) return TSNODE_ERR_NO_MEMORY;
    pos += n;

    if (hostname != NULL && hostname[0] != '\0') {
        buf[pos++] = ',';
        n = snprintf(buf + pos, buf_size - pos,
                     "\"Hostinfo\":{\"OS\":\"linux\",\"Hostname\":\"%s\"}",
                     hostname);
        if (n < 0 || (size_t)n >= buf_size - pos) return TSNODE_ERR_NO_MEMORY;
        pos += n;
    }

    /* Endpoints: WireGuard UDP endpoint (IP:port) */
    if (endpoint_ip != 0 && endpoint_port != 0) {
        buf[pos++] = ',';
        n = snprintf(buf + pos, buf_size - pos,
                     "\"Endpoints\":[\"%lu.%lu.%lu.%lu:%u\"]",
                     (unsigned long)((endpoint_ip >> 24) & 0xFF),
                     (unsigned long)((endpoint_ip >> 16) & 0xFF),
                     (unsigned long)((endpoint_ip >> 8) & 0xFF),
                     (unsigned long)(endpoint_ip & 0xFF),
                     (unsigned)endpoint_port);
        if (n < 0 || (size_t)n >= buf_size - pos) return TSNODE_ERR_NO_MEMORY;
        pos += n;
    }

    buf[pos++] = '}';
    buf[pos] = '\0';

    *out_len = pos;
    return TSNODE_OK;
}

/* ---- MapResponse framing (control/tsp/map.go) ---- */

/* Firma de frames zstd: pedimos JSON crudo (sin Compress), verlo acá
 * significa que el par violó lo acordado o que cambió el protocolo. */
static const uint8_t ZSTD_MAGIC[4] = {0x28, 0xB5, 0x2F, 0xFD};

tsnode_err_t tsnode_map_parse_framed(const uint8_t *wire, size_t wire_len,
                                      const uint8_t **json_out,
                                      size_t *json_len_out)
{
    if (wire == NULL || json_out == NULL || json_len_out == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }
    if (wire_len < 4) {
        return TSNODE_ERR_NETWORK;
    }

    uint32_t declared = (uint32_t)wire[0] |
                        ((uint32_t)wire[1] << 8) |
                        ((uint32_t)wire[2] << 16) |
                        ((uint32_t)wire[3] << 24);

    /* Input hostil por defecto: el length declarado nunca se usa para
     * indexar; solo se valida contra el tamaño real recibido. */
    if ((size_t)declared != wire_len - 4) {
        return TSNODE_ERR_NETWORK;
    }

    if (declared >= sizeof(ZSTD_MAGIC) &&
        memcmp(wire + 4, ZSTD_MAGIC, sizeof(ZSTD_MAGIC)) == 0) {
        return TSNODE_ERR_NOT_IMPLEMENTED;
    }

    *json_out = wire + 4;
    *json_len_out = declared;
    return TSNODE_OK;
}

/* ---- MapResponse parser ---- */

/* Find a string value for a JSON key. Returns pointer past closing quote,
 * or NULL if not found. Does NOT handle escaped quotes. */
static const char *find_json_string(const char *json, const char *key,
                                    char *value_out, size_t value_out_len)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *found = strstr(json, pattern);
    if (found == NULL) return NULL;

    found += strlen(pattern);
    /* Skip whitespace and colon */
    while (*found == ' ' || *found == ':') found++;
    if (*found != '"') return NULL;
    found++; /* skip opening quote */

    const char *end = strchr(found, '"');
    if (end == NULL) return NULL;

    size_t len = (size_t)(end - found);
    if (len >= value_out_len) len = value_out_len - 1;
    memcpy(value_out, found, len);
    value_out[len] = '\0';

    return end + 1;
}

/* Find next occurrence of "Key":"nodekey:..." and extract the 32-byte key */
static const char *find_next_node_key(const char *search_from,
                                      uint8_t key_out[32])
{
    const char *marker = "\"Key\":\"nodekey:";
    const char *found = strstr(search_from, marker);
    if (found == NULL) return NULL;

    found += strlen(marker);
    if (strlen(found) < 64) return NULL;

    if (hex_to_bytes(key_out, 32, found, 64) != 0) {
        return NULL;
    }
    return found + 64;
}

/* Find "Self" object and extract first "100.x.y.z/32" from Addrs array.
 * Tailscale MapResponse format: "Self":{"Addrs":["100.x.y.z/32"],...}
 * Returns true if a valid IP was extracted. */
static bool find_self_addrs(const char *json, char *ip_out, size_t ip_out_len)
{
    const char *self_marker = "\"Self\":{";
    const char *self_start = strstr(json, self_marker);
    if (self_start == NULL) return false;

    /* Find Addrs array within Self object (bounded search) */
    const char *addrs_marker = "\"Addrs\":[";
    const char *addrs = strstr(self_start, addrs_marker);
    if (addrs == NULL) return false;

    /* Ensure Addrs is within Self object (not in a peer) */
    const char *peers_marker = "\"Peers\":[";
    const char *peers = strstr(json, peers_marker);
    if (peers != NULL && addrs > peers) return false;

    /* Find first "100." in Addrs array */
    const char *ip_start = strstr(addrs, "\"100.");
    if (ip_start == NULL) return false;

    /* Skip opening quote */
    ip_start++;

    /* Extract IP string (stop at quote, comma, or slash for CIDR) */
    size_t len = 0;
    const char *p = ip_start;
    while (*p && *p != '"' && *p != ',' && *p != '/' && len < ip_out_len - 1) {
        ip_out[len++] = *p++;
    }
    ip_out[len] = '\0';

    return len > 0;
}

tsnode_err_t tsnode_map_parse_response(tsnode_map_netmap_t *netmap,
                                        const char *json, size_t json_len)
{
    if (netmap == NULL || json == NULL || json_len == 0) {
        return TSNODE_ERR_INVALID_ARG;
    }
    /* El escaneo usa strstr/strchr: exige buffer NUL-terminado (el caller
     * garantiza espacio para el NUL al pedir la respuesta a h2). json_len
     * valida no-vacío acá; los límites reales los pone el NUL. */

    memset(netmap, 0, sizeof(*netmap));

    /* Extract Self.Key */
    find_next_node_key(json, netmap->self_node_key);

    /* Extract self IP from Self.Addrs array (Tailscale MapResponse format).
     * Falls back to scanning AllowedIPs if Self.Addrs not found. */
    if (!find_self_addrs(json, netmap->self_ip, sizeof(netmap->self_ip))) {
        /* Fallback: scan for "100." within "AllowedIPs" context */
        const char *allowed = strstr(json, "\"AllowedIPs\"");
        if (allowed != NULL) {
            const char *ip = strstr(allowed, "\"100.");
            if (ip != NULL) {
                ip++; /* skip quote */
                size_t len = 0;
                const char *p = ip;
                while (*p && *p != '"' && *p != '/' && len < sizeof(netmap->self_ip) - 1) {
                    netmap->self_ip[len++] = *p++;
                }
                netmap->self_ip[len] = '\0';
            }
        }
    }

    /* Parse Peers array */
    const char *peers_marker = "\"Peers\":[";
    const char *peers_start = strstr(json, peers_marker);
    if (peers_start != NULL) {
        peers_start += strlen(peers_marker);

        /* Scan for peer entries.
         *
         * Cada peer del array `Peers` está anclado por su `"Key":"nodekey:`.
         * Los campos de un peer (Hostname/AllowedIPs/Endpoints/DiscoKey/PSK)
         * aparecen TODOS después de su nodekey y ANTES del nodekey del peer
         * siguiente. Usamos el nodekey de cada peer como ancla y acotamos toda
         * búsqueda de campos a la ventana [nodekey_actual, nodekey_siguiente).
         * Esto evita el desync histórico donde `strchr('{')` caía en un `{`
         * anidado (p.ej. dentro de Hostinfo) y los campos se desalineaban un
         * peer (bug HW 2026-09-03). */
        const char *scan = peers_start;
        while (scan != NULL && netmap->peer_count < TSNODE_MAP_MAX_PEERS) {
            /* Ancla: nodekey del peer actual */
            const char *key_marker =
                strstr(scan, "\"Key\":\"nodekey:");
            if (key_marker == NULL) break;

            /* Límite: nodekey del peer siguiente (o fin de cadena) */
            const char *next_key = strstr(key_marker + 1, "\"Key\":\"nodekey:");
            const char *peer_end = (next_key != NULL)
                                       ? next_key
                                       : key_marker + strlen(key_marker);

            tsnode_map_peer_t *peer = &netmap->peers[netmap->peer_count];

            /* Peer Key */
            const char *hex = key_marker + strlen("\"Key\":\"nodekey:");
            if (strlen(hex) < 64) break;
            if (hex_to_bytes(peer->key, 32, hex, 64) != 0) break;

            /* Find Hostname (in HostInfo sub-object), acotado a este peer */
            const char *hn = NULL;
            {
                const char *hit = strstr(key_marker, "\"Hostname\"");
                if (hit != NULL && hit < peer_end) hn = hit;
            }
            if (hn != NULL) {
                find_json_string(hn, "Hostname",
                                 peer->host_name, sizeof(peer->host_name));
            }

            /* Find AllowedIPs — parse first CIDR entry (e.g. "100.64.0.1/32") */
            const char *allowed = NULL;
            {
                const char *hit = strstr(key_marker, "\"AllowedIPs\"");
                if (hit != NULL && hit < peer_end) allowed = hit;
            }
            if (allowed != NULL) {
                const char *ip = strstr(allowed, "\"100.");
                if (ip != NULL) {
                    ip++; /* skip quote */
                    /* Parse dotted-decimal IP */
                    uint32_t a = 0, b = 0, c = 0, d = 0;
                    int slash_pos = 0;
                    int parsed = sscanf(ip, "%" SCNu32 ".%" SCNu32 ".%" SCNu32 ".%" SCNu32 "/%d",
                                        &a, &b, &c, &d, &slash_pos);
                    if (parsed >= 4) {
                        peer->allowed_ip = (a << 24) | (b << 16) | (c << 8) | d;
                        /* Convert IP to string for display */
                        snprintf(peer->tailscale_ip, sizeof(peer->tailscale_ip),
                                 "%u.%u.%u.%u", (unsigned)a, (unsigned)b,
                                 (unsigned)c, (unsigned)d);
                        /* CIDR to mask: /32 -> 0xFFFFFFFF, /24 -> 0xFFFFFF00, etc. */
                        if (parsed == 5 && slash_pos >= 0 && slash_pos <= 32) {
                            peer->allowed_mask = (slash_pos == 0) ? 0u :
                                (UINT32_MAX << (32 - (uint32_t)slash_pos));
                        } else {
                            peer->allowed_mask = UINT32_MAX; /* default /32 */
                        }
                    }
                }
            }

            /* Find Endpoints — format: "Endpoints":["ip:port",...]
             * Parse endpoints in order hasta TSNODE_MAP_MAX_ENDPOINTS. El
             * primer endpoint (endpoints[0]) lo usa el handshake WG de
             * arranque; disco (por debajo) prueba TODOS los endpoints, así
             * que la selección fina de ruta LAN vs pública la resuelve disco,
             * no este parser. */
            const char *ep = NULL;
            {
                const char *hit = strstr(key_marker, "\"Endpoints\"");
                if (hit != NULL && hit < peer_end) ep = hit;
            }
            if (ep != NULL) {
                const char *bracket = strchr(ep + 12, '[');
                if (bracket != NULL) {
                    /* Acotar el barrido al array Endpoints (hasta su `]` de
                     * cierre). Crítico: sin esto, tras el último endpoint el
                     * strchr('"') se escapaba hacia el peer siguiente y su
                     * "Key"/AllowedIPs se parseaban como endpoints falsos
                     * (desync HW 2026-09-03). */
                    const char *close = strchr(bracket, ']');
                    const char *scan_ep = bracket + 1;
                    while (peer->n_endpoints < TSNODE_MAP_MAX_ENDPOINTS &&
                           close != NULL && scan_ep < close) {
                        const char *q = strchr(scan_ep, '"');
                        if (q == NULL || q >= close) break;
                        q++; /* skip opening quote */
                        /* Copy IP until colon */
                        size_t iplen = 0;
                        while (*q && *q != ':' &&
                               iplen < sizeof(peer->endpoints[0].ip) - 1) {
                            peer->endpoints[peer->n_endpoints].ip[iplen++] = *q++;
                        }
                        peer->endpoints[peer->n_endpoints].ip[iplen] = '\0';
                        /* Parse port after colon */
                        if (*q == ':') {
                            peer->endpoints[peer->n_endpoints].port =
                                (uint16_t)atoi(q + 1);
                        }
                        if (peer->endpoints[peer->n_endpoints].port > 0) {
                            peer->n_endpoints++;
                        }
                        /* Advance past this quoted string */
                        const char *end_q = strchr(q, '"');
                        if (end_q == NULL) break;
                        scan_ep = end_q + 1;
                    }
                }
            }

            /* Find PresharedKey — hex-encoded 32-byte key */
            const char *psk = NULL;
            {
                const char *hit = strstr(key_marker, "\"PresharedKey\"");
                if (hit != NULL && hit < peer_end) psk = hit;
            }
            if (psk != NULL) {
                const char *psk_hex = strchr(psk, '"');
                if (psk_hex != NULL) {
                    psk_hex++; /* skip quote */
                    /* Check for "key:" prefix (Tailscale uses "key:hex") */
                    if (strncmp(psk_hex, "key:", 4) == 0) psk_hex += 4;
                    if (strlen(psk_hex) >= 64) {
                        hex_to_bytes(peer->preshared_key, 32, psk_hex, 64);
                    }
                }
            }

            /* Find DiscoKey — hex-encoded 32-byte key (discokey:hex) */
            const char *dk = NULL;
            {
                const char *hit = strstr(key_marker, "\"DiscoKey\"");
                if (hit != NULL && hit < peer_end) dk = hit;
            }
            if (dk != NULL) {
                /* Skip past the "DiscoKey" key literal to the ':' then value */
                const char *colon =
                    strchr(dk + strlen("\"DiscoKey\""), ':');
                if (colon != NULL) {
                    const char *dk_hex = colon + 1;
                    /* Skip whitespace and opening quote */
                    while (*dk_hex == ' ' || *dk_hex == '\t') dk_hex++;
                    if (*dk_hex == '"') dk_hex++;
                    /* Check for "discokey:" prefix (Tailscale uses "discokey:hex") */
                    if (strncmp(dk_hex, "discokey:", 9) == 0) dk_hex += 9;
                    size_t hlen = 0;
                    uint8_t c;
                    while ((c = (uint8_t)dk_hex[hlen]) != '\0' && c != '"' &&
                           ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                            (c >= 'A' && c <= 'F'))) {
                        hlen++;
                    }
                    if (hlen >= 64) {
                        hex_to_bytes(peer->disco_key, 32, dk_hex, 64);
                    }
                }
            }

            peer->online = (peer->n_endpoints > 0);
            netmap->peer_count++;

            /* Move past this peer's key marker; next iteration finds the
             * next peer anchored by its own nodekey. */
            scan = peer_end;
        }
    }

    /* Parse DERPMap for STUN server.
     * Tailscale MapResponse does NOT have a dedicated "STUNIPv4" field.
     * DERP nodes have "IPv4" which serves as both DERP and STUN endpoint.
     * Find the first DERP node's IPv4 (1234 is the standard STUN port).
     * Also check for explicit STUNIPv4/STUNPort if future versions add it. */
    netmap->stun.valid = false;

    /* Try explicit STUNIPv4 first (future-proof) */
    const char *stun_marker = "\"STUNIPv4\"";
    const char *stun_ip_str = strstr(json, stun_marker);
    if (stun_ip_str != NULL) {
        stun_ip_str += strlen(stun_marker);
        while (*stun_ip_str && *stun_ip_str != '"') stun_ip_str++;
        stun_ip_str++;
        unsigned a, b, c, d;
        if (sscanf(stun_ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            netmap->stun.ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                              ((uint32_t)c << 8) | (uint32_t)d;
            const char *port_marker = "\"STUNPort\"";
            const char *port_str = strstr(stun_ip_str, port_marker);
            if (port_str != NULL) {
                port_str += strlen(port_marker);
                while (*port_str && (*port_str < '0' || *port_str > '9')) port_str++;
                netmap->stun.port = (uint16_t)atoi(port_str);
            }
            if (netmap->stun.port == 0) netmap->stun.port = 3478;
            netmap->stun.valid = true;
        }
    }

    /* Fallback: use first DERP node's IPv4 as STUN server (default port 3478) */
    if (!netmap->stun.valid) {
        const char *ip_marker = "\"IPv4\"";
        const char *ip_str = strstr(json, ip_marker);
        if (ip_str != NULL) {
            ip_str += strlen(ip_marker);
            while (*ip_str && *ip_str != '"') ip_str++;
            ip_str++;
            unsigned a, b, c, d;
            if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                netmap->stun.ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                                  ((uint32_t)c << 8) | (uint32_t)d;
                netmap->stun.port = 3478;
                netmap->stun.valid = true;
            }
        }
    }

    return TSNODE_OK;
}
