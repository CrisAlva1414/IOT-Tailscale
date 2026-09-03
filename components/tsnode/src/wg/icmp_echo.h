/*
 * tsnode-icmp-echo — minimal IPv4 ICMP echo responder (GOAL-5).
 *
 * Responde a paquetes Ping (ICMP echo request) que llegan por el túnel
 * WireGuard descifrado. Es pura transformación de bytes, sin I/O ni heap:
 * el caller entrega el buffer con el paquete IPv4 interno, este módulo lo
 * convierte en el echo reply correspondiente (o lo deja intacto si no es
 * un echo request).
 *
 * Alcance v1 (AGENTS.md §1): IPv4 solamente. No IPv6, no fragmentación
 * propia (el reply tiene la misma longitud que el request, así que no
 * fragmenta). Solo ICMP echo request (type 8) genera respuesta; cualquier
 * otro paquete interno se deja intacto para que el caller lo maneje (en
 * v1: se descarta, no hay TUN).
 *
 * Seguridad: opera sobre datos que ya pasaron la autenticación WireGuard
 * (peers de la tailnet únicamente). Antes de tocar cualquier campo valida
 * longitudes mínimas (input hostil por defecto, AGENTS.md §2.2). El
 * checksum ICMP se verifica en el request ANTES de responder: no se
 * responde a requests con checksum inválido.
 *
 * Pure C11, sin headers de plataforma (ADR-0006).
 */

#ifndef TSNODE_ICMP_ECHO_H
#define TSNODE_ICMP_ECHO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IPv4 header minimum length (no options). We reject packets with IHL
 * options for v1 (size check enforces enough room for ICMP anyway). */
#define TSNODE_ICMP4_MIN_IPHDR 20u
/* ICMP header length (type,code,checksum,id,seq). */
#define TSNODE_ICMP4_HDR_LEN 8u

/*
 * If pkt is IPv4 + ICMP echo REQUEST (type 8), convert it IN PLACE into
 * the matching echo REPLY (type 0): swap src/dst IP, set type 0, recompute
 * ICMP and IPv4 checksums. Returns true if it produced a reply.
 *
 * Returns false if: len < Ethernet-free IPv4+ICMP minimum, not IPv4
 * (version != 4), not ICMP (protocol != 1), not an echo request, or the
 * request's ICMP checksum is invalid (hostile input — never reply).
 *
 * pkt must be a complete inner IPv4 packet (len includes IP+ICMP+data).
 * IHL > 20 bytes (options) is accepted as long as there is room for ICMP;
 * the reply carries the same options so length stays consistent and the
 * IP checksum recompute covers the full declared IHL.
 */
bool tsnode_icmp4_make_echo_reply(uint8_t *pkt, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_ICMP_ECHO_H */
