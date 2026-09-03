/*
 * tsnode-icmp-echo — minimal IPv4 ICMP echo responder (GOAL-5).
 * See icmp_echo.h for the contract and security rationale.
 */

#include "icmp_echo.h"

/* Standard one's-complement Internet checksum (RFC 1071), over a byte
 * buffer with the checksum field already zeroed by the caller. Returns the
 * value to store in the checksum field (big-endian network order). */
static uint16_t ip_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += ((uint32_t)data[i] << 8) | (uint32_t)data[i + 1];
    }
    /* Odd trailing byte */
    if (i < len) {
        sum += (uint32_t)data[i] << 8;
    }
    /* Fold 32-bit into 16-bit */
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/* Verify a received ICMP checksum over the ICMP header+payload. */
static bool icmp_checksum_valid(const uint8_t *icmp, size_t icmp_len)
{
    if (icmp_len == 0) return false;
    /* Recompute over a copy with checksum field zeroed; reject if the
     * stored checksum does not match (hostile/malformed input). */
    /* Use a bounded stack scratch for the whole ICMP message so the
     * checksummed region is contiguous. ICMP data can be large (up to the
     * buffer cap), so cap at what fits; a ping payload is ~24-64 B. */
    uint16_t stored = (uint16_t)((icmp[2] << 8) | icmp[3]);
    /* Cheap path for the common 8-byte header + small payload: recompute
     * directly on a zeroed local copy of the checksum bytes. For larger
     * payloads this walks the bytes twice, which is fine (ping rate is
     * low). We zero bytes 2-3 in place of a copy by recomputing with a
     * wrapper. */
    uint32_t sum = 0;
    size_t i = 0;
    for (; i + 1 < icmp_len; i += 2) {
        uint32_t word;
        if (i == 2) {
            word = 0; /* checksum field treated as zero */
        } else {
            word = ((uint32_t)icmp[i] << 8) | (uint32_t)icmp[i + 1];
        }
        sum += word;
    }
    if (i < icmp_len) {
        uint32_t word = (i == 2) ? 0u : ((uint32_t)icmp[i] << 8);
        sum += word;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    uint16_t computed = (uint16_t)~sum;
    return computed == stored;
}

bool tsnode_icmp4_make_echo_reply(uint8_t *pkt, size_t len)
{
    if (pkt == NULL) return false;

    /* IPv4 header minimum + ICMP header minimum. */
    if (len < TSNODE_ICMP4_MIN_IPHDR + TSNODE_ICMP4_HDR_LEN) {
        return false;
    }

    /* Version must be 4 and IHL must be >= 5 (20 bytes). */
    uint8_t ver_ihl = pkt[0];
    if ((ver_ihl >> 4) != 4u) return false;
    uint8_t ihl = ver_ihl & 0x0Fu;
    if (ihl < 5u) return false;
    size_t ip_hdr_len = (size_t)ihl * 4u;

    /* Payload must leave room for at least the ICMP header after IHL. */
    if (len < ip_hdr_len + TSNODE_ICMP4_HDR_LEN) return false;

    /* Fragment offset: only handle first fragment (offset 0). Non-first
     * fragments carry no ICMP header worth replying to — reject safely. */
    uint16_t frag_field = (uint16_t)((pkt[6] << 8) | pkt[7]);
    if ((frag_field & 0x1FFFu) != 0u) return false;

    /* Protocol must be ICMP (1). */
    if (pkt[9] != 1u) return false;

    const uint8_t *icmp = pkt + ip_hdr_len;
    size_t icmp_len = len - ip_hdr_len;
    if (icmp_len < TSNODE_ICMP4_HDR_LEN) return false;

    /* Must be an echo request (type 8, code 0). */
    if (icmp[0] != 8u || icmp[1] != 0u) return false;

    /* Hostile input: never reply to a request with an invalid ICMP
     * checksum. */
    if (!icmp_checksum_valid(icmp, icmp_len)) return false;

    /* Build the reply in place:
     *   - swap source/destination IP
     *   - ICMP type 8 -> 0 (code stays 0 — already checked)
     *   - recompute ICMP checksum
     *   - recompute IPv4 header checksum (matches at this point too; not
     *     validated for request, only recomputed for our reply) */

    /* 1. Swap IP src/dst. */
    uint8_t tmp_ip[4];
    tmp_ip[0] = pkt[12]; tmp_ip[1] = pkt[13];
    tmp_ip[2] = pkt[14]; tmp_ip[3] = pkt[15];
    pkt[12] = pkt[16]; pkt[13] = pkt[17];
    pkt[14] = pkt[18]; pkt[15] = pkt[19];
    pkt[16] = tmp_ip[0]; pkt[17] = tmp_ip[1];
    pkt[18] = tmp_ip[2]; pkt[19] = tmp_ip[3];

    /* 2. Type 8 -> 0. identifier and sequence are already echoed back by
     *    keeping the payload; only type changes. */
    pkt[ip_hdr_len] = 0u;

    /* 3. Recompute ICMP checksum over the whole ICMP message (header+data)
     *    with the checksum field zeroed. */
    pkt[ip_hdr_len + 2] = 0;
    pkt[ip_hdr_len + 3] = 0;
    uint16_t icmp_cksum = ip_checksum(icmp, icmp_len);
    pkt[ip_hdr_len + 2] = (uint8_t)(icmp_cksum >> 8);
    pkt[ip_hdr_len + 3] = (uint8_t)(icmp_cksum & 0xFF);

    /* 4. Recompute IPv4 header checksum (src/dst changed). */
    pkt[10] = 0;
    pkt[11] = 0;
    uint16_t ip_cksum = ip_checksum(pkt, ip_hdr_len);
    pkt[10] = (uint8_t)(ip_cksum >> 8);
    pkt[11] = (uint8_t)(ip_cksum & 0xFF);

    return true;
}
