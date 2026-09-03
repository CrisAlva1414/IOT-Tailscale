/*
 * Host tests for tsnode_icmp_echo (GOAL-5).
 * Pure C11, no platform headers. Builds the icmp_echo.c source only.
 */

#include <stdio.h>
#include <string.h>

#include "icmp_echo.h"

static int s_failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("FAIL %s (line %d)\n", msg, __LINE__); \
        s_failures++; \
    } \
} while (0)

/* Build a full IPv4 + ICMP echo request packet. Returns length.
 * cksum_valid: 0 = store a bad ICMP checksum (0xFFFF twice), else compute. */
static size_t build_echo_request(uint8_t *pkt, size_t cap,
                                 const uint8_t src[4], const uint8_t dst[4],
                                 uint16_t id, uint16_t seq,
                                 const uint8_t *data, size_t data_len,
                                 int cksum_valid)
{
    (void)cap;
    memset(pkt, 0, 20 + 8 + data_len);

    /* IPv4 header */
    pkt[0] = 0x45;                 /* version 4, IHL 5 */
    uint16_t total_len = (uint16_t)(20 + 8 + data_len);
    pkt[2] = (uint8_t)(total_len >> 8);
    pkt[3] = (uint8_t)(total_len & 0xFF);
    pkt[8] = 64;                   /* TTL */
    pkt[9] = 1;                    /* protocol ICMP */
    memcpy(pkt + 12, src, 4);
    memcpy(pkt + 16, dst, 4);

    /* ICMP echo request */
    uint8_t *icmp = pkt + 20;
    icmp[0] = 8;                   /* echo request */
    icmp[1] = 0;
    icmp[4] = (uint8_t)(id >> 8);
    icmp[5] = (uint8_t)(id & 0xFF);
    icmp[6] = (uint8_t)(seq >> 8);
    icmp[7] = (uint8_t)(seq & 0xFF);
    if (data_len > 0) {
        memcpy(icmp + 8, data, data_len);
    }

    size_t icmp_len = 8 + data_len;

    /* ICMP checksum */
    if (cksum_valid) {
        uint32_t sum = 0;
        for (size_t i = 0; i + 1 < icmp_len; i += 2) {
            sum += ((uint32_t)icmp[i] << 8) | (uint32_t)icmp[i + 1];
        }
        if (icmp_len & 1u) sum += (uint32_t)icmp[icmp_len - 1] << 8;
        while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
        uint16_t ck = (uint16_t)~sum;
        icmp[2] = (uint8_t)(ck >> 8);
        icmp[3] = (uint8_t)(ck & 0xFF);
    } else {
        icmp[2] = 0xFF;
        icmp[3] = 0xFF;
    }

    /* IP header checksum */
    {
        uint32_t sum = 0;
        for (size_t i = 0; i + 1 < 20; i += 2) {
            sum += ((uint32_t)pkt[i] << 8) | (uint32_t)pkt[i + 1];
        }
        while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
        uint16_t ck = (uint16_t)~sum;
        pkt[10] = (uint8_t)(ck >> 8);
        pkt[11] = (uint8_t)(ck & 0xFF);
    }

    size_t total = 20 + 8 + data_len;
    return total;
}

/* Verify ICMP checksum of a packet's ICMP message region: recompute over
 * the full message INCLUDING the stored checksum bytes; valid iff the
 * folded sum is 0xFFFF (one's complement). */
static int icmp_ck_ok(const uint8_t *pkt, size_t ihl)
{
    const uint8_t *icmp = pkt + ihl;
    uint16_t total_len = (uint16_t)((pkt[2] << 8) | pkt[3]);
    size_t icmp_len = (size_t)total_len - ihl;
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < icmp_len; i += 2) {
        sum += ((uint32_t)icmp[i] << 8) | (uint32_t)icmp[i + 1];
    }
    if (icmp_len & 1u) sum += (uint32_t)icmp[icmp_len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return sum == 0xFFFFu;
}

/* Verify IP header checksum: recompute over full header including the
 * stored checksum bytes; valid iff folded sum is 0xFFFF. */
static int ip_ck_ok(const uint8_t *pkt, size_t ihl)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < ihl; i += 2) {
        sum += ((uint32_t)pkt[i] << 8) | (uint32_t)pkt[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return sum == 0xFFFFu;
}

static void test_echo_request_becomes_reply(void)
{
    uint8_t pkt[200];
    uint8_t src[4] = {100, 64, 0, 1};   /* ping initiator (tailnet) */
    uint8_t dst[4] = {10, 0, 0, 5};     /* us (inner IP) */
    uint8_t data[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    size_t len = build_echo_request(pkt, sizeof(pkt), src, dst,
                                    0x1234, 7, data, sizeof(data), 1);

    CHECK(tsnode_icmp4_make_echo_reply(pkt, len) == true,
          "echo request should produce a reply");

    /* Type now 0 (echo reply) */
    CHECK(pkt[20] == 0u, "ICMP type must be 0 (echo reply)");
    CHECK(pkt[21] == 0u, "ICMP code must be 0");

    /* IP src/dst swapped */
    CHECK(pkt[12] == 10 && pkt[13] == 0 && pkt[14] == 0 && pkt[15] == 5,
          "new src must be old dst");
    CHECK(pkt[16] == 100 && pkt[17] == 64 && pkt[18] == 0 && pkt[19] == 1,
          "new dst must be old src");

    /* identifier/sequence preserved */
    CHECK(pkt[24] == 0x12 && pkt[25] == 0x34, "identifier preserved (hi)");
    CHECK(pkt[26] == 0x00 && pkt[27] == 0x07, "sequence preserved");

    /* payload preserved */
    CHECK(memcmp(pkt + 28, data, sizeof(data)) == 0, "payload preserved");

    /* total length unchanged */
    uint16_t tl = (uint16_t)((pkt[2] << 8) | pkt[3]);
    CHECK(tl == (uint16_t)(20 + 8 + sizeof(data)), "total length unchanged");

    /* checksums valid */
    CHECK(icmp_ck_ok(pkt, 20), "reply ICMP checksum valid");
    CHECK(ip_ck_ok(pkt, 20), "reply IP checksum valid");

    printf("ok   echo request -> reply (type/swap/checksum)\n");
}

static void test_invalid_icmp_checksum_not_replied(void)
{
    uint8_t pkt[100];
    uint8_t src[4] = {100, 64, 0, 1};
    uint8_t dst[4] = {10, 0, 0, 5};
    size_t len = build_echo_request(pkt, sizeof(pkt), src, dst, 0, 0,
                                    NULL, 0, 0 /* invalid cksum */);

    CHECK(tsnode_icmp4_make_echo_reply(pkt, len) == false,
          "invalid ICMP checksum must NOT be replied");

    printf("ok   invalid ICMP checksum rejected\n");
}

static void test_non_icmp_not_converted(void)
{
    uint8_t pkt[100];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 20;
    pkt[9] = 6;   /* protocol TCP, not ICMP */
    pkt[12] = 100; pkt[13] = 64; pkt[14] = 0; pkt[15] = 1;
    pkt[16] = 10; pkt[17] = 0; pkt[18] = 0; pkt[19] = 5;

    CHECK(tsnode_icmp4_make_echo_reply(pkt, 20) == false,
          "TCP packet must not be converted");

    printf("ok   non-ICMP packet rejected\n");
}

static void test_not_echo_type(void)
{
    uint8_t pkt[100];
    uint8_t src[4] = {100, 64, 0, 1};
    uint8_t dst[4] = {10, 0, 0, 5};
    size_t len = build_echo_request(pkt, sizeof(pkt), src, dst, 1, 1,
                                    NULL, 0, 1);
    pkt[20] = 3;  /* destination unreachable, not echo request */

    CHECK(tsnode_icmp4_make_echo_reply(pkt, len) == false,
          "non-echo ICMP type must not be converted");

    printf("ok   non-echo ICMP type rejected\n");
}

static void test_short_packet_rejected(void)
{
    uint8_t pkt[20];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[9] = 1;
    /* only 20 bytes, no room for ICMP header */
    CHECK(tsnode_icmp4_make_echo_reply(pkt, 20) == false,
          "too-short packet rejected");
    /* NULL */
    CHECK(tsnode_icmp4_make_echo_reply(NULL, 20) == false,
          "NULL packet rejected");

    printf("ok   short/empty packets rejected\n");
}

static void test_non_ipv4_not_converted(void)
{
    uint8_t pkt[100];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60; /* version 6 */
    pkt[9] = 1;

    CHECK(tsnode_icmp4_make_echo_reply(pkt, 100) == false,
          "IPv6 packet rejected");

    printf("ok   IPv6 rejected\n");
}

static void test_fragment_not_replied(void)
{
    uint8_t pkt[100];
    uint8_t src[4] = {100, 64, 0, 1};
    uint8_t dst[4] = {10, 0, 0, 5};
    size_t len = build_echo_request(pkt, sizeof(pkt), src, dst, 1, 1,
                                    NULL, 0, 1);
    /* set fragment offset field (byte 7 low, byte 6 high) to nonzero */
    pkt[6] = 0x00; pkt[7] = 0x01; /* offset 1 (8-byte units) */

    CHECK(tsnode_icmp4_make_echo_reply(pkt, len) == false,
          "non-first fragment must not be replied");

    printf("ok   fragmented packet rejected\n");
}

int main(void)
{
    printf("icmp echo responder tests:\n");
    test_echo_request_becomes_reply();
    test_invalid_icmp_checksum_not_replied();
    test_non_icmp_not_converted();
    test_not_echo_type();
    test_short_packet_rejected();
    test_non_ipv4_not_converted();
    test_fragment_not_replied();

    if (s_failures == 0) {
        printf("\nICMP ECHO TESTS: ALL PASS\n");
        return 0;
    }
    printf("\nICMP ECHO TESTS: %d FAILURES\n", s_failures);
    return 1;
}
