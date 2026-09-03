/*
 * Implementación ESP-IDF del port de tsnode — networking (ADR-0008).
 *
 * TCP vía lwIP, TLS vía mbedTLS. Único lugar del componente donde se
 * permiten headers de plataforma.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "esp_log.h"
#include "esp_crt_bundle.h"

#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"

/* lwIP socket options: TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT (A3) */
#include <lwip/sockets.h>

#include "tsnode_port.h"

static const char *TAG = "tsnode_port_net";

/* Global DRBG state: entropy source + CTR_DRBG. Initialized once. */
static mbedtls_entropy_context s_entropy;
static mbedtls_ctr_drbg_context s_ctr_drbg;
static bool s_rng_initialized;

static int init_rng(void)
{
    if (s_rng_initialized) {
        return 0;
    }
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&s_ctr_drbg, mbedtls_entropy_func,
                                     &s_entropy,
                                     (const unsigned char *)"tsnode", 6);
    if (ret != 0) {
        ESP_LOGE(TAG, "ctr_drbg_seed: -0x%04x", -ret);
        return ret;
    }
    s_rng_initialized = true;
    return 0;
}

/* Socket opaco: contends TCP (mbedTLS net) + TLS context */
struct tsnode_port_socket {
    mbedtls_net_context      net;
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       conf;
    mbedtls_x509_crt         ca_certs;
    bool                     use_tls;
};

/* Convert mbedTLS error to tsnode_err_t */
static tsnode_err_t tls_err_to_tsn(int ret)
{
    if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
        return TSNODE_ERR_TIMEOUT;
    }
    return TSNODE_ERR_NETWORK;
}

tsnode_err_t tsnode_port_tcp_connect(tsnode_port_socket_t **out_sock,
                                     const char *host, uint16_t port,
                                     uint32_t timeout_ms)
{
    if (out_sock == NULL || host == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    tsnode_port_socket_t *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return TSNODE_ERR_NO_MEMORY;
    }

    mbedtls_net_init(&s->net);

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int ret = mbedtls_net_connect(&s->net, host, port_str,
                                  MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        ESP_LOGE(TAG, "tcp_connect to %s:%u failed: -0x%04x", host, port, -ret);
        mbedtls_net_free(&s->net);
        free(s);
        return TSNODE_ERR_NETWORK;
    }

    /* Apply read timeout on the raw socket so mbedtls_net_recv does not
     * block forever on a dead connection (fix: A2).  Without this, a
     * silent TCP close or NAT timeout causes the task to hang. */
    if (timeout_ms > 0) {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(s->net.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    /* TCP keepalive to prevent NAT/firewall from dropping idle connections
     * between map polls (fix: A3).  Default: idle 60s, probe every 10s,
     * give up after 3 probes.  The control-plane TCP sits idle for ~30s
     * between MapRequest/MapResponse exchanges; without keepalive the
     * NAT mapping may expire. */
    {
        int yes = 1;
        setsockopt(s->net.fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
        int idle_s = 60;   /* seconds before first probe */
        int intvl_s = 10;  /* seconds between probes */
        int cnt = 3;       /* failed probes before giving up */
        setsockopt(s->net.fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_s, sizeof(idle_s));
        setsockopt(s->net.fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl_s, sizeof(intvl_s));
        setsockopt(s->net.fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    }

    s->use_tls = false;
    *out_sock = s;
    return TSNODE_OK;
}

tsnode_err_t tsnode_port_tls_connect(tsnode_port_socket_t **out_sock,
                                     const char *host, uint16_t port,
                                     uint32_t timeout_ms)
{
    if (out_sock == NULL || host == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    tsnode_port_socket_t *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return TSNODE_ERR_NO_MEMORY;
    }

    /* Ensure RNG is initialized */
    int ret = init_rng();
    if (ret != 0) {
        free(s);
        return TSNODE_ERR_CRYPTO;
    }

    mbedtls_net_init(&s->net);
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    mbedtls_x509_crt_init(&s->ca_certs);

    /* Configure TLS */
    ret = mbedtls_ssl_config_defaults(&s->conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        ESP_LOGE(TAG, "ssl_config_defaults: -0x%04x", -ret);
        goto fail;
    }

    /* Load system CA bundle (must be after ssl_config_defaults) */
    ret = esp_crt_bundle_attach(&s->conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "crt_bundle_attach failed: %s", esp_err_to_name(ret));
        goto fail;
    }

    mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&s->conf, mbedtls_ctr_drbg_random,
                         &s_ctr_drbg);

    ret = mbedtls_ssl_setup(&s->ssl, &s->conf);
    if (ret != 0) {
        ESP_LOGE(TAG, "ssl_setup: -0x%04x", -ret);
        goto fail;
    }

    mbedtls_ssl_set_hostname(&s->ssl, host);

    /* TCP connect */
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    ret = mbedtls_net_connect(&s->net, host, port_str,
                              MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        ESP_LOGE(TAG, "tls tcp_connect to %s:%u failed: -0x%04x",
                 host, port, -ret);
        goto fail;
    }

    mbedtls_ssl_set_bio(&s->ssl, &s->net,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    /* TLS handshake with timeout */
    if (timeout_ms > 0) {
        uint64_t deadline;
        tsnode_port_uptime_ms(&deadline);
        deadline += timeout_ms;
        mbedtls_ssl_conf_read_timeout(&s->conf, (int)timeout_ms);
    }

    while ((ret = mbedtls_ssl_handshake(&s->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "ssl_handshake: -0x%04x", -ret);
            goto fail;
        }
    }

    /* Verify certificate */
    uint32_t flags = mbedtls_ssl_get_verify_result(&s->ssl);
    if (flags != 0) {
        char vbuf[512];
        mbedtls_x509_crt_verify_info(vbuf, sizeof(vbuf), "  ! ", flags);
        ESP_LOGE(TAG, "cert verify failed:\n%s", vbuf);
        goto fail;
    }

    s->use_tls = true;
    *out_sock = s;
    return TSNODE_OK;

fail:
    tsnode_port_socket_close(s);
    return TSNODE_ERR_NETWORK;
}

tsnode_err_t tsnode_port_socket_write(tsnode_port_socket_t *sock,
                                      const uint8_t *data, size_t nlen,
                                      uint32_t timeout_ms)
{
    if (sock == NULL || data == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    size_t written = 0;
    while (written < nlen) {
        int ret;
        if (sock->use_tls) {
            ret = mbedtls_ssl_write(&sock->ssl, data + written, nlen - written);
        } else {
            ret = mbedtls_net_send(&sock->net, data + written, nlen - written);
        }
        if (ret > 0) {
            written += (size_t)ret;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                   ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
                   ret == MBEDTLS_ERR_NET_SEND_FAILED) {
            continue;
        } else {
            return TSNODE_ERR_NETWORK;
        }
    }
    return TSNODE_OK;
}

tsnode_err_t tsnode_port_socket_read(tsnode_port_socket_t *sock,
                                     uint8_t *buf, size_t buf_size,
                                     size_t *nread, uint32_t timeout_ms)
{
    if (sock == NULL || buf == NULL || nread == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* For non-TLS sockets: apply SO_RCVTIMEO so that mbedtls_net_recv
     * (which calls recv() internally) returns EAGAIN instead of blocking
     * forever on a dead or idle connection (fix: A2).
     * The timeout is also set once in tsnode_port_tcp_connect for the
     * lifetime of the socket; this per-call set handles cases where the
     * caller uses a different timeout than the connect-time default. */
    if (!sock->use_tls && timeout_ms > 0) {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock->net.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    int ret;
    if (sock->use_tls) {
        ret = mbedtls_ssl_read(&sock->ssl, buf, buf_size);
    } else {
        ret = mbedtls_net_recv(&sock->net, buf, buf_size);
    }

    if (ret > 0) {
        *nread = (size_t)ret;
        return TSNODE_OK;
    }
    if (ret == 0) {
        /* Connection closed */
        *nread = 0;
        return TSNODE_ERR_NETWORK;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        *nread = 0;
        return TSNODE_ERR_TIMEOUT;
    }
    *nread = 0;
    return tls_err_to_tsn(ret);
}

void tsnode_port_socket_close(tsnode_port_socket_t *sock)
{
    if (sock == NULL) {
        return;
    }
    if (sock->use_tls) {
        mbedtls_ssl_close_notify(&sock->ssl);
        mbedtls_ssl_free(&sock->ssl);
        mbedtls_ssl_config_free(&sock->conf);
        mbedtls_x509_crt_free(&sock->ca_certs);
    }
    mbedtls_net_free(&sock->net);
    free(sock);
}

/* ---- UDP socket for WireGuard data plane (ADR-0011) ---- */

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

struct tsnode_port_udp_socket {
    int fd;
};

tsnode_err_t tsnode_port_udp_bind(tsnode_port_udp_socket_t **out_sock,
                                  uint16_t port)
{
    if (out_sock == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    tsnode_port_udp_socket_t *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return TSNODE_ERR_NO_MEMORY;
    }

    s->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s->fd < 0) {
        ESP_LOGE(TAG, "udp socket: %d", errno);
        free(s);
        return TSNODE_ERR_NETWORK;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(s->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "udp bind port %u: %d", port, errno);
        close(s->fd);
        free(s);
        return TSNODE_ERR_NETWORK;
    }

    /* Non-blocking for timeout-aware receive */
    int flags = fcntl(s->fd, F_GETFL, 0);
    fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    /* SO_REUSEADDR: allow rebinding even if a stale socket from a previous
     * session still holds the port.  Without this, a failed reconnection
     * attempt leaks the fd and the next bind() fails with EADDRINUSE until
     * the device is rebooted (fix: B2). */
    int reuse = 1;
    setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    /* Enable broadcast (needed for WireGuard discovery) */
    int broadcast = 1;
    setsockopt(s->fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    *out_sock = s;
    return TSNODE_OK;
}

tsnode_err_t tsnode_port_udp_sendto(tsnode_port_udp_socket_t *sock,
                                    const uint8_t *data, size_t len,
                                    uint32_t dest_ip, uint16_t dest_port)
{
    if (sock == NULL || data == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(dest_ip);
    dest.sin_port = htons(dest_port);

    ssize_t sent = sendto(sock->fd, data, len, 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0 || (size_t)sent != len) {
        ESP_LOGE(TAG, "udp sendto %u.%u.%u.%u:%u: %d",
                 (dest_ip >> 24) & 0xFF, (dest_ip >> 16) & 0xFF,
                 (dest_ip >> 8) & 0xFF, dest_ip & 0xFF,
                 dest_port, errno);
        return TSNODE_ERR_NETWORK;
    }
    return TSNODE_OK;
}

tsnode_err_t tsnode_port_udp_recvfrom(tsnode_port_udp_socket_t *sock,
                                      uint8_t *buf, size_t buf_size,
                                      size_t *nread,
                                      uint32_t *src_ip, uint16_t *src_port,
                                      uint32_t timeout_ms)
{
    if (sock == NULL || buf == NULL || nread == NULL) {
        return TSNODE_ERR_INVALID_ARG;
    }

    /* Set receive timeout via setsockopt (lwIP-compatible) */
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t got = recvfrom(sock->fd, buf, buf_size, 0,
                           (struct sockaddr *)&from, &from_len);
    if (got < 0) {
        *nread = 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return TSNODE_ERR_TIMEOUT;
        }
        return TSNODE_ERR_NETWORK;
    }

    *nread = (size_t)got;
    if (src_ip != NULL) {
        *src_ip = ntohl(from.sin_addr.s_addr);
    }
    if (src_port != NULL) {
        *src_port = ntohs(from.sin_port);
    }
    return TSNODE_OK;
}

void tsnode_port_udp_close(tsnode_port_udp_socket_t *sock)
{
    if (sock == NULL) {
        return;
    }
    if (sock->fd >= 0) {
        close(sock->fd);
    }
    free(sock);
}
