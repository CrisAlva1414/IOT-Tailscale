/*
 * Interfaz interna del core de tsnode hacia la plataforma (ADR-0006).
 *
 * El core NUNCA incluye headers de ESP-IDF/FreeRTOS/lwIP: todo acceso a
 * plataforma pasa por esta interfaz. Implementaciones:
 *   - src/port/esp_idf/  — ESP-IDF real.
 *   - tests/unit/        — mocks host-side (ahí corre el core con
 *                          -Wpedantic completo, ver docs/format/c-style.md).
 *
 * La interfaz se diseña desde las necesidades del core, no calca APIs del
 * SDK (ADR-0006, consecuencias de seguridad). Ampliarla exige justificarlo
 * desde ese criterio.
 */

#ifndef TSNODE_PORT_H
#define TSNODE_PORT_H

#include <stddef.h>
#include <stdint.h>

#include "tsnode_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Entropía criptográficamente segura para generación de claves y nonces.
 * len debe ser > 0; out debe tener al menos len bytes. Falla
 * TSNODE_ERR_CRYPTO si la fuente de entropía no está lista — nunca retorna
 * pseudo-aleatoriedad débil "para no bloquear".
 */
tsnode_err_t tsnode_port_random_bytes(uint8_t *out, size_t len);

/*
 * Tiempo monotónico desde el boot, en milisegundos. Para timeouts y
 * medición de presupuesto de tiempo crypto (AGENTS.md §2.2). No depende del
 * reloj de pared ni de NTP.
 */
tsnode_err_t tsnode_port_uptime_ms(uint64_t *out_ms);

/* --- Tarea (ADR-0006: FreeRTOS no se toca desde core) --- */

typedef void (*tsnode_port_task_fn)(void *arg);
tsnode_err_t tsnode_port_task_create(tsnode_port_task_fn fn, void *arg,
                                     const char *name, size_t stack_bytes,
                                     int priority);

/*
 * Autodestruye la tarea llamante. No retorna: la tarea termina aquí.
 * El core no puede llamar vTaskDelete() directamente (ADR-0006).
 */
void tsnode_port_task_delete_self(void);

/*
 * Bloquea la tarea llamante durante ms milisegundos.
 * Wrapper sobre la primitiva de delays de la plataforma (FreeRTOS
 * vTaskDelay, Linux usleep, etc.). El core no incluye FreeRTOS
 * directamente (ADR-0006).
 */
void tsnode_port_delay_ms(uint32_t ms);

/* --- Logging (ADR-0006: sin headers de plataforma en core) --- */

/* Log callback registrado por la app. level: 0=error, 1=warn, 2=info, 3=debug */
typedef void (*tsnode_port_log_fn)(int level, const char *tag, const char *fmt,
                                   ...);
void tsnode_port_set_log(tsnode_port_log_fn fn);
tsnode_port_log_fn tsnode_port_get_log(void);

/* Convenience macros que delegan al callback registrado.
 *
 * ISO C variadic macros: `(tag, ...)` y `__VA_ARGS__` sin `##` (GNU).
 * El formato y sus argumentos entran todos en `__VA_ARGS__` (siempre >= 1),
 * así que esto es C99 estricto y el core compila en tests host con
 * -Wpedantic -Werror (docs/format/c-style.md). */
#define TSNODE_LOGE(tag, ...) do { \
    tsnode_port_log_fn _fn = tsnode_port_get_log(); \
    if (_fn) _fn(0, tag, __VA_ARGS__); \
} while (0)
#define TSNODE_LOGW(tag, ...) do { \
    tsnode_port_log_fn _fn = tsnode_port_get_log(); \
    if (_fn) _fn(1, tag, __VA_ARGS__); \
} while (0)
#define TSNODE_LOGI(tag, ...) do { \
    tsnode_port_log_fn _fn = tsnode_port_get_log(); \
    if (_fn) _fn(2, tag, __VA_ARGS__); \
} while (0)

/* --- Red: sockets TCP/TLS para ts2021 (ADR-0008) --- */

/*
 * Descriptor de socket opaco. El valor real depende de la plataforma.
 * El core solo usa los punteros a funciones que operan sobre él.
 */
typedef struct tsnode_port_socket tsnode_port_socket_t;

/*
 * Conecta TCP a host:port con timeout_ms. Retorna socket en out_sock.
 * host es resuelto internamente (DNS). timeout_ms = 0 sin timeout.
 */
tsnode_err_t tsnode_port_tcp_connect(tsnode_port_socket_t **out_sock,
                                     const char *host, uint16_t port,
                                     uint32_t timeout_ms);

/*
 * Conecta TLS (HTTPS) con verificación de certificados.
 * La CA store depende de la plataforma.
 */
tsnode_err_t tsnode_port_tls_connect(tsnode_port_socket_t **out_sock,
                                     const char *host, uint16_t port,
                                     uint32_t timeout_ms);

/*
 * Escribe exactamente nlen bytes con timeout. Falla TSNODE_ERR_TIMEOUT
 * si se agota el tiempo parcialmente.
 */
tsnode_err_t tsnode_port_socket_write(tsnode_port_socket_t *sock,
                                      const uint8_t *data, size_t nlen,
                                      uint32_t timeout_ms);

/*
 * Lee hasta rlen bytes. Retorna en *nread cuántos bytes se leyeron.
 * TSNODE_ERR_TIMEOUT si no llega nada antes del timeout.
 * TSNODE_ERR_NETWORK si la conexión se cerró (nread == 0).
 */
tsnode_err_t tsnode_port_socket_read(tsnode_port_socket_t *sock,
                                     uint8_t *buf, size_t buf_size,
                                     size_t *nread, uint32_t timeout_ms);

/*
 * Cierra el socket y libia recursos. Idempotente.
 */
void tsnode_port_socket_close(tsnode_port_socket_t *sock);

/* --- Red: UDP para WireGuard data plane (ADR-0011) --- */

/*
 * Socket UDP opaco. El valor real depende de la plataforma.
 */
typedef struct tsnode_port_udp_socket tsnode_port_udp_socket_t;

/*
 * Bind a UDP socket to a local port. port=0 asigna un puerto efímero.
 * out_sock recibe el socket vinculado.
 */
tsnode_err_t tsnode_port_udp_bind(tsnode_port_udp_socket_t **out_sock,
                                  uint16_t port);

/*
 * Envía un datagrama UDP a dest_ip:dest_port (host byte order).
 * Retorna TSNODE_ERR_NETWORK si el envío falla.
 */
tsnode_err_t tsnode_port_udp_sendto(tsnode_port_udp_socket_t *sock,
                                    const uint8_t *data, size_t len,
                                    uint32_t dest_ip, uint16_t dest_port);

/*
 * Recibe un datagrama UDP. Retorna en *nread cuántos bytes se recibieron.
 * src_ip y src_port indican el origen (opcional, pueden ser NULL).
 * timeout_ms: 0 = no bloquea, >0 = espera máxima.
 * TSNODE_ERR_TIMEOUT si no llega nada antes del timeout.
 */
tsnode_err_t tsnode_port_udp_recvfrom(tsnode_port_udp_socket_t *sock,
                                      uint8_t *buf, size_t buf_size,
                                      size_t *nread,
                                      uint32_t *src_ip, uint16_t *src_port,
                                      uint32_t timeout_ms);

/*
 * Cierra el socket UDP y libia recursos. Idempotente.
 */
void tsnode_port_udp_close(tsnode_port_udp_socket_t *sock);

/*
 * Almacenamiento persistente clave-valor de blobs binarios (ADR-0003:
 * identidad del nodo en NVS cifrada cuando corresponda). El core define
 * namespace y claves; el port elige el backend (NVS en ESP-IDF).
 *
 * tsnode_port_kv_get: copia len bytes a out; false si la clave no existe,
 * el tamaño no coincide exactamente o falla el backend.
 * tsnode_port_kv_set: persiste len bytes; true solo si quedó commiteado.
 * tsnode_port_kv_del: best-effort; borrar lo inexistente no es error.
 */
bool tsnode_port_kv_get(const char *ns, const char *key, uint8_t *out,
                        size_t len);
bool tsnode_port_kv_set(const char *ns, const char *key, const uint8_t *val,
                        size_t len);
void tsnode_port_kv_del(const char *ns, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* TSNODE_PORT_H */
