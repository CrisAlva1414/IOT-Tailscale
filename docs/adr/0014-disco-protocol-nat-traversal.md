# ADR-0014: Disco protocol — NAT traversal del data plane

- Estado: aceptado
- Fecha: 2026-09-01 (revisado 2026-09-03)

## Contexto

El ESP32 se registra correctamente en la tailnet y obtiene una IP 100.x.x.x,
pero es inalcanzable por los demás peers del nodo: está detrás de NAT y el
control plane ignora sus endpoints hasta que un peer demuestra ruta directa.
Sin disco protocol, los peers no responden a los WireGuard handshake
initiations porque no conocen endpoint del ESP32 ni este puede hacer hole
punching.

Tailscale usa disco sobre UDP (magic `TS💬`) para descubrimiento de rutas
directas y "hole punching" de NAT (sin DERP en v1, AGENTS.md §1). Este ADR
fija el alcance de la implementación disco del proyecto.

## Decisión

Implementar un subconjunto mínimo de disco:

- **Cifrado**: `crypto_box` de NaCl (XSalsa20-Poly1305 + HSalsa20/Poly1305,
  ver ADR-0015). El mismo construction que Tailscale usa en
  `types/key/disco.go` y `golang.org/x/crypto/nacl/secretbox`.
- **Mensajes soportados**: `Ping` (TypePing=0x01) y `Pong` (TypePong=0x02)
  sobre UDP directo. `CallMeMaybe`/`CallMeMaybeVia`/DERP fuera de alcance v1.
- **Header de paquete**: `magic(6) "TS💬" || senderDiscoPub(32) || nonce(24)
  || secretbox(tag(16) || ciphertext)`.
- **PING plaintext**: `type(1) || ver(1) || txid(12) || nodekey(32)` = 46 B.
- **PONG plaintext**: `type(1) || ver(1) || txid(12) || src_ip16(16) ||
  src_port(2)` = 32 B. (Nota: IP como IPv4-mapped IPv6, 16 bytes; la
  implementación v1 envía el campo IP en cero hasta que STUN confirme el
  endpoint público.)
- **STUN**: Binding Request (RFC 5389, 20 bytes) a un servidor DERP como
  STUN para descubrir el endpoint público (GOAL-3). Parseo de
  XOR-MAPPED-ADDRESS.
- **Hole punching**: reintentos periódicos (PING con backoff, keepalive) y
  marcado de `direct_path_ok` al recibir PONG válido (txid coincide).
- **Sin DERP**: si no hay ruta directa tras los reintentos, el nodo lo
  reporta y no conecta el data plane. Es la limitación conocida de v1
  (documentada en AGENTS.md §1 y en el proyecto de referencia).

## Alternativas consideradas

1. **DERP relay en v1**: se descarta — AGENTS.md §1 lo excluye y agrega
   superficie de red considerable.
2. **IPv6 en disco**: fuera de alcance; los endpoints son IPv4.
3. **Soporte de `CallMeMaybe`**: diferido; requiere DERP/relay para recibir
   los numéricos de pares detrás de NAT simétrico.

## Consecuencias de seguridad

- Los mensajes disco se cifran y autentican con XSalsa20-Poly1305. El
  descifrado fail-closed (verifica el tag antes de liberar plaintext) se
  implementa en `nacl_box` (ADR-0015).
- Los endpoints y llaves disco se tratan como datos hostiles (AGENTS.md §2.2);
  el parseo valida longitudes antes de tocar buffers.
- Sin DERP deliberadamente: no se abre ningún puerto sin autenticar como
  workaround de conectividad (AGENTS.md §1).

## Consecuencias de estabilidad

- Los PING/PONG disco no están en el hot path de datos WireGuard; su
  frecuencia (keepalive 20s, reintentos con backoff) es baja y no afecta el
  timing de crypto.
- El buffer PONG se corrige a 32 bytes (overflow previo cuando era 30).
