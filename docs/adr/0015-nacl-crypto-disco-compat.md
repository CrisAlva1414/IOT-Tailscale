# ADR-0015: Crypto disco compatible con Tailscale (NaCl crypto_box)

- Estado: aceptado
- Fecha: 2026-09-03

## Contexto

El disco protocol (ADR-0014) requiere cifrado autenticado compatible con el
control plane y los peers de Tailscale. El proyecto se registra y negocia el
disco key, pero el data plane no funciona: los peers no responden a los
WireGuard handshake initiations porque el ESP32 no puede procesar ni generar
mensajes disco PING/PONG en un formato que los peers de Tailscale (Go) puedan
descifrar.

### Causa raíz (dos errores en la implementación original)

La implementación original de `disco.c` usaba el vtable crypto de WireGuard
(`tsnode_wg_crypto_t`) aplicado al disco:

1. **Cifrado incorrecto**: ChaCha20-Poly1305 con nonce de 12 bytes (RFC 8439),
   en vez de XSalsa20-Poly1305 con nonce de 24 bytes (NaCl `crypto_secretbox`).
   Tailscale disco usa `golang.org/x/crypto/nacl/secretbox`
   (`types/key/disco.go`): XSalsa20-Poly1305 con nonce de 24 bytes.

2. **Derivación de clave incorrecta**: la clave del box se tomaba como el
   resultado directo de `X25519(priv, pub)`. Tailscale usa
   `box.Precompute(shared, peerPub, priv)` que hace
   `HSalsa20(X25519(priv, pub), zeros[16], sigma)` antes de usar la clave en el
   secretbox. (En realidad `crypto_box`/`box.Precompute` produce una clave
   precomputada; el secretbox interno deriva subclaves por HSalsa20 del nonce.)

Se verificó contra la fuente primaria (`disco/disco.go` y
`golang.org/x/crypto/nacl/box` y `secretbox`, fetch 2026-09-03) que:

- Header disco: `magic(6) || senderDiscoPub(32) || nonce(24) || box`.
- El box es `secretbox.Seal(msg, nonce, shared)` → `tag(16) || ciphertext`.
- La clave se deriva con `box.Precompute`.
- PING plaintext: `type(1) || ver(1) || txid(12) || nodekey(32)` = 46 bytes.
- PONG plaintext: `type(1) || ver(1) || txid(12) || ip16(16) || port(2)` = 32
  bytes (pongLen = 12+16+2; ver también el test vector de `disco_test.go`).

## Decisión

Reimplementar la construcción NaCl `crypto_box` usada por Tailscale disco:

1. **Cifrado**: `XSalsa20-Poly1305` (NaCl `crypto_secretbox`) con nonce de
   24 bytes. Formato de salida **`tag(16) || ciphertext(msglen)`** (orden
   NaCl/Go, no el `ciphertext || tag` de RFC 8439).

2. **Derivación de clave**: `box_key = HSalsa20(X25519(priv, pub), zeros[16],
   sigma)` — equivalente a `box.Precompute`. Implementado en
   `tsnode_nacl_box_beforenm()`.

3. **Vendoring**: se extraen `Salsa20/HSalsa20/XSalsa20` (de TweetNaCl,
   dominio público, audited reference por Bernstein et al.) y `Poly1305`
   (también de TweetNaCl) a `third_party/salsa20poly1305/`. mbedTLS (ya
   incluida en ESP-IDF) no corresponde porque **no incluye Salsa20/HSalsa20**
   (verificado contra el árbol de mbedTLS 3.6.3). Se optó por la
   reimplementación auditable de referencia sobre vendorizar `noise-c` parcheado
   (como hace `alfs/tailscale-iot`), siguiendo AGENTS.md §6.

4. **Inyección de X25519**: `nacl_box` recibe el DH X25519 por puntero de
   función (mismo backend `tsnode_wg_crypto_t::dh` usado por WireGuard), para
   no duplicar implementaciones de curvas elípticas.

5. **Disco rewiring**: `disco.c` deja de usar `crypto->aead_seal/aead_open`
   (ChaCha20) para disco y pasa a `tsnode_nacl_box_seal/open`. WireGuard data
   plane **sigue** usando ChaCha20-Poly1305 (correcto para WireGuard, ADR-0011).

## Alternativas consideradas

1. **Vendorizar `noise-c` y parchearlo** (como `alfs/tailscale-iot`): se
   descartó por AGENTS.md §6 (preferencia por bibliotecas auditadas/maduras,
   no vendorizar PoC parcheado en build time).

2. **Usar `monocypher`**: tiene X25519/ChaCha20 pero no Salsa20/HSalsa20
   necesarios para el secretbox de Tailscale. Se descartó.

3. **Reimplementar desde zero sin referencia**: se descartó; aquí se extrae de
   TweetNaCl (referencia del algoritmo, dominio público) y se cross-valida
   byte-a-byte contra la propia TweetNaCl en tests. No es una reimplementación
   sin base auditable.

4. **`crypto_secretbox` de libsodium**: viable para host pero no disponible
   para ESP32 sin librería externa grande; se descartó por footprint y porque
   ya usamos mbedTLS+TweetNaCl primitives ligeras.

## Consecuencias de seguridad

- **Amenaza remota**: la interoperabilidad byte-a-byte con Go/NACL elimina el
  bug de formato que impedía a los peers descifrar los PING del ESP32. El
  descifrado autenticado fail-closed (verifica el tag Poly1305 **antes** de
  liberar cualquier plaintext) se mantiene: `open_afternm` valida el tag
  completo antes de copiar el mensaje, y cualquier fallo de autenticación
  retorna `TSNODE_ERR_CRYPTO` sin modificar el buffer de salida.
- Poly1305 y comparación de tags: constant-time (se usa `vpoly1305_verify`,
  no `memcmp` directo), cumpliendo AGENTS.md §4.
- El nonce de 24 bytes es generado por CSPRNG del backend (`crypto->random`)
  y nunca se reutiliza para el mismo par (key, nonce) — invariante de
  security-critical para XSalsa20 que ya estaba en `disco_send_ping`.
- Se mantiene la regla de AGENTS.md §2.1/§2.2: los datos de red se tratan como
  input hostil, y el parseo valida longitudes antes de tocar buffers.
- La clave de box derivada (`box_key`) se limpió del stack con `memset` tras
  su uso en `beforenm`/`seal`/`open`, reduciendo el rastro en memoria.

- **Amenaza física**: no cambia — las claves disco se siguen persistiendo en
  NVS con la estrategia de ADR-0003 (NVS + flash encryption), y ninguna clave
  privada se imprime en logs.

## Consecuencias de estabilidad

- La operación de derivación de clave por peer (X25519 + HSalsa20) y el
  cifrado XSalsa20 son computacionalmente más pesados que ChaCha20, pero se
  realizan solo en el path de disco (PING/PONG periódicos, no en el hot path
  de datos WireGuard). Presupuesto de tiempo real evaluado como aceptable
  para el ESP32-C3 a 160MHz (medido en el banco, sin watchdog resets).
- Buffers anclados en stack con tamaño máximo en compile time
  (`TSNODE_NACL_BOX_MAX_MSG = 80`), sin asignación dinámica en el hot path,
  de acuerdo AGENTS.md §4.
- PONG buffer overflow corregido: `TSNODE_DISCO_PONG_LEN` ahora es 32 (antes
  30) — el código escribía `pong_plain[31]` en un buffer de 30 bytes.
