# 2026-09-03 — Disco crypto fix (NaCl crypto_box) + PONG buffer

## Contexto

Se identifica que GOAL-1 (disco crypto compatible con Tailscale) estaba
bloqueado por dos errores en la implementación original de `disco.c`:

1. **Cifrado incorrecto**: se usaba ChaCha20-Poly1305 con nonce de 12 bytes
   (RFC 8439), pero Tailscale disco usa XSalsa20-Poly1305 con nonce de 24
   bytes (NaCl `crypto_secretbox`, `golang.org/x/crypto/nacl/secretbox`).
2. **Derivación de clave incorrecta**: se usaba el DH X25519 directo como
   clave del box; Tailscale aplica `box.Precompute` =
   `HSalsa20(X25519(priv, pub), zeros[16], sigma)`.

Ambos errores impedían que los peers de Tailscale (Go) pudieran descifrar los
PING del ESP32 y que el ESP32 descifrara los PONG recibidos.

Además, GOAL-2: `TSNODE_DISCO_PONG_LEN` era 30 pero el código escribía
`pong_plain[31]` (overflow de 2 bytes). El formato real del PONG (verificado
contra `disco_test.go` de Tailscale) es 32 bytes:
`type(1) || ver(1) || txid(12) || src_ip16(16) || port(2)`.

## Cambios

- **Nuevo**: `components/tsnode/src/crypto/nacl_box.{c,h}` — construcción NaCl
  `crypto_box` (XSalsa20-Poly1305) con `beforenm` (HSalsa20 sobre X25519) y
  `seal/open` en formato `tag(16) || ciphertext`. X25519 se inyecta por
  puntero de función (backend WireGuard).
- **Nuevo**: `third_party/salsa20poly1305/` — Salsa20/HSalsa20/XSalsa20 y
  Poly1305 extraídos de TweetNaCl (dominio público, reference auditable).
- **Modificado**: `components/tsnode/src/disco/disco.c` — `disco_box_seal/open`
  ahora delegan en `nacl_box` (ya no en ChaCha20). Limpiados warnings
  sign-compare pre-existentes.
- **Modificado**: `components/tsnode/src/disco/disco.h` — `TSNODE_DISCO_PONG_LEN`
  = 32 (era 30). Comentario de crypto corregido.
- **Modificado**: `components/tsnode/CMakeLists.txt` — agrega `nacl_box.c` y
  los fuentes vendored de salsa20/poly1305, y el include path de third_party.
- **Nuevo**: `tests/unit/test_nacl_box.c` — cross-validación byte-a-byte contra
  TweetNaCl (beforenm, seal interop, open interop, fail-closed, round-trip via
  DH, argument validation). Todo PASS.
- **Modificado**: `tests/unit/Makefile` — agrega `test_nacl_box`.
- **Nuevo**: `docs/adr/0014-disco-protocol-nat-traversal.md` y
  `docs/adr/0015-nacl-crypto-disco-compat.md`.
- **Modificado**: `third_party/README.md` — documenta la dependencia vendored.
- **Modificado**: `docs/PROJECT-GOALS.md` — GOAL-1 y GOAL-2 marcados como
  COMPLETED (validado; prueba en hardware pendiente).

## Decisiones de seguridad tomadas o revisadas

- `nacl_box` verifica el tag Poly1305 **antes** de liberar cualquier plaintext
  (fail-closed, AGENTS.md §2.2). Usa comparación constant-time
  (`vpoly1305_verify`, no `memcmp` directo).
- La clave de box derivada se limpia del stack (`memset`) tras cada uso.
- No se patchea el código vendored de terceros para silenciar linters
  (política third_party/README.md).
- mbedTLS (ESP-IDF) no cubre Salsa20/HSalsa20 (verificado), por eso se
  vendoriza desde TweetNaCl — justificado en ADR-0015 per AGENTS.md §6.
- WireGuard data plane sigue usando ChaCha20-Poly1305 (correcto para WG);
  el cambio es solo para disco.

## Validación

- **Cross-validation**: `nacl_box` byte-identical a TweetNaCl `crypto_secretbox`
  (seal) y descifra su ciphertext (open). beforenm == box.Precompute.
- **Tests unitarios**: `make -C tests/unit check` — todos PASS (incl. test_nacl_box).
- **Build firmware**: `idf.py build` exitoso sin warnings (-Werror activo para
  el componente).
- **Análisis estático**: cppcheck sin hallazgos de memory/crypto; solo
  `constParameter` pre-existente en disco.c y `variableScope` en código
  vendored (no se parchea).

## Pendiente / bloqueado

- **Prueba en hardware real** (M5Stack Core 2 / ESP32): flashear y verificar
  que el ESP32 recibe y descifra un PONG de un peer Tailscale cuando hay ruta
  directa/NAT traversal viable. Sin esto, GOAL-1 queda validado solo a nivel
  de tests, no end-to-end.
- Los peers deben estar accesibles por ruta directa (no solo detrás de NAT
  simétrico sin DERP); para peers detrás de NAT simétrico seguirá sin conectar
  (limitación v1 sin DERP, ver sesión 2026-09-03-disco-debug-fix).
- GOAL-3 (endpoint público en MapRequest) permanece pendiente — STUN
  descubierto pero no usado en MapRequest.
