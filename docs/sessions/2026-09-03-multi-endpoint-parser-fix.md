# 2026-09-03 — multi-endpoint parser fix (LAN connectivity)

## Contexto

El nodo ESP32 registraba correctamente en la tailnet pero no lograba
conectividad WireGuard directa con el peer en la misma LAN /24 (comportamiento:
`WG TX init` solo a la IP pública del router, `RX init=0` por falta de hairpin
NAT en ese NAT). El diagnóstico fue un bug del parser: `tsnode_map_parse_response`
descartaba todos los endpoints de cada peer salvo el primero, perdiendo el
endpoint LAN-privado que permitiría conexión directa.

## Cambios

- `components/tsnode/src/proto/tsnode_map.h`: `tsnode_map_peer_t` ahora tiene
  array `endpoints[TSNODE_MAP_MAX_ENDPOINTS]` + `n_endpoints`, en reemplazo de
  `endpoint_ip`/`endpoint_port` únicos. Definido `TSNODE_MAP_MAX_ENDPOINTS=4`.
- `components/tsnode/src/proto/tsnode_map.c`: `tsnode_map_parse_response`
  parsea todos los `"Endpoints":[...]` (cap 4). `peer->online =
  (n_endpoints > 0)`.
- `components/tsnode/src/proto/tsnode_client.c`: `update_wg_peers` ahora pasa
  todos los endpoints a `tsnode_disco_add_peer`; el handshake WG de arranque usa
  `endpoints[0]`; log de peers actualizado a la nueva estructura.
- `tests/unit/test_h2.c`: actualizados tests de endpoint existentes + nuevos
  `test_map_parse_peer_endpoint_multi`, `_cap`, `_no_endpoints`.
- `docs/adr/0017-multi-endpoint-per-peer.md`: ADR nuevo.

## Decisiones de seguridad tomadas o revisadas

- Parsing tratado como input hostil: validación IPv4 estricta con `sscanf` y
  cap fijo en compile time antes de usar (sin confiar en la cantidad declarada
  por el peer).
- No se confía en el endpoint LAN como autenticación: la autenticación del peer
  sigue siendo el handshake Noise/WireGuard; el endpoint es solo un candidato de
  ruta que disco prueba. Ver ADR-0017 §Consecuencias de seguridad.

## Verificación

- Build ESP-IDF (dev): OK, sin errores ni warnings.
- `make -C tests/unit check`: todos pasan (incl. nuevos tests de multi-endpoint).
- `cppcheck` sobre `components/tsnode/src/`: limpio, exit 0.

## Pendiente / bloqueado

- Flashear el firmware actualizado al ESP32 real (`/dev/ttyACM0`).
- `.tsforget` + `.tsconnect` (o wipe+reprovision) para re-registrar y forzar un
  MapResponse fresco.
- Monitorear que `WG TX init` apunte a `<ip-lan>:41641` (LAN) y no solo a
  la IP pública, y que el peer devuelva `RX init`. Validar con
  `tailscale ping <ip-tailnet>` desde el host y ping ICMP end-to-end (GOAL-5/6).
- Decidir commit del trabajo (pendiente de validación en HW).
