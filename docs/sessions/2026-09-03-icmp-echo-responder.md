# 2026-09-03 — GOAL-5: ICMP echo responder (ping end-to-end)

## Contexto

GOAL-5: desde la tailnet, `ping 100.x.x.x` debe recibir respuesta. Estaba
marcado BLOCKED ("WireGuard no establece data plane sin disco funcional").
Con GOAL-1 (crypto disco), GOAL-2 (PONG buffer) y GOAL-3 (endpoint público)
completados, el data plane ya descifraba transporte — pero **descartaba todo
paquete IP interno** al no haber TUN. Sin responder al ICMP echo request, el
ping nunca obtiene reply.

## Cambios

- **Nuevo**: `components/tsnode/src/wg/icmp_echo.{c,h}` — responder ICMP
  echo mínimo. Transforma in-place un IPv4+ICMP echo request (type 8) a
  echo reply (type 0): swap src/dst IP, recompute checksum ICMP + IPv4.
  Validación de input hostil: longitudes, versión=4, protocolo=ICMP, tipo
  echo, offset de fragmento=0, checksum ICMP debe ser válido (nunca se
  responde a requests corruptos).
- **`components/tsnode/src/proto/tsnode_client.c`**: en el caso
  TRANSPORT_DATA de `wg_recv_task`, si el paquete interno es un echo request
  se genera el reply, se re-encapsula con `tsnode_wg_encap()` y se envía por
  UDP al endpoint de origen. El resto (no-ICMP, TCP, etc.) se descarta como
  antes.
- **Nuevo**: `tests/unit/test_icmp_echo.c` — 7 casos: request→reply
  (type/swap/checksum), checksum inválido rechazado, no-ICMP, no-echo, corto,
  IPv6, fragmento. Todos PASS.
- **`components/tsnode/CMakeLists.txt`**: agrega `icmp_echo.c`.
- **`tests/unit/Makefile`**: agrega `test_icmp_echo` al check.
- **Nuevo**: `docs/adr/0016-icmp-echo-responder.md`.

## Decisiones de seguridad tomadas o revisadas

- Respuesta SOLO dentro del túnel autenticado WG (solo peers de la tailnet
  pueden generar reply). No se abre puerto sin autenticar.
- No se responde a requests con checksum ICMP inválido (input hostil).
- Transform in-place con tamaños acotados en compile-time; el reply tiene la
  misma longitud que el request (sin fragmentación, sin desborde).
- Costo de checksum lineal y bajo (frecuencia de ping baja) — no afecta el
  timing crypto.

## Validación

- **Tests unitarios**: `make -C tests/unit check` — todos PASS (incl.
  test_icmp_echo).
- **Build firmware**: `idf.py build` exitoso sin warnings (-Werror activo).
- **Análisis estático**: cppcheck sin hallazgos en icmp_echo.c ni
  tsnode_client.c.

## Pendiente / bloqueado

- **Prueba de hardware real**: flashear, conectar a la tailnet con ruta
  directa, y `ping 100.x.x.x` desde otro nodo — verificar el reply en logs
  ("WG ICMP echo reply"). La validación end-to-end depende de hardware y de
  una ruta directa (sin DERP en v1). GOAL-5 marcado COMPLETED a nivel de
  código + tests; la confirmación final es hardware.
- GOAL-6 (conexión estable, 99.9% uptime) es el siguiente.
