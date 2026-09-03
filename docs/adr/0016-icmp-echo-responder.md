# ADR-0016: ICMP echo responder dentro del túnel WireGuard

- Estado: aceptado
- Fecha: 2026-09-03

## Contexto

GOAL-5 (ping end-to-end) requiere que `ping 100.x.x.x` desde otro nodo de la
tailnet reciba respuesta del ESP32. El data plane WireGuard ya descifra
paquetes transport (GOAL-1), pero descartaba todo paquete IP interno al no
existir una interfaz TUN. Sin responder al ICMP echo request, el ping nunca
obtiene reply.

## Decisión

Implementar un **responder ICMP echo mínimo** dentro del data plane, como
módulo puro y testeable (`src/wg/icmp_echo.c`):

- Cuando el túnel WireGuard entrega un paquete IPv4 interno cuyo protocolo
  es ICMP (1) y es un echo request (type 8, code 0) con checksum ICMP
  válido y offset de fragmento 0, se transforma **in-place** a un echo reply:
  - Swap de src/dst IP.
  - ICMP type 8 → 0 (se conservan identifier, sequence y payload).
  - Recompute del checksum ICMP y del checksum del header IPv4.
- El reply se re-encapsula con la sesión WireGuard existente
  (`tsnode_wg_encap`) y se envía por UDP al endpoint de origen.
- Todo otro paquete interno (TCP, UDP, ICMP no-echo, fragmentos, IPv6,
  checksum ICMP inválido) se descarta como antes (v1 sin TUN).

## Alternativas consideradas

1. **Interfaz TUN real (lwIP)**: requiere el stack TCP/IP completo, memoria
   y superficie considerable — fuera de alcance v1 (AGENTS.md §1). El
   responder ICMP cubre el único caso que GOAL-5 exige (ping).
2. **Responder desde el app layer (main/)**: se implementa en el componente
   (core puro) para mantenerla testeable y reusable, coherente con ADR-0005/0006.

## Consecuencias de seguridad

- La respuesta ocurre **únicamente dentro del túnel autenticado** WireGuard:
  solo peers de la tailnet pueden hacer que se genere un reply. No se abre
  ningún puerto sin autenticar (AGENTS.md §1).
- **Input hostil**: antes de tocar cualquier campo se validan longitudes
  mínimas (IPv4+ICMP), versión=4, protocolo=ICMP, tipo=echo, fragmento=0.
  No se responde a requests con **checksum ICMP inválido** (nunca se
  responde a paquetes corruptos/hostiles).
- El transforms es in-place con tamaños acotados en compile-time; el reply
  tiene la misma longitud que el request (no fragmenta, no desborda).
- No se modifican claves ni nonces; es transformación de bytes del plano de
  datos ya descifrado.

## Consecuencias de estabilidad

- El responder corre en el hot path de recepción WG solo para paquetes que
  llegan como ICMP echo request (baja frecuencia, típicamente pings cada
  1s). El costo de checksum es lineal y pequeño; no afecta el timing crypto.
- Falla cerrada: cualquier error de encap/send loguea y no rompe el bucle
  de recepción (se sigue procesando el siguiente paquete).
