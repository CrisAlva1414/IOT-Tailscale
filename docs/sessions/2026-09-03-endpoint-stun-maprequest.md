# 2026-09-03 — GOAL-3: Endpoint público via STUN en MapRequest

## Contexto

GOAL-3: MapRequest debía incluir el endpoint público (STUN-descubierto), no
la IP local WiFi (192.168.x.x).

Investigación del flujo actual:
- `tsnode_disco_poll()` envía STUN Binding Request periódicamente y
  `tsnode_disco_stun_parse_response()` extrae correctamente el endpoint
  público (XOR-MAPPED-ADDRESS) en `s_disco.stun.{public_ip, public_port,
  discovered}`.
- Pero `tsnode_map_build_request()` recibía SIEMPRE `s_config.endpoint_ip` /
  `s_config.endpoint_port`, que se poblaban una única vez al arrancar el
  cliente con la IP local WiFi (en `tsnode_simple.c` / `console.c`).
- Resultado: el control plane nunca recibía la IP pública en MapRequest;
  el endpoint local (inútil fuera de la LAN) era el que se reportaba.

## Cambios

- **`components/tsnode/src/disco/disco.h`**: nuevo getter público
  `tsnode_disco_get_stun_endpoint()` — devuelve el endpoint público
  STUN-descubierto (IP + port) o `false` si aún no se descubrió.
- **`components/tsnode/src/disco/disco.c`**: implementación del getter
  (fail-closed: NULL-checks, devuelve `false` si `!discovered`).
- **`components/tsnode/src/proto/tsnode_client.c**:
  - Nuevo helper estático `apply_stun_endpoint_to_config()`: si el disco
    reporta endpoint público descubierto, reemplaza `s_config.endpoint_ip` /
    `endpoint_port` por la IP/port pública STUN.
  - Se llama al inicio de `do_map_poll()` antes de construir cada MapRequest.

## Flujo resultante

1. Primer `do_connect()`: MapRequest inicial usa la IP local WiFi (aún no hay
   STUN; no hay nada que sustituir).
2. Primer poll: se parsea el netmap (STUN server de DERPMap) y
   `tsnode_disco_poll()` envía el Binding Request.
3. `wg_recv_task` recibe la respuesta STUN, la parsea y setea
   `stun.discovered = true`.
4. Segundo poll (30s después): `apply_stun_endpoint_to_config()` detecta el
   endpoint público y lo usa en el MapRequest. De ahí en adelante, la IP
   pública (no la local) es la que llega al control plane.
5. En reconexión, `s_config.endpoint_ip/port` conservan el último endpoint
   público conocido (buen comportamiento: se sigue reportando la última IP
   pública válida hasta que un STUN fresco la confirme/actualice).

## Decisiones de seguridad tomadas o revisadas

- No hay contacto con clave privada: solo se lee el endpoint público del
  estado disco para reportarlo al control plane (dato ya público, va por el
  túnel Noise cifrado).
- El log de `apply_stun_endpoint_to_config()` imprime la IP pública
  (necesaria para debug) — IP pública no es secreto (es visible por cualquier
  peer de la tailnet), no viola ADR-0010.

## Validación

- **Build firmware**: `idf.py build` exitoso sin warnings (-Werror activo).
- **Tests unitarios**: `make -C tests/unit check` — todos PASS (h2, blake2s,
  replay, wg, nacl_box).
- **Análisis estático**: cppcheck sin hallazgos en los archivos modificados.

## Pendiente / bloqueado

- Prueba en hardware real: con el ESP32 en la LAN detrás de NAT, verificar
  en los logs que el segundo MapRequest (poll ~30s) reporta la IP pública
  STUN y no la 192.168.x.x. Esperar a que la tailnet marque el nodo online.
- GOAL-3 marcado COMPLETED a nivel de código + build; falta la validación
  end-to-end en hardware.
