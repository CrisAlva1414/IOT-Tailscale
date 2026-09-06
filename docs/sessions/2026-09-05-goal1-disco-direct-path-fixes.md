# 2026-09-05 — GOAL-1 ciclo 1: fix crítico ct_equal en disco + ruta directa (ADR-0018)

## Contexto

Retomada del loop agent (GOAL-1). Se encontraba trabajo sin commitear en
`disco.{c,h}` y `tsnode_client.c`: disco ahora guarda la `direct_ip/direct_port`
de la fuente del PONG (ruta directa real, p.ej. LAN del peer) y
`update_wg_peers` la prefiere sobre `endpoints[0]` del MapResponse para el
handshake WG (ampliaba ADR-0017). Ese trabajo no tenía tests host.

Al escribir `tests/unit/test_disco.c` (con stubs del port layer) se destaparon
**dos bugs reales en producción**:

1. **`ct_equal` (antes `ct_memcmp`) con semántica invertida en los call sites**:
   la función retorna `true` cuando los buffers son iguales (es un `ct_equal`),
   pero `find_peer_by_disco_key` comparaba `ct_memcmp(...) == 0` (invertido) y
   el encaje del PONG también. Consecuencia: el nodo **nunca reconocía a un peer
   válido** en un PING/PONG disco ("disco from unknown peer" siempre) y, peor,
   un PONG con txid **incorrecto** marcaba `direct_path_ok=true` (no
   fail-closed). Esto explicaba que el handshake disco/PONG nunca confirmara
   ruta directa en hardware y era un candidato directo de por qué el data
   plane WG no arrancaba (RX init=0). Se renombró a `ct_equal` (nombre explícito:
   retorna igualdad, no orden como memcmp) y se corrigieron los call sites.
2. **NULL-deref en `tsnode_disco_get_peer_endpoint`**: faltaba validar
   `ip_out`/`port_out`; un llamador con punteros NULL escribía en NULL.
3. **`TSNODE_DISCO_PING_MIN_LEN` mal calculada**: era 44 pero el PING disco es
   `type(1)+ver(1)+txid(12)+nodekey(32)` = 46. Constante de validación de
   longitud (AGENTS.md §2.2): estaba en el umbral mínimo del `is_disco_packet`
   y de parseo. Corregida a 46.

Además se normalizó `tsnode_port.h` para compilar bajo `-Wpedantic -Werror`
del test host: las macros de log usaban `##__VA_ARGS__` (extensión GNU); se
pasó a la forma ISO `(tag, ...)` con `__VA_ARGS__` (siempre ≥1 argumento), sin
cambiar el comportamiento en firmware. Verificados todos los call sites: nadie
usa `TSNODE_LOGx(TAG)` sin argumento variádico.

## Cambios

- `components/tsnode/src/disco/disco.c`:
  - `ct_memcmp` → `ct_equal` (+fix de los 2 call sites).
  - PONG: guarda `direct_ip/direct_port` desde la fuente del datagrama.
  - `get_peer_endpoint`: valida `ip_out/port_out` NULL; devuelve la ruta
    directa primero, fallback a `endpoints[0]` defensivo.
  - Nuevo `tsnode_disco_find_peer_by_wg_key`.
- `components/tsnode/src/disco/disco.h`: campos `direct_ip/direct_port` en el
  struct de peer; declaración de `find_peer_by_wg_key`; `PING_MIN_LEN` 46.
- `components/tsnode/src/port/tsnode_port.h`: macros de log ISO.
- `components/tsnode/src/proto/tsnode_client.c`: `update_wg_peers` prefiere la
  ruta directa de disco para el handshake WG, fallback a `endpoints[0]`;
  logging diferenció (`(disco direct)`).
- `tests/unit/test_disco.c`: nuevo — cobertura de `find_peer_by_wg_key`,
  `get_peer_endpoint` (ADR-0018), roundtrip completo PING→PONG (incluyendo
  captura de direct path desde la fuente del PONG), respuesta a PING entrante
  con PONG al remitente, y fail-closed ante PONG con txid incorrecto.
- `tests/unit/Makefile`: target `test_disco` + `check`.
- `docs/adr/0018-wg-handshake-disco-direct-path.md`: nuevo ADR.

## Decisiones de seguridad tomadas o revisadas

- El bug `ct_equal` es un hallazgo de **fallos en comparación de secretos**:
  ahora `find_peer_by_disco_key` y el encaje de txid son correctos y
  fail-closed (un peer desconocido o un txid incorrecto no confirman ruta).
  El PONG con txid incorrecto ya no setea `direct_path_ok` (regresión que
  habría permitido "confirmar" ruta con un PONG antiguo/forjado descifrable).
- La ruta directa es input hostil (fuente de datagrama UDP) y solo se usa como
  destino del handshake; la autenticación del peer sigue recayendo en el
  handshake Noise/WireGuard contra la public key firmada del control plane.
- `PING_MIN_LEN=46` protege el parseo de longitudes declaradas (AGENTS.md §2.2).

## Validación

- Tests host: 7/7 bins PASS (incl. test_disco nuevo, 22 checks).
- `test_disco` bajo ASan+UBSan: PASS (destapó el NULL-deref).
- Build firmware (`idf.py build`, target esp32, `-Werror`): PASS, 35% libre.
- cppcheck (flags de static-analysis.md): exit 0.
- Arch guard CI (core sin headers de plataforma, ADR-0006): PASS.

## Pendiente

- Prueba en hardware real (M5Stack Core 2, `/dev/ttyACM0` disponible):
  flashear y verificar que disco ahora confirma PONG ("direct path confirmed")
  y que el handshake WG usa la ruta directa cuando hay conectividad LAN-LAN
  con un peer Tailscale. Sigue siendo el acceptance test de GOAL-1.
- Commitear el bloque (incluye el trabajo que estaba sin commitear + este fix).
  Nótese que GOAL-1 / GOAL-5 se mueven sustancialmente: el bug ct_equal era
  probable causa raíz de no ver PONG ni sesión WG en hardware.