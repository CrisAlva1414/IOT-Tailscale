# ADR-0019: Activación de sesión WG por keepalive y clamp X25519 compatible con mbedTLS

- Estado: aceptado
- Fecha: 2026-09-05

## Contexto

GOAL-5 (ping end-to-end) alcanzado en el data plane WireGuard pero con dos
fallos de hardware que impedían el flujo de datos real:

1. **Sesiones establecidas sin tráfico**: tras `WG session ESTABLISHED`, el
   notebook (tailscaled) no enviaba ni un paquete de datos. Causa raíz: en el
   handshake WireGuard, el **iniciador** debe enviar el primer paquete de
   transporte autenticado (un keepalive transport = `data` vacío, 32 bytes)
   para que el **responder** active su sesión. Ningún lado lo hacía: nosotros
   (iniciador) solo enviábamos transporte cuando había un paquete IP interno,
   y tailscaled esperaba nuestra confirmación.
2. **Respuesta a handshakes entrantes intermitente**: al responder un
   `RX init` del notebook, `create_response` fallaba con
   `E (...) x25519: ecp_mul pubkey failed: -0x4c80` (mbedTLS
   `BAD_INPUT_DATA`) la mitad de las veces. Causa raíz: la versión de mbedTLS
   de ESP-IDF rechaza escalares X25519 con el bit 255 puesto
   (`bitlen == 256`); `create_response` generaba el efímero con
   `random() + pubkey()`, y una clave aleatoria cruda tiene el bit 255 puesto
   con p = 1/2. Reproducido en host contra el fuente exacto de esa mbedTLS.

## Decisión

1. **Keepalive de sesión WG** (implementado en `proto/tsnode_client.c`):
   - Nuevo `wg_send_keepalive(peer_idx)`: encapsula un transport data con
     payload vacío (`tsnode_wg_encap(len=0)`, 32 bytes) y lo envía por UDP al
     endpoint directo del peer (misma resolución que el retransmit).
   - Se envía **inmediatamente** tras `WG session ESTABLISHED` (confirmación
     del iniciador) y luego cada `WG_KEEPALIVE_IDLE_MS = 10s` de idle de
     *transporte autenticado* por peer (trackeado en `s_wg_last_tx_ms[]`),
     dentro del bucle de retransmisión existente.
   - Contador observable `tx_keepalive` en `status`.
2. **Clamp X25519 completo RFC 7748 §5 en el wrapper** (`x25519_wrapper.c`):
   - `tsnode_x25519_publickey` y `tsnode_x25519_shared` ahora limpian bits
     0/1/2, fijan bit 254 y limpian bit 255 (bit 255 era el faltante).
   - `tsnode_wg_create_response` pasa a usar `cr->keygen(priv, pub)` (escalar
     ya clampeado) en vez de `random() + pubkey()`, igual que
     `create_initiation`.

## Alternativas consideradas

1. **No enviar keepalive y esperar que tailscaled active la sesión**: no
   funciona — tailscaled (wireguard-go) no marca usable la sesión del
   iniciador hasta recibir su primer transporte; la sesión quedaba muerta (la
   regla está en la propia arquitectura WireGuard y se confirmó en hardware).
2. **Bump de mbedTLS / usar otra implementación X25519**: el wrapper con
   clamp es un parche de 5 líneas, determinista e idempotente; cambiar la
   pila criptográfica entra dentro del alcance del ADR de crypto y no era
   necesario para el bug.
3. **Reintentar `random()` hasta que bit 255 esté en 0**: sesgado, no
   determinista, y deja el mismo clúster de runtime en `shared()`; el clamp
   es la solución por definición (X25519 clampea su escalar de todas formas).

## Consecuencias de seguridad

- El keepalive es un transport data autenticado de 32 bytes (por diseño de
  WireGuard); no abre superficie nueva: solo peers de la tailnet con sesión
  válida pueden hacer que se envíen, y van al endpoint ya validado por disco
  (ADR-0018). El contador de nonce se incrementa como cualquier transporte,
  sin reuso.
- El clamp del escalar no degrada el secreto: X25519 por definición clampea
  el escalar antes de operar (RFC 7748 §5); mbedTLS era *más estricto* que la
  spec. Limpiar el bit 255 en `shared()` es idempotente para claves ya
  válidas y hace determinista el path de responder (antes, un `RX init`
  legítimo podía no recibir respuesta — DoS trivial de sesión).

## Consecuencias de estabilidad

- 10s de keepalive por peer = 1 UDP pequeño cada 10s por sesión activa
  (despreciable en RAM/CPU; en WiFi, <1 KB/min). Evita el estado "sesión
  establecida pero inutilizable" que mantenía peers fantasma.
- El path de responder deja de depender de un coin-flip criptográfico: la
  respuesta al handshake es determinista y estable bajo carga de handshake
  (rekey del peer cada ~120s observado correctamente).