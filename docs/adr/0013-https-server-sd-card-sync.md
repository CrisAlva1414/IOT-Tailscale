# ADR-0013: HTTPS server + SD card file sync

- Estado: **propuesto**
- Fecha: 2026-09-01

## Contexto

El ESP32 está registrado en la tailnet con IP `<ip-tailnet>` y tiene WireGuard data plane funcional (handshake + transport). Falta hacerlo **alcanzable** para que otros nodos puedan enviarle consultas.

Caso de uso del usuario:
- El ESP32 almacena datos en una **SD card** (sensores, logs, archivos)
- El **notebook** hace polling cada ~10 minutos buscando archivos no sincronizados
- Comunicación vía **HTTPS** sobre la tailnet (WireGuard tunnel)

## Decisión

### 1. HTTPS server mínimo en el ESP32

- HTTP/1.1 server simple (no HTTP/2 para simplificar)
- Escucha en puerto **443** (HTTPS) sobre la interfaz WireGuard (IP 100.x.x.x)
- TLS con certificado self-signed generado en el primer boot
- Endpoints:
  - `GET /status` — estado del dispositivo (uptime, SD free space, file count)
  - `GET /files` — lista de archivos en SD con metadata (nombre, tamaño, timestamp)
  - `GET /files/<name>` — descarga un archivo específico
  - `HEAD /files/<name>` — verifica si el archivo existe (para sync check)

### 2. SD card storage

- SD card en slot del M5Stack Core 2 (SPI bus)
- Formato FAT32 (compatible con cualquier OS)
- Estructura de directorios:
  ```
  /sdcard/
  ├── data/           # archivos de datos del ESP32
  │   ├── sensor_20260901.csv
  │   └── ...
  ├── metadata.json   # índice de archivos para sync rápido
  └── config.json     # configuración del dispositivo
  ```

### 3. File sync protocol

El notebook (cliente) hace polling:
1. `GET /files` → obtiene lista de archivos con timestamps
2. Compara con archivos locales descargados
3. `GET /files/<name>` → descarga archivos nuevos
4. `HEAD /files/<name>` → verifica si un archivo cambió

### 4. Certificado self-signed

- Generado en el primer boot con `mbedtls`
- Almacenado en NVS (cifrado vía ADR-0003)
- Fingerprint del certificado visible en consola serial para verificación
- El notebook debe aceptar el certificado (curl -k o equivalente)

## Alternativas consideradas

- **HTTP en vez de HTTPS**: descartado — aunque el tráfico va por WireGuard (cifrado), HTTPS agrega autenticación del servidor y previene MITM si el WireGuard se compromete. Overhead mínimo en ESP32.
- **MQTT en vez de HTTP**: descartado para este caso de uso — MQTT es mejor para telemetría continua, pero para sync de archivos HTTP es más simple y directo. El usuario mencionó MQTT pero descidió HTTPS para el sync.
- **WebSocket**: descartado — polling simple cada 10min no necesita persistent connections.
- **rsync/scp**: descartado — demasiado complejo para el ESP32. HTTP GET es suficiente.

## Consecuencias de seguridad

- **TLS self-signed**: el notebook debe configurar `--insecure` o instalar el CA. trade-off aceptable para LAN/confianza.
- **Sin autenticación del cliente**: cualquier nodo en la tailnet puede acceder. Mitigación: ACLs de Tailscale (ADR-0002) restringen qué nodos alcanzan al ESP32.
- **SD card contents**: los archivos en SD NO están cifrados (fuera de alcance v1). trade-off: el atacante con acceso físico ya puede extraer la SD. La flash encryption protege las claves, no la SD.
- **Buffer overflow en HTTP parsing**: input hostile por defecto (ADR-0008). Usar parsing mínimo con límites fijos.

## Consecuencias de estabilidad

- **TLS handshake**: mbedTLS TLS server consume ~20KB de RAM. Verificar que el heap es suficiente con WG + TLS concurrente.
- **SD card polling**: SPI bus puede interferir con WiFi si se usa simultáneamente. Mitigación: SD solo se accede cuando no hay tráfico WG activo.
- **Watchdog**: HTTP server no debe bloquear el watchdog. Usar non-blocking I/O o timeouts cortos.
