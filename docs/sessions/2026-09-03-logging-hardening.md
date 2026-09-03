# 2026-09-03 — GOAL-4: Logging hardening

## Contexto

GOAL-4: Logging "perfecto" — sin truncamiento de strings, sin caracteres
raros en serial output, timestamps correctos. No había bugs reportados,
pero hacía falta validación exhaustiva.

## Investigación

Revisión de todo el logging del componente (`components/tsnode/`) y del
app layer (`main/`):

- **Port layer**: `default_log()` en `tsnode_port_esp_idf.c` usa un buffer
  fijo de **256 bytes** con `vsnprintf`.
- **Timestamps**: manejados correctamente por `esp_log_write()` de ESP-IDF
  (agrega timestamp + tag + nivel internamente). Sin fix necesario.
- **Caracteres raros**: los dumps REG/JSON usan `%.*s` con chunks acotados
  (200/150 B); el console filtra no-imprimibles en la entrada; los datos
  binarios (claves, nonces, magic disco) se loguean solo en hex.
- **Consola serie** (`main/console.c`): buffers acotados (`snprintf`),
  filtra `< 0x20` y `> 0x7e`, maneja CR/LF correctamente.

### Hallazgo principal (truncamiento)

`default_log()` con buffer de 256 B: varias líneas de debug quedan cerca del
límite:
- `raw /key response (%u bytes): %.200s` → ~240 B
- `REG[%zu]: %.*s` con chunk 200 → ~212 B
- `JSON[%zu]: %.*s` con chunk 150 → ~163 B

El margen era muy fino: cualquier crecimiento de un formato truncaría el
mensaje **silenciosamente** (vsnprintf no avisa). Exactamente lo que GOAL-4
pide evitar.

## Cambios

- **`components/tsnode/src/port/esp_idf/tsnode_port_esp_idf.c`**:
  - Buffer de formato subido de 256 → **512 bytes** (`TSNODE_DEFAULT_LOG_BUF`),
    comentario justificando por qué (dumps de 200 B + prefijo).
  - Detección de truncación **no silenciosa**: si `vsnprintf` indica que el
    mensaje excedía el buffer, se emite un `esp_log_write(WARN, ...)` de
    aviso. Un formato que crezca no pasa desapercibido (AGENTS.md §4).

## Decisiones de seguridad tomadas o revisadas

- El warning de truncación no imprime el contenido (solo el tamaño), así no
  expone posiblemente datos parciales de red.
- No se cambió el nivel de log de ningún mensaje: los dumps de debug (REG/JSON)
  siguen a INFO, como estaban (decisión de banco de pruebas).

## Validación

- **Build**: `idf.py build` exitoso sin warnings (-Werror activo).
- **Tests unitarios**: `make -C tests/unit check` — todos PASS.
- **Análisis estático**: cppcheck sin hallazgos en el archivo modificado.

## Pendiente / bloqueado

- Validación en hardware del serial output (verificar que los timestamps de
  ESP-IDF salen correctamente y que ningún dump se ve cortado). GOAL-4
  marcado COMPLETED a nivel de build + tests; la confirmación visual del
  serial es lo que queda.
