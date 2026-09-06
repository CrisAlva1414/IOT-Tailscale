# AGENTS.md — IOT-Tailscale

> Este archivo es el system prompt operativo para opencode en este repositorio.
> Léelo completo antes de tocar cualquier archivo. Si algo aquí entra en conflicto
> con una instrucción puntual del usuario en el chat, **prevalece este documento**
> salvo que el usuario lo modifique explícitamente y por escrito en este mismo archivo.

## 0. Qué es este proyecto

Cliente Tailscale mínimo en **C puro** (no C++, no ESPHome, no Arduino framework)
para ESP32 (target inicial: ESP32-C3, RISC-V, sobre ESP-IDF), construido desde cero
como reimplementación selectiva — **no fork, no submódulo** — inspirada en el enfoque
de [`alfs/tailscale-iot`](https://github.com/alfs/tailscale-iot).

De ese proyecto se toma **el enfoque**, no el código:

- Confirma que un port de Tailscale a microcontrolador es viable implementando
  solo el subconjunto de protocolo necesario (ts2021 sobre Noise, registro de nodo,
  intercambio de llaves, WireGuard de datos) en vez de portar el cliente Go completo.
- Documenta honestamente sus límites: sin DERP (solo UDP directo/NAT traversal),
  sin IPv6, watchdog resets por intervalos de crypto mal calibrados, dependencia de
  `noise-c` vendorizado y parcheado en build time.
- Es explícito en llamarse a sí mismo "Frankenstein PoC" — código que funciona pero
  que su propio autor no recomienda tocar a mano ni usar como base de producción.

**Este repo existe precisamente para no repetir eso último.** El objetivo no es
"que conecte", es que conecte de forma auditable, con superficie de ataque entendida
y documentada, y con cada decisión de protocolo/memoria/criptografía respaldada por
un ADR. Prioridad explícita, en este orden: **1) seguridad, 2) estabilidad,
3) todo lo demás** (footprint, velocidad de desarrollo, features). Si una feature
compromete 1 o 2, no se implementa hasta que exista un ADR que la justifique y mitigue.

## 1. Alcance real (no idealizado)

Léase como scope, no como aspiración:

- **Sí**: unir un ESP32 a la tailnet personal del usuario (Tailscale SaaS, no
  Headscale), obtener una IP 100.x.x.x, ser alcanzable/alcanzar otros nodos de la
  tailnet mediante WireGuard con NAT traversal directo cuando sea posible.
- **No en v1**: relay DERP (si no hay ruta directa, el nodo simplemente no conecta;
  esto se documenta como limitación conocida, igual que en el proyecto de referencia,
  no se intenta resolver a medias). No en v1 tampoco: IPv6, subnet routing, exit
  node, MagicDNS resolution local, soporte multi-tailnet.
- El usuario ya tiene cuenta Tailscale (SaaS, plan free) y `tailscaled` corriendo en
  su NAS como exit node. Ese NAS **no** es el control plane — el control plane es
  Tailscale (login.tailscale.com / controlplane.tailscale.com). El NAS es simplemente
  otro peer de la tailnet, potencialmente el más cómodo para pruebas de conectividad
  LAN-a-LAN antes de exponer un ESP32 a internet real.

## 2. Modelo de amenaza (obligatorio, sin excepciones)

El usuario fijó explícitamente que **amenaza física y amenaza remota se tratan con
igual prioridad**. Ninguna decisión de diseño puede optimizar una a costa de la otra
sin que el ADR correspondiente lo justifique explícitamente.

### 2.1 Amenaza física (dispositivo robado, accedido, o con acceso físico temporal)

- El ESP32 **no tiene elemento seguro dedicado** en la mayoría de variantes (excepción:
  variantes con ATECC608 externo, que se evalúan aparte vía ADR si el usuario las
  adopta). Esto significa: **toda clave almacenada en flash es extraíble** por
  alguien con acceso físico, tiempo y las herramientas correctas (dump de flash SPI,
  glitching, lectura de eFuse si no están bloqueados). No prometer al usuario
  "inextraíble" — prometer "el costo de extracción es alto y detectable, y el radio
  de daño de una extracción exitosa está acotado".
- Superficie mínima de lo que debe protegerse en reposo:
  - Node key (la identidad WireGuard del dispositivo en la tailnet).
  - Cualquier auth key o token de registro reutilizable (ver 2.3, deben ser
    de un solo uso y expirar).
  - Wi-Fi PSK.
- Mitigaciones obligatorias, en orden de prioridad de implementación:
  1. **NVS encryption** de ESP-IDF habilitado (flash encryption + NVS encryption
     nativos del SoC), no un esquema de cifrado propio en aplicación.
  2. **Flash encryption** en modo Release (no Development) antes de cualquier
     despliegue fuera del banco de pruebas del usuario. Documentar en el ADR
     correspondiente que Development mode dejaría la flash en claro.
  3. **Secure Boot v2** evaluado como siguiente paso, no bloqueante para v1 pero
     con ADR abierto explicando por qué se pospuso y qué lo activaría (ej. el
     dispositivo sale del banco de pruebas hacia una ubicación no controlada).
  4. eFuses de debug (JTAG) deshabilitados en builds de producción; permitidos
     solo en builds de desarrollo, marcados y documentados como tales.
  5. Ningún log, ni siquiera en nivel DEBUG, imprime claves privadas, PSKs o
     tokens completos. Nunca. Ni truncados de forma reversible.

### 2.2 Amenaza remota (red, protocolo, MITM, replay, fuzzing de ts2021/Noise/WireGuard)

- El parseo de cualquier dato que llegue por red (respuestas de control plane,
  paquetes WireGuard, mensajes Noise/ts2021, DHCP/DNS si aplica) se trata como
  **input hostil por defecto**, incluso si "en teoría" viene de Tailscale.
- Reglas de C obligatorias para todo el código que toca bytes de red (ver también
  sección 4):
  - Nada de `strcpy`, `sprintf`, `gets`, ni funciones de la libc sin límite de
    tamaño explícito. Usar variantes `n`/`snprintf` con verificación de retorno.
  - Toda deserialización de mensajes de protocolo valida longitud **antes** de
    tocar el buffer, no después. Longitudes declaradas por el peer nunca se confían
    ciegamente para `malloc`/`memcpy` sin un techo (cap) fijo conocido en compile time.
  - Aritmética de tamaños de buffer siempre revisada por overflow (usar
    comprobaciones explícitas o `__builtin_add_overflow` / equivalentes, no confiar
    en que "nunca va a pasar de X").
  - Nonces de Noise/WireGuard: nunca reutilizados, contador monotónico verificado,
    ventana anti-replay implementada y testeada explícitamente (ADR + test).
- El estado "sin DERP" del proyecto de referencia se hereda como limitación conocida
  de v1, pero se documenta el corolario de seguridad: sin DERP, el nodo depende de
  conectividad directa; no se debe "simular" un fallback inseguro (ej. abrir un
  puerto sin autenticar como workaround) para resolver conectividad. Si no hay ruta
  directa, el nodo no conecta y lo reporta, punto.
- Watchdog / crypto timing: el proyecto de referencia documenta haber tenido resets
  por intervalos de crypto mal calibrados. Aquí eso se trata como bug de estabilidad
  Y de seguridad a la vez — un dispositivo que resetea impredeciblemente bajo carga
  criptográfica es un vector de DoS y una señal de que el timing no está bien
  entendido. No se "ajusta el número hasta que deje de resetear"; se mide, se
  documenta el presupuesto de tiempo real disponible, y se ADR-ea la solución.

### 2.3 Autenticación del dispositivo ante Tailscale (SaaS)

El usuario usa Tailscale oficial, no Headscale. Esto implica:

- Las **auth keys** se generan desde la consola de Tailscale
  (https://login.tailscale.com/admin/settings/keys), nunca se hardcodean en el
  repo, nunca se commitean ni siquiera en un archivo "de ejemplo" con valor real.
- Auth keys usadas por este proyecto deben ser, salvo ADR que justifique lo
  contrario:
  - **De un solo uso** (`reusable: false`) para el registro inicial de cada
    dispositivo físico.
  - **Con expiración corta** (días, no meses) configurada en la consola.
  - **Tagueadas** (ej. `tag:esp32-iot`) para poder aplicar ACLs de Tailscale
    restrictivas a estos nodos sin depender de que el humano recuerde hacerlo
    cada vez.
- Tras el registro inicial, el dispositivo pasa a autenticarse con su propia
  **node key** (generada localmente, la pública se registra en el control plane).
  La auth key inicial no se reutiliza ni se conserva en flash una vez consumida.
- Provisioning de la auth key hacia el dispositivo (cómo llega la key al ESP32 la
  primera vez) es una decisión de seguridad de primer orden, no un detalle
  operativo. Debe resolverse con un ADR explícito antes de escribir código de
  provisioning. Opciones a evaluar ahí (no elegir por defecto sin registrarlo):
  provisioning por USB/serial en banco de pruebas controlado (menor superficie),
  vs. provisioning por Wi-Fi AP temporal (mayor superficie, requiere su propio
  modelo de amenaza para la ventana de setup).
- ACLs de Tailscale: se recomienda al usuario (documentar en ADR, no asumir que
  ya existe) restringir explícitamente qué puede alcanzar un nodo `tag:esp32-iot`
  dentro de la tailnet, en vez de dejar el default "todos los nodos se ven entre
  sí" del plan free.

## 3. Estructura del repositorio

Al inicializar, opencode debe crear exactamente esta estructura (los directorios
vacíos llevan un `.gitkeep` si no hay contenido aún):

```
.
├── AGENTS.md                      # este archivo
├── README.md                      # qué es, qué NO es, estado actual, cómo correr
├── LICENSE
├── .gitignore                     # incluye sdkconfig con secretos, build/, *.pem, *.key
├── CMakeLists.txt                 # build ESP-IDF, sin ESPHome de por medio
├── sdkconfig.defaults             # flash encryption / secure boot flags documentados
├── main/
│   ├── CMakeLists.txt
│   ├── main.c
│   └── ...                        # se define incrementalmente, ver §5
├── components/
│   └── tsnode/                    # componente propio, nombre provisional confirmar con ADR-0001
│       ├── CMakeLists.txt
│       ├── include/
│       └── src/
├── third_party/
│   └── README.md                  # política de vendoring: qué se vendoriza, por qué,
│                                   # cómo se audita antes de entrar (ver §6)
├── tests/
│   ├── unit/
│   └── protocol_vectors/          # test vectors de Noise/WireGuard conocidos
└── docs/
    ├── adr/
    │   ├── 0000-template.md
    │   └── 0001-record-architecture-decisions.md
    ├── private/                   # NO versionado (gitignore): ops personales,
    │                              # runbooks del despliegue propio, credenciales
    │                              # de entorno — ver ADR-0010
    ├── sessions/
    │   └── .gitkeep                # una entrada por sesión de trabajo, ver §7
    └── format/
        └── .gitkeep                # convenciones de código/commit, ver §8
```

**Regla transversal de privacidad documental (ADR-0010):** todo lo versionado
es público. Ningún `.md` ni comentario de código puede contener SSIDs, PSKs,
IPs reales (tailnet o LAN), tokens, ni detalles identificatorios del despliegue
personal del operador — usar placeholders (`<ssid>`, `<ip-tailnet>`, etc.) y
llevar el detalle sin sanitizar a `docs/private/`. Checklist y placeholders en
`docs/format/documentation-privacy.md`.

No se crean `main/*.c` de funcionalidad real en la sesión de inicialización.
Inicializar = estructura + docs + build system vacío que compila un "hello world"
de ESP-IDF sin lógica de Tailscale todavía. La lógica de protocolo empieza
**después** de que exista al menos ADR-0001 y ADR-0002 (ver §6).

## 4. Reglas de C — no negociables

Este proyecto es C, no "C con hábitos de C++". Se aplica sobre ESP-IDF (que expone
FreeRTOS + libc de newlib), target embebido con RAM y flash limitados.

- **Estándar**: C11 con dialecto GNU. Firmware: `-std=gnu11 -Wall -Wextra
  -Werror` (sin `-Wpedantic`: los headers de ESP-IDF/newlib disparan pedwarns
  de preprocesador insuprimibles; evidencia y compensación en
  `docs/format/c-style.md`). Tests host (`tests/unit/`, sin headers de
  ESP-IDF): `-std=c11 -Wall -Wextra -Wpedantic -Werror` completos.
  Actualizado 2026-08-20 con confirmación explícita del usuario en el chat.
  `-Werror` no se desactiva "temporalmente" para avanzar más rápido; si algo
  rompe el build por un warning, se arregla el warning.
- **Sin asignación dinámica no acotada en runtime crítico**: preferir buffers
  estáticos con tamaño máximo conocido en compile time para todo lo que toca el
  hot path de red/crypto. Si se necesita heap, documentar por qué en el ADR
  correspondiente y verificar fragmentación bajo uso sostenido (ESP32 con heap
  fragmentado es una causa común de crash tras horas/días de uptime, no minutos —
  no basta con "arrancó y funcionó").
- **Manejo de errores explícito**: toda función que puede fallar retorna un código
  de error revisado en el call site. Nada de ignorar retornos de funciones de
  criptografía, red, o NVS. Un `(void)` explícito para descartar un retorno se
  permite solo cuando el ADR o el comentario in situ explica por qué es seguro
  ignorarlo.
- **Sin macros que oculten control de flujo** de forma no obvia (nada de macros
  que hagan `return` o `goto` implícito sin que se lea clarísimo en el call site).
- **`goto` permitido y preferido** para limpieza de recursos en un único punto de
  salida por función (patrón estándar en C embebido/kernel), sobre múltiples
  `free`/`return` dispersos que son fuente típica de use-after-free o memory leak.
- **Constant-time donde importa**: comparación de MACs, claves, tokens — nunca
  `memcmp` directo. Usar comparación en tiempo constante explícita y documentar
  en el ADR de crypto por qué cada comparación sensible la usa.
- **Fuzzing** de los parsers de protocolo (ts2021/Noise/WireGuard) se planifica
  desde el ADR de arquitectura de protocolo, no se agrega "después si hay tiempo".
- **Análisis estático** corre en cada sesión relevante: `cppcheck` y/o
  `clang-tidy` como mínimo, configuración versionada en `docs/format/`. Un
  hallazgo de análisis estático relacionado a memoria o crypto no se descarta sin
  justificación escrita.

## 5. Cómo debe trabajar opencode en este repo

1. **Antes de escribir código de protocolo**, confirmar que existen ADRs para:
   arquitectura general del componente (ADR-0001), modelo de amenaza aceptado
   (ADR-0002, esencialmente formalizando la §2 de este documento con las
   decisiones específicas que se vayan tomando), y estrategia de manejo de
   claves en flash (ADR-0003). Si no existen, crearlos primero.
2. **Una sesión de trabajo = una entrada en `docs/sessions/`.** Ver formato en §7.
   No se cierra una sesión sin dejar la entrada escrita, incluso si el resultado
   fue "no avancé, bloqueado por X".
3. **Cambios de arquitectura o de superficie de seguridad = ADR nuevo**, no una
   nota suelta en el commit. Si opencode detecta que una tarea pedida por el
   usuario implica una decisión de este tipo sin ADR previo, se detiene y lo
   señala antes de escribir código, no lo decide unilateralmente.
4. **No se optimiza prematuramente el footprint de memoria a costa de claridad
   del manejo de errores o de la seguridad.** ESP32-C3 tiene margen razonable de
   RAM/flash para un cliente mínimo si se es disciplinado; no se sacrifica una
   verificación de límites por ahorrar algunos bytes salvo que un ADR con datos
   reales de uso de memoria lo justifique.
5. **No se marca nada como "listo para producción" o "seguro" sin que exista al
   menos**: build en modo Release con flash encryption activa probado en
   hardware real, análisis estático limpio o con hallazgos justificados, y los
   test vectors de protocolo pasando.
6. Cuando opencode no tenga certeza técnica (ej. comportamiento exacto de un
   registro de ts2021, tamaño de un campo, versión de protocolo Noise usada por
   Tailscale actualmente), **lo dice explícitamente y busca la fuente primaria**
   (código de Tailscale, spec de WireGuard/Noise) en vez de asumir un valor
   plausible. Un valor de protocolo asumido incorrectamente es un bug de
   seguridad silencioso, no un detalle menor.

## 6. Vendoring y dependencias de terceros

- Toda dependencia externa (ej. una implementación de Noise, de ChaCha20-Poly1305,
  de Curve25519) entra a `third_party/` con: origen exacto (repo + commit/tag),
  razón por la que se vendoriza en vez de reimplementar, y qué se hizo para
  verificar que no es una fuente comprometida (revisar historial, stars/forks,
  si tiene CVEs conocidos, si está mantenida).
- Preferencia explícita por bibliotecas de criptografía **auditadas y maduras**
  (ej. mbedTLS, que ya viene con ESP-IDF, o monocypher si el footprint mbedTLS
  no calza) sobre implementaciones ad-hoc encontradas en un repo de referencia
  tipo PoC. El proyecto `alfs/tailscale-iot` vendoriza `noise-c` y lo parchea en
  build time — eso es aceptable para un PoC personal del autor original, pero
  aquí cualquier decisión equivalente pasa primero por ADR evaluando alternativas
  mantenidas.
- Nunca se copia código directamente de `alfs/tailscale-iot` línea por línea.
  Se puede **leer** ese repo como referencia de protocolo/arquitectura (está en
  MIT o licencia que se debe confirmar antes de citar) pero este proyecto es una
  reimplementación propia. Si en algún punto se decide portar una función
  puntual literalmente, eso se documenta explícitamente en el ADR y en el
  comentario del código, con atribución.

## 7. Formato de `docs/sessions/`

Un archivo por sesión: `docs/sessions/YYYY-MM-DD-slug-corto.md`. Estructura mínima:

```markdown
# YYYY-MM-DD — <slug corto>

## Contexto
Qué se buscaba lograr en esta sesión.

## Cambios
- Lista concreta de lo que se tocó (archivos, ADRs creados/modificados).

## Decisiones de seguridad tomadas o revisadas
Si esta sesión tocó algo de §2, se explicita aquí aunque ya esté en un ADR.

## Pendiente / bloqueado
Qué queda para la próxima sesión, y por qué no se cerró ahora.
```

**Las sesiones son públicas y se escriben sanitizadas desde el origen**
(ADR-0010): sin SSIDs, PSKs, IPs de tailnet/LAN, tokens ni datos identificatorios
del despliegue personal — placeholders (`<ssid>`, `<ip-tailnet>`) y el detalle
operativo sin sanitizar va a `docs/private/` (no versionada). Checklist en
`docs/format/documentation-privacy.md`.

## 8. Formato de `docs/format/`

Contiene las convenciones vivas del proyecto, separadas por archivo:

- `docs/format/c-style.md` — estilo de código C (naming, indentación, organización
  de headers, convenciones de esta base específicas más allá de lo ya fijado en §4).
- `docs/format/commits.md` — convención de mensajes de commit (conventional commits
  o el esquema que se decida; debe quedar fijado antes del primer commit real).
- `docs/format/adr-process.md` — cómo se numeran, cuándo se marcan como
  `superseded`, quién puede proponer uno (spoiler: cualquiera, incluyendo opencode
  cuando detecta que una tarea lo requiere).

## 9. Plantilla ADR (`docs/adr/0000-template.md`)

```markdown
# ADR-XXXX: <título corto>

- Estado: propuesto | aceptado | rechazado | superseded por ADR-YYYY
- Fecha: YYYY-MM-DD

## Contexto
Qué problema o decisión motiva este ADR.

## Decisión
Qué se decidió, en términos concretos y accionables.

## Alternativas consideradas
Qué otras opciones se evaluaron y por qué se descartaron.

## Consecuencias de seguridad
Obligatorio, no opcional. Qué cambia en el modelo de amenaza (§2) con esta
decisión. Si la respuesta es "nada", decirlo explícitamente y por qué.

## Consecuencias de estabilidad
Qué riesgo de estabilidad (crashes, resets, degradación bajo carga/tiempo)
introduce o mitiga esta decisión.
```

`ADR-0001` debe fijar como mínimo: nombre definitivo del componente, target de
hardware confirmado (ESP32-C3 u otro), y el diagrama de alto nivel de qué hace
cada módulo. `ADR-0002` formaliza el modelo de amenaza de §2 con cualquier
precisión adicional que surja al implementar. `ADR-0003` fija la estrategia de
almacenamiento de claves (NVS encryption + flash encryption, alcance de Secure
Boot v2 en v1).

## 10. Esquema documental heredado de BuzzSound

Este proyecto no comparte dominio con BuzzSound, pero sí hereda su disciplina
documental de trabajo por sesiones e iteración incremental versionada
(`SPRINT_0X.md` allá → `docs/sessions/` acá) y su costumbre de declarar
explícitamente separación de responsabilidades entre componentes antes de
escribir la integración entre ellos. Si el usuario pide revisar cómo se hizo
algo específico en BuzzSound (formato exacto de un sprint, convención de
commits, etc.), opencode debe pedir ver el archivo real en `proyectos/BuzzSound`
en vez de asumir el formato — este documento describe el espíritu, no una
copia exacta de esa estructura.

## 11. Qué hacer si algo en este documento queda obsoleto

Este AGENTS.md se versiona como cualquier otro archivo. Si una decisión aquí
descrita cambia (ej. se decide sí soportar DERP, o se cambia de Tailscale SaaS
a Headscale), el cambio se hace vía ADR primero, y **después** se actualiza este
archivo para reflejarlo, nunca al revés. opencode no debe auto-modificar este
archivo para "flexibilizar" una regla de seguridad sin que exista ese ADR previo
y sin confirmación explícita del usuario en la conversación.
