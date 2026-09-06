# 2026-09-06 — release packaging, rename y sanitización

## Contexto
El proyecto está validado en hardware (GOAL-1..6 y GOAL-8 COMPLETED) y la CI
verde. Se pidió preparar el repo para que terceros puedan usarlo de forma
simple, actualizar el README, renombrar el repo a IOT-Tailscale, y auditar
que no se haya filtrado nada personal/operativo en lo versionado.

## Cambios
- **Rename**: repo GitHub `CrisAlva1414/tailnet-esp32-node` → `IOT-Tailscale`
  (remote actualizado solo por `gh`). Títulos y strings human-facing a
  `IOT-Tailscale`: `AGENTS.md`, `docs/PROJECT-GOALS.md`, `main/main.c` (log),
  `partitions.csv`, `sdkconfig.defaults`. El nombre interno del app/binario
  (`tailnet_esp32_node`) se mantiene para no churnear el build.
- **README** reescrito para terceros: dos caminos de uso (app de referencia
  del banco vs. `tsnode` como librería), generación de auth key, targets/Tier,
  testing, pointers de seguridad, badge de CI.
- **QUICKSTART**: nota de purga de auth key tras primer registro, path
  `.ts_auth_key = NULL` para nodos ya registrados, provisioning por serial
  (ADR-0007). **HOWTO-HUMANS**: se quita el inicio rápido duplicado y queda
  como guía extendida del SDK (config, estados, seguridad, multi-target, debug).
- **`.env.example`** agregado y `.gitignore` ajustado para no ignorarlo
  (`.env` sigue ignorado). El repo sigue sin `.env` ni `docs/private/` trackeado.
- **GOAL-7** → diferido a decisión explícita del operador (eFuse irreversible;
  el dispositivo puede no salir de su entorno controlado). No bloquea compartir.
- **Auditoría ADR-0010**: solo un leak real, un node-id + IP de tailnet en
  `docs/sessions/2026-09-06-ci-display-guard-fix.md` → sanitizado a
  `esp32-<node-id>` / `<ip-tailnet>`. El resto son placeholders
  (`tskey-auth-...`), IPs RFC 5737 o de ejemplo.

## Decisiones de seguridad tomadas o revisadas
- GOAL-7 (flash encryption Release) baja prioridad a decisión operativa; el
  checklist de producción de `docs/INTEGRATION.md` y `docs/adr/0002`/`0003`
  siguen siendo obligatorios para desplegar fuera del banco.
- Sanitización del leak confirma el flujo ADR-0010 (todo versionado público).

## Pendiente / bloqueado
- Nada bloqueante. Integración de `tsnode` en el dispositivo del usuario queda
  a pedido (guía en `docs/QUICKSTART.md` y `docs/INTEGRATION.md`).
- GOAL-7 esperando decisión del operador.