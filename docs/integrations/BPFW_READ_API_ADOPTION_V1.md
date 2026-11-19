# BPFW Core — evaluación de adopción de consultas de solo lectura

**ID compartido:** BPFW-READ-API-20261119
**Estado:** PROPOSED / NOT_IMPLEMENTED
**Fecha:** 2026-11-19
**Producto:** Blueprint Framework Core público. Documento de adopción; no es una API ya disponible.

## Fuente de contrato

La especificación de API del productor se mantiene en el repositorio BPFW experimental:
[READ_API_FOR_AGENTS_V1.md](https://github.com/LuigiD5555/bpfw-experimental/pull/7).
No copiar el plan completo al Core ni asumir que la versión experimental es la distribución Core actual.

## Estado y frontera del Core

El README de Core expone init, verify, status, lock, unlock, watch y reshard, además de autoridad/blueprint y verificación de drift. No incluye en su superficie pública las herramientas intent/why/trace, Editor y Planner del experimental. Este archivo **no** altera los comandos ni convierte un proyecto Core en experimental.

**Objetivo futuro opcional:** evaluar un subconjunto mínimo de consultas por bloques y capabilities para otros programas, sin duplicar la autoridad del proyecto y sin asumir SQLite.

## Ruta local de trabajo

- C0 Inventario de Core: revisar cargador, formato de bloques, protección de archivos, ruta del CLI, comportamiento real de status/verify y posibilidades de exportar lectura **sin mutar**.
- C1 Contrato/paridad: contrastar las operaciones de la especificación BPFW productora; definir cuáles puede soportar Core sin arrastrar módulos experimentales. Responder UNSUPPORTED_CAPABILITY para las demás.
- C2 Implementación sólo si se aprueba: lectura de capabilities y un subset de bloques, con datos acotados, versión, procedencia y pruebas de no escritura.
- C3 Revisión de compatibilidad: mantener Core pequeño; versionado sin romper CLI anterior; no añadir servidor ni conexión saliente de forma predeterminada.

## Criterios negativos

1. Ninguna consulta nueva dispara verify, status con sincronización, reshard, lock/unlock ni escrituras de shards.
2. Sin prometer propósito, UID o historial donde el Core no los almacene.
3. Ausencia de BPFW experimental no bloquea Core.
4. Identidad, rutas, filtros y límites se validan; no revelar fuentes fuera de la raíz autorizada.
5. La etiqueta de soporte READ_ONLY_VERIFIED exige prueba focal sobre el Core que se instala realmente.

**NEXT_ACTION:** evaluación documental C0 sin modificar el runtime. No ejecutar PR de implementación ni fusionar por esta propuesta. La autoridad de los cambios en Core permanece en este repositorio.
