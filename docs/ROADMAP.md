# Roadmap

Este documento describe trabajo pendiente. No es una lista de capacidades ya disponibles ni un compromiso de fechas.

## v0.1 — base implementada

- CLI JSON y servidor MCP stdio con validación y pruebas de protocolo.
- SQLite: entidades, evidencias, relaciones, historial y caché.
- Adaptadores y puentes descritos en la matriz del README.
- Scope, exclusiones, ejecución secuencial, límites, resultados parciales y demo offline.
- README con banner, licencia MIT, documentación y CI.

## Siguiente versión: compatibilidad y cobertura

- Pruebas optativas de contrato con versiones fijadas de subfinder, Amass, dnsx, httpx y naabu en un laboratorio local.
- Detección de binario y versión en un comando `doctor`; evitar confundir httpx con el paquete Python del mismo nombre.
- RDAP, DNS histórico con proveedores configurados, certificados alternativos, Wayback y URLs históricas.
- Importadores nativos versionados para recon-ng y SpiderFoot; conectores con fixtures de sus versiones.
- Metadatos adicionales y OCR local optativo, revisión y minimización de datos personales.
- Conectores de repositorios públicos y búsqueda de exposiciones sin persistir valores de secretos.

## Escalabilidad

- Trabajos persistentes cancelables y recuperación tras reinicio; ahora una ejecución interrumpida puede quedar como `running` en el historial.
- Cuotas por proveedor persistentes entre procesos, jitter y circuit breakers.
- Familias de fuentes y scoring calibrado con corpus etiquetado. Hoy las puntuaciones son heurísticas y no se suman fuentes como si fueran independientes.
- Exportación de grafo Neo4j/GraphML y diffs entre ejecuciones.
- Informes HTML/SARIF sanitizados y exportación completa paginada.
- Contenedores por herramienta, versiones/digests fijados y políticas de salida por proveedor.

## Validación independiente

Nuclei y otros validadores tendrían su propia interfaz, alcance, límites y evidencia. No se ejecutan en el pipeline de OSINT actual ni se convierten observaciones en vulnerabilidades confirmadas.
