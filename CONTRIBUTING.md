# Contribuir a OSINT POWER

Abre un issue con el caso de uso, formato esperado y un fixture sintético. Para un nuevo adaptador, sigue [docs/ADAPTERS.md](docs/ADAPTERS.md). Evita dependencias obligatorias de frameworks externos completos: el núcleo debe seguir funcionando con la demo offline.

```bash
npm ci --ignore-scripts
npm test
npm run format
npm run lint
npm run schema
npm audit
```

Las pruebas no deben enviar tráfico a servicios externos ni usar datos de personas reales. Incluye controles de alcance, errores y resultados parciales cuando cambies colección o parsing. Comprueba que stdout del servidor siga siendo exclusivamente MCP.

Documenta lo que está implementado, sus límites y cómo se comprobó. No presentes planes futuros como capacidades existentes. Conserva la licencia MIT y los créditos de los proyectos integrados.
