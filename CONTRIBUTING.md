# Contributing

Open an issue with the use case, expected contract and a synthetic fixture. Follow [adapter guidance](docs/ADAPTERS.md) for new sources. Keep the offline core usable without installing entire third-party frameworks.

```bash
npm ci --ignore-scripts
npm test
npm run format
npm run lint
npm run schema
npm audit
```

Tests must not contact external targets or contain real personal information. Cover scope, malformed inputs, partial results and errors when changing collection/parsing. Preserve stdout as exclusively MCP in the server.

Document implemented behavior, compatibility and validation. Keep planned capabilities distinct. Preserve MIT notices and upstream credits. Documentation, examples, templates and user-facing messages are maintained in English.
