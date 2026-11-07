# Contributing

Run `npm run benchmark` alongside the test suite. Changes to parsers, normalization, correlation or source behavior should preserve the labeled expectations in [the benchmark corpus](benchmarks/cases.json). Add reviewed fixture labels for new behavior; synthetic scores do not establish real-world accuracy. Tool-output changes require regenerated schemas and a real MCP contract check. See [benchmark design](docs/BENCHMARKS.md) and [v0.4 migration](docs/V0.4.md).

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

For real binary compatibility, run the opt-in checksum-pinned loopback lab: npm run lab:install, then npm run test:lab. Review native-tools.lock.json before updating versions/digests. See [operations](docs/OPERATIONS.md). Do not add external target traffic to CI.
