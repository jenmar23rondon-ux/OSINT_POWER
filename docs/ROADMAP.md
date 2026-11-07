# Roadmap

This lists implemented work and future proposals, not a guarantee of dates or source coverage.

## Implemented in v0.1

JSON CLI, MCP stdio, SQLite evidence/provenance, deduplication, graph, cache, bounded subprocesses, partial results, synthetic offline demo, documentation and Windows/Linux CI.

## Implemented in v0.2

Seven bounded workflows, professional candidate aliases, sourced company/employee/role/technology/public-office context, MX checks, RDAP, RIPEstat ASN/prefix data, public GitHub profiles, Sherlock/theHarvester wrappers, WhatsMyName bridge, TruffleHog secret references and strict breach-summary imports.

## Compatibility and source coverage

- Opt-in binary contract tests against pinned versions in a local lab.
- A doctor command for binary/version checks, including ProjectDiscovery versus Python httpx.
- Historical DNS, certificate alternatives, Wayback and URL history.
- Versioned native recon-ng/SpiderFoot importers.
- Additional reviewed business-record sources and local document analysis.
- Public repository exposure connectors without retaining secret values.

## Scale and resilience

- Durable cancellable jobs and restart recovery; interrupted runs may currently remain running in history.
- Cross-process provider quotas, jitter and circuit breakers.
- Calibrated source-family confidence using labeled data.
- Neo4j/GraphML export and run-to-run diffs.
- Sanitized HTML/SARIF reports and complete paginated exports.
- Per-tool containers, pinned image digests and provider-specific egress policies.

## Independent validation

Nuclei or other validators would need separate interfaces, scope, budgets and evidence. Current reconnaissance does not automatically confirm vulnerabilities or execute validators.
