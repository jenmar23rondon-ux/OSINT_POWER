# Roadmap

This lists implemented work and future proposals, not a guarantee of dates or source coverage.

## Implemented in v0.1

JSON CLI, MCP stdio, SQLite evidence/provenance, deduplication, graph, cache, bounded subprocesses, partial results, synthetic offline demo, documentation and Windows/Linux CI.

## Implemented in v0.2

Seven bounded workflows, professional candidate aliases, sourced company/employee/role/technology/public-office context, MX checks, RDAP, RIPEstat ASN/prefix data, public GitHub profiles, Sherlock/theHarvester wrappers, WhatsMyName bridge, TruffleHog secret references and strict breach-summary imports.

## Compatibility and source coverage

- Broader binary compatibility coverage beyond the v0.3 pinned httpx/dnsx/naabu local lab.
- Additional tool dialect/version profiles beyond the v0.3 doctor probes.
- Historical DNS and additional historical URL providers beyond v0.4 Cert Spotter/Wayback.
- Versioned native recon-ng/SpiderFoot importers.
- Additional reviewed business-record sources and local document analysis.
- Public repository exposure connectors without retaining secret values.

## Scale and resilience

- Cross-machine orchestration beyond v0.3 SQLite job leases and explicit recovery.
- Distributed quotas and improved jitter beyond v0.3 shared-workspace reservations/cooldowns.
- Calibrated source-family confidence using labeled data.
- Neo4j/GraphML export; immutable run-to-run comparisons are implemented.
- SARIF and complete graph exports; v0.3 includes bounded JSON/offline interactive HTML.
- Per-tool containers, pinned image digests and provider-specific egress policies.

## Independent validation

Nuclei or other validators would need separate interfaces, scope, budgets and evidence. Current reconnaissance does not automatically confirm vulnerabilities or execute validators.

## Implemented in v0.3

Persistent job/checkpoint recovery, cancellation, worker leases, immutable execution snapshots, coverage-aware comparisons, shared provider quotas/cooldowns, doctor, source-family provenance, ranked planning, 19 MCP tools, an offline interactive report and pinned native loopback lab coverage.

## Implemented in v0.4

Direct Cert Spotter/Wayback connectors and imports, persistent per-target cursors with atomic progress, historical hostname/URL semantics, 20 tool-specific MCP output contracts, separate execution/collection/retry states, normalized evidence packages with offline integrity verification, 17 labeled synthetic benchmark scenarios, evidence freshness/conflict assessments and observed source novelty/request-cost samples in the planner.

## Evidence review

Persistent analyst decisions with append-only history, candidate entity links, contradiction flags and independent-source counts. A shared name or handle is never a confirmed identity. Exposed through additive CLI commands and MCP tools on SQLite schema v5. Package version remains 0.4.0.

## Phishing leads

Deterministic lookalikes of one in-scope apex, then passive enrichment of only those names. Every candidate stays `suspected` until an analyst decides. Package version remains 0.4.0. Schema v5 gains the phishing tables on open and does not rewrite existing evidence.

## Next investigation improvements

- Broaden the labeled corpus with reviewed, publishable datasets and independently maintained gold labels.
- Calibrate source assessments from evaluation data; current confidence remains heuristic.
- Monitor incrementally with reviewed change notifications and source-specific watermarks.
- Add analyst decisions to the offline HTML report. Decisions, candidate links and contradictions are available through CLI and MCP.
- Harden per-tool process/resource/egress isolation and publish reproducible release artifacts.
