# Changelog

## 0.4.0 — 2026-11-07

Added bounded Cert Spotter and Wayback CDX connectors/imports, atomic persistent continuation, historical hostname/URL relationships and explicit restart. Added deterministic evidence packages, paginated MCP export and offline integrity verification. Every MCP tool now has a validated output schema; the server exposes 20 tools. Partial/deferred collection is separated from execution failure, which changes v0.3 MCP response semantics. Added 17 labeled benchmark scenarios and CI gates, freshness/conflict assessments and planner source-yield/request-cost samples. SQLite schema v4 preserves existing evidence and jobs; original captures are not backfilled with missing provenance.

See [v0.4 operations and migration](docs/V0.4.md).

## 0.3.0 — 2026-11-07

Added durable jobs and checkpoints, lease recovery, cancellation, sealed snapshots, coverage-aware run comparisons, shared provider budgets/cooldowns, local doctor probes, provenance explanations, ranked planning and offline interactive HTML reports. Added ten MCP tools and checksum-pinned native integration labs. Correlation totals now remain separate from samples. Existing evidence is preserved by schema migration; pre-v0.3 historical snapshots cannot be reconstructed.

## 0.2.0 — 2026-11-07

Added seven CLI/MCP workflows with budgets, candidate aliases, professional/public-office context, MX, RDAP, routing ASN data, public GitHub profiles and bounded Sherlock/theHarvester wrappers. Added WhatsMyName, TruffleHog and breach-summary import bridges. Documentation and user-facing workflow names are English; original workflow names remain compatibility aliases.

Secret values/prefixes are discarded. MX, username matches and breaches are not treated as mailbox, identity or credential verification.

## 0.1.0 — 2026-11-07

Initial JSON CLI, MCP server, normalized SQLite evidence, provenance, deduplication, graph, cache, limits, adapters/importers, offline demo and CI. Added project documentation and the supplied banner; preserved Jenmar Rondon's MIT license.
