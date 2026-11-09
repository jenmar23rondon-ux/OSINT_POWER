# Changelog

## Unreleased

Added a read-only STIX 2.1 export. `export-stix` and `export_stix` turn stored, in-scope evidence into a bundle with deterministic UUIDv5 identifiers. Suspected lookalikes stay suspected indicators, analyst decisions become notes and opinions, and out-of-scope rows are omitted. `validate-stix` checks the bundle offline. An operational runbook and a release checklist are documented in [PRODUCTION.md](docs/PRODUCTION.md). The checklist does not bump the version, tag, or publish a GitHub release. Package version remains 0.4.0. Schema remains v6. Existing MCP tool names and output schemas are unchanged.

Added local incremental monitors. `monitor add|run|diff|list` and the MCP tools `create_monitor`, `run_monitor`, `monitor_changes` and `list_monitors` store a definition, snapshot a run, and diff subdomains, hosts, certificates, DNS records, phishing lookalikes and exposures. Significance rules record an explicit basis. Alerts stay local unless an optional webhook is configured, and that hook is skipped while network access is disabled. There is no scheduler. New entities remain unreviewed. SQLite schema v6 adds the monitor tables without rewriting existing rows and rejects a newer database. Package version remains 0.4.0. Existing MCP tool names and output schemas are unchanged.

Added persistent analyst review decisions (`accept`, `reject`, `needs-more-evidence`) with append-only history, candidate entity links, contradiction flags and independent-source corroboration counts. A shared name or handle never confirms an identity. SQLite schema v5 adds the review tables without rewriting existing evidence. Three MCP tools and CLI commands expose the queue, decisions and entity view. Package version remains 0.4.0. Existing MCP tool names and output schemas are unchanged.

Added a scope-gated phishing lead workflow. It generates deterministic lookalikes of one in-scope apex and can enrich only those names from configured crt.sh, Cert Spotter, domain RDAP, Wayback and active-gated DNS. Candidates stay `suspected`, enter the review queue, and are reported as unverified leads. `phishing-scan`, `phishing-report`, `run_phishing_workflow` and `phishing_report` are additive. Package version remains 0.4.0.

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
