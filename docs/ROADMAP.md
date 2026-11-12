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

## Incremental monitors

Local monitor definitions, per-run snapshots and diffs for subdomains, hosts, certificates, DNS, phishing lookalikes and exposures. Alerts are local records with an explicit basis. A webhook is opt-in and off by default. There is no scheduler: the operator's cron or CI calls `monitor run`. New entities stay unreviewed. SQLite schema v6 is additive. Package version remains 0.4.0.

## STIX export and production notes

Read-only STIX 2.1 export (`export-stix`, `export_stix`) and an offline bundle validator. Suspected and candidate records are not rewritten as confirmed. The operational runbook and release checklist are documentation only: version stays 0.4.0, and the checklist does not create a tag or a GitHub release. That export does not add a table.

## Evidence intelligence

Read-only `assess`, `assess_evidence` and `explain_asset` turn stored in-scope domains, IPs, ASNs, URLs and technologies into separate historical, activity, attribution, conflict, independence and review statuses. Suggestions stay inside the current gates and do not collect. That reader does not add a table. Package version remains 0.4.0. The synthetic benchmark reports v0.4 versus this reader for attribution precision, recall and false attributions.

## Intelligence agent and case review

Local hypotheses and cases. `evaluate_hypothesis` reads stored evidence and the evidence-intelligence assessment, then returns supporting, contradicting and missing evidence. It can store `open`, `supported-pending-review` or `weakened`. `analyst-confirmed` and `rejected` come only from `close_hypothesis`. A hypothesis is not a finding. Suggested collection steps carry `requires_gate` when network, active mode, or an adapter is missing, and they are not executed. Case reports keep analyst decisions, candidates, hypotheses and limitations apart. `export_case_stix` reuses the STIX exporter and writes hypotheses as notes. SQLite schema v7 is additive. Package version remains 0.4.0.

## Benchmark corpus and investigation graph

The labeled corpus is 52 synthetic scenarios. The runner reports per-category precision and recall, false attributions, scope-block rate, export reproducibility and secret-leak count. Those figures are regression controls. They were not independently reviewed by humans and are not a production accuracy claim. `investigation_graph` and `graph --case` or `graph --investigation` export a read-only graph as JSON or a self-contained offline HTML file. Candidates stay candidates. Package version remains 0.4.0. Schema remains v7.

## Next investigation improvements

The [visual and identity evidence roadmap](VISUAL-IDENTITY.md) tracks image inspection, local image comparison, and account corroboration.

The temporal network graph is available through `timeline` and `temporal_graph`. It queries DNS, HTTP, and archive observations by time window and knowledge cutoff using existing capture provenance. [Temporal graph operations](OPERATIONS.md#temporal-network-graph)

- Broaden the labeled corpus with reviewed, publishable datasets and independently maintained gold labels.
- Calibrate source assessments from evaluation data; current confidence remains heuristic.
- Source-specific watermarks beyond the current per-run snapshot. The monitor does not advance Cert Spotter or Wayback cursors by itself.
- Add analyst decisions to the offline HTML report. Decisions, candidate links and contradictions are available through CLI and MCP.
- Harden per-tool process/resource/egress isolation. The release checklist is documented; signed archives and a published GitHub release are still future work.
