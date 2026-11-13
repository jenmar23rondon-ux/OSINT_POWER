# Reliable investigations and run comparisons

Version 0.3 adds durable jobs, sealed snapshots, shared provider budgets, local diagnostics, provenance explanations, ranked planning and an offline HTML report.

## Plan, queue, execute and resume

```bash
node src/cli.js doctor
node src/cli.js plan --workflow company --target example.com
node src/cli.js workflow --workflow company --target example.com --queue
node src/cli.js jobs
node src/cli.js job --id JOB_UUID
node src/cli.js resume --id JOB_UUID --max-calls 10
node src/cli.js cancel --id JOB_UUID
```

Replace example.com with the configured scope. Queueing creates a local job without collection. A workflow with --execute creates and runs a durable job immediately. Do not combine --queue and --execute.

Resume reuses completed checkpoints and frozen target batches. It reevaluates pending dependencies and revalidates scope and settings. Adapter enablement, network/active flags, timeouts and quotas may change; changing scope, collector configuration or selected ports requires a new job/database as applicable.

Each resume has its own logical call budget, defaulting to the original request. There is a **100-call lifetime cap per job** and **three starts per collection step**. Completed checkpoint reuse does not consume another call. Cached collector invocations still count as logical calls.

Partial jobs can remain partial because a source, input or reviewed import is unavailable. Resuming does not invent the missing data. Start a new investigation to refresh completed sources or select newly discovered target batches.

## Worker leases and recovery

A SQLite lease prevents two workers using the same workspace from running the same job. The lease lasts 15 seconds and is renewed while the worker is active. If a process dies, explicitly resume after lease expiry. Opening the application never automatically sends recovery traffic.

Checkpointed steps and completed child runs are reused. A crash after a remote request but before its result was committed may cause that read-only collection to run again: execution is **at least once**, not an exactly-once network guarantee. Provider reservations are retained conservatively.

Cancellation is terminal for that job. Queued jobs cancel without collection. Active workers poll cancellation and abort HTTP, DNS resolution, and native subprocesses. A native timeout or cancellation kills the whole child tree: POSIX signals the detached process group with SIGTERM and then SIGKILL; Windows runs `taskkill /T` and then `taskkill /T /F`. Output beyond the byte cap is truncated with an `[OSINT_POWER_OUTPUT_TRUNCATED]` marker and reported as `RESPONSE_TOO_LARGE`. Each process runs at most four native binaries at once. CPU niceness and Linux `prlimit` CPU-time are best-effort and are not a memory sandbox. Upstream tools can still open their own network connections, and a grandchild that starts a new session is outside the POSIX group. Use host egress controls and a cgroup, job object, or container when that isolation is required.

There is no background scheduler, daemon, automatic task resubmission or cross-machine lease service.

## Immutable snapshots

A workflow result contains:

- **run_id:** the durable job ID used for resume, cancellation and inspection.
- **snapshot_id:** a sealed evidence snapshot for that completed/partial/cancelled execution segment.

The mutable job record accumulates checkpoints. Every settled execution segment creates a separate immutable snapshot. Use snapshot_id for comparisons. Direct collect/import results use their run_id as the immutable capture ID.

```bash
node src/cli.js runs --limit 20
node src/cli.js compare --before SNAPSHOT_UUID --after SNAPSHOT_UUID --limit 25
```

Comparisons require the same workflow/collector and target. Import comparisons require the same importer; the input exports may differ. Different investigation scopes cannot share a database.

| Change           | Meaning                                                                  |
| ---------------- | ------------------------------------------------------------------------ |
| added            | Entity evidence occurs only in the later capture                         |
| evidence_changed | The normalized evidence set differs                                      |
| not_observed     | Earlier evidence was absent from comparable fresh collection             |
| coverage_gap     | A corresponding source was omitted, failed, limited or served from cache |
| unchanged        | Captured evidence set matches                                            |

Absence is never labeled removed. A changed evidence set is not automatic proof that the real-world asset changed. Source failures must not produce a disappearance claim.

Results contain exact change counts, total matching changes, returned count and next_cursor. Source summaries show failures, truncation and original collection times. Cached captures preserve their original observation time and origin run ID.

Pre-v0.3 runs do not have historical snapshots. Migration preserves their accumulated evidence, but cannot reconstruct what a source returned earlier. Comparing such runs reports SNAPSHOT_UNAVAILABLE. Mutable job IDs report USE_IMMUTABLE_SNAPSHOT_ID.

## Provider quotas and cooldowns

```bash
node src/cli.js health
```

HTTP reservations are coordinated in SQLite by provider hostname. Native collectors are coordinated by binary name, and MX by the system DNS collector. Multiple processes must share the same database to share these limits.

Defaults are 60 reservations per minute with the workspace minimum interval. GitHub public API defaults to 60 per hour; HIBP defaults to 10 per minute with at least six seconds between requests. Configure actual subscription/provider limits rather than assuming these defaults match every service.

Example configuration fragment:

```json
{
  "limits": {
    "minIntervalMs": 1500,
    "providers": {
      "maxWaitMs": 5000,
      "overrides": {
        "crt.sh": { "maxRequests": 20, "windowMs": 60000 },
        "api.github.com": { "maxRequests": 60, "windowMs": 3600000 }
      }
    }
  }
}
```

Reservations and failure state survive restarts. 429/401/403 responses and repeated failures open a cooldown. Retry-After is never shortened. If a wait exceeds maxWaitMs, collection returns a deferred result rather than waiting indefinitely. There is no MCP reset or key rotation to bypass a cooldown.

For a native binary, one reservation means one process invocation, not every internal HTTP request. The wrapper cannot enforce per-provider quotas inside third-party tools. Review their native configuration and use host egress controls where necessary.

## Diagnostics

```bash
node src/cli.js doctor
node src/cli.js doctor --skip-probes
```

Doctor reports enabled binary paths, version/help results, missing required flags, schema version, resumable jobs, expired leases, provider state and whether HIBP_API_KEY is present. It never prints raw probe output or key values.

Default probes run bounded local version/help commands without target queries. Skip probes for filesystem/database inspection only. Flag presence is not runtime certification; use the pinned native lab.

## Evidence explanation and planning

```bash
node src/cli.js explain --id ENTITY_HASH
node src/cli.js plan --workflow company --target example.com --max-calls 3
```

Explanations include source families, original captures, input hashes, collection/observation timestamps, cache origin and parser version. Shared CT sources and unknown aggregators are not counted as independent confirmations. `explain_entity` keeps its heuristic `review_status`. Analyst decisions live on the review commands below and do not change that assessment.

The planner ranks registered source/target actions using missing inventory, passive collection preference, prior outcomes, freshness, cache and current provider availability. It does not contact sources or write jobs. Scores are transparent prioritization heuristics, not probabilities or risk scores.

Plans remain bounded. Later targets can be deferred until earlier discoveries exist; execution still checks scope and budgets.

## Evidence review and entity resolution

```bash
node src/cli.js review-queue --limit 25
node src/cli.js show-entity --id ENTITY_HASH
node src/cli.js decide --subject entity --id ENTITY_HASH --decision accept --reason "In-scope and consistent." --analyst analyst-1
node src/cli.js decide --subject finding --id OBSERVATION_HASH --decision reject --reason "Duplicate row." --analyst analyst-1
```

Decisions are `accept`, `reject`, or `needs-more-evidence`. Each one stores the reason, analyst id and timestamp. Older decisions stay in the table. The queue lists entities with no terminal decision, an unconfirmed candidate link, or a contradiction.

Identity links are recomputed from stored observations. The same name or handle on two entities, such as GitHub user `alice` and `alice@example.com`, is always a candidate. Confirmation requires a non-name identifier (a full email address, profile URL, or key fingerprint) supported by at least two independent sources. Sources that share an `upstream`, a `mirror_of` origin, or a collector run count once. Only username, email, profile and employee entities are compared. A decision never merges those entities.

Contradictions are derived when stored sources disagree on an attribute such as `public_company`, `name`, `company`, `title`, `country`, or `account`. They are shown on `show-entity` and keep the entity in the queue. SQLite schema v5 adds `review_decisions` and `entity_links` without rewriting existing evidence.

## Offline HTML report

```bash
node src/cli.js report --format html --output investigation.html
node src/cli.js report --format json --output investigation.json
```

HTML provides a searchable/type-filtered inventory, selectable graph, entity summaries, execution timeline and provider health. It embeds a bounded report with no external assets, scripts, fonts, analytics or network calls. Untrusted content is rendered as text, not HTML. Treat the file as private investigation data.

The core report includes at most 50 entities, 50 relationships and 20 recent runs/jobs. Inventory totals are separate from displayed counts; correlation totals are computed independently from samples. Use CLI/MCP pagination for more.

## MCP additions

| Tool                  | Behavior                                                                   |
| --------------------- | -------------------------------------------------------------------------- |
| start_workflow        | Create a queued job without collection                                     |
| resume_run            | Execute pending steps of a durable job                                     |
| cancel_run            | Request cancellation                                                       |
| get_job / list_jobs   | Inspect durable state                                                      |
| doctor                | Local diagnostics                                                          |
| source_health         | Persisted quotas and cooldowns                                             |
| compare_runs          | Paginated immutable evidence comparison                                    |
| explain_entity        | Provenance and source-family explanation                                   |
| assess_evidence       | Read-only cross-source assessment page; suggestions do not collect         |
| explain_asset         | One asset's assessment, conflicts, review state and suggestion             |
| plan_investigation    | Rank eligible actions without execution                                    |
| list_review_queue     | Unreviewed entities, candidate links, contradictions                       |
| record_decision       | Append an analyst decision; does not confirm identity                      |
| show_entity           | Candidates, contradictions, independence, decision history                 |
| run_phishing_workflow | Suspected lookalikes; execute stores leads and may query passive sources   |
| phishing_report       | Unverified lead report; no collection                                      |
| create_monitor        | Store a monitor definition. No collection and no webhook unless one is set |
| run_monitor           | Re-check scope, collect allowed sources, snapshot and diff                 |
| monitor_changes       | Read one page of stored changes and their evidence identifiers             |
| list_monitors         | List definitions and the latest run status                                 |
| export_stix           | Read-only STIX 2.1 bundle; suspected leads stay suspected                  |
| create_hypothesis     | Store an open hypothesis. No collection and no confirmation                |
| update_hypothesis     | Edit an open hypothesis. Cannot set analyst-confirmed                      |
| close_hypothesis      | Record rejected or analyst-confirmed. Still not a finding                  |
| list_hypotheses       | Read stored hypotheses                                                     |
| evaluate_hypothesis   | Supporting, contradicting and missing evidence. Does not collect           |
| create_case           | Group investigations, targets, hypotheses, decisions and notes             |
| list_cases            | List stored cases                                                          |
| case_summary          | Read one case without collecting                                           |
| case_report           | Separate decisions, candidates, hypotheses and limitations                 |
| export_case_stix      | Existing STIX exporter; hypotheses are notes, not indicators               |
| investigation_graph   | Read-only case or investigation graph. Candidates stay candidates          |

There are **49 MCP tools** in total, including export_evidence, export_stix, the three review tools, `assess_evidence`, `explain_asset`, the five hypothesis tools, the five case tools, `investigation_graph`, the two phishing tools and the four monitor tools. Existing tool names and output schemas are unchanged. execute=true on the seven workflows uses durable jobs. The phishing scan and `monitor run` are synchronous and are not durable jobs. The legacy passive_pipeline is still a synchronous convenience command, without durable workflow recovery. MCP response-envelope changes are documented in the [v0.4 migration guide](V0.4.md). Backup, retention, STIX filters, and the release checklist are in [PRODUCTION.md](PRODUCTION.md).

## Incremental monitor

```bash
node src/cli.js monitor add --name edge --workflow company --target example.com --sources crtsh,naabu --interval 24h
node src/cli.js monitor run --id MONITOR_UUID --max-calls 10
node src/cli.js monitor diff --id MONITOR_UUID --format markdown --output changes.md
node src/cli.js monitor list
```

`interval_hint` is documentation for the operator. Cron or CI must invoke `monitor run`. Opening the application does not schedule anything.

Each run authorizes the target again and skips sources that are disabled, blocked by `network: false`, or blocked because they are active while `active` is false. It does not add adapters or turn those gates off. A deferred run collected nothing and does not replace the previous snapshot.

The diff reports added, removed and changed assets, plus coverage gaps. Removed means the asset was in the previous snapshot and absent from this comparable collection. It is not proof of deletion. If a producing source was skipped, failed, truncated, or stopped by the call budget, absence is a coverage gap and the previous asset is carried forward. Asset types that were not collected at all are carried forward and are not diffed.

Default alerts are `notable` or higher:

| Rule                       | Meaning                                                                                                |
| -------------------------- | ------------------------------------------------------------------------------------------------------ |
| new_certificate_brand_term | New certificate whose names include the apex label or a configured brand term of at least 4 characters |
| new_lookalike_with_mx      | New or newly mail-enabled suspected lookalike. MX does not prove a mailbox                             |
| new_exposed_service        | Newly observed service. An open port or HTTP response is not a confirmed vulnerability                 |
| new_exposure_record        | New breach association or secret location. Not proof of a valid credential                             |

New subdomains and attribute edits are informational unless the minimum is lowered. Set `include_apex_label` false to stop treating the monitored domain's first label as a brand term. The first label is used only when it has at least 4 characters.

New entities from a run stay in the review queue until an analyst decides. The monitor never writes `review_decisions` and never changes a phishing lead from `suspected`.

Alerts are stored in `monitor_alerts` and included in the JSON result. To send them, list the full HTTPS destination in `webhookAllowedUrls` in the workspace configuration, then set that URL on the monitor. Use a public DNS hostname and HTTPS port 443. The allowlist defaults to empty and is checked again for existing monitors. Delivery requires `network: true`, a provider reservation, and public addresses for every DNS answer. The connection uses one validated address with TLS verification for the approved hostname. Redirects fail delivery. Keep full webhook URLs private if their paths or query strings contain tokens.

No alerts means no request. A failed post is recorded as `hook_failed` and the local alert remains. A crash between a successful post and the snapshot commit can cause a duplicate on the next comparable run.

SQLite schema v6 creates `monitors`, `monitor_runs`, `monitor_assets`, `monitor_changes` and `monitor_alerts` with `CREATE TABLE IF NOT EXISTS`. Schema v7 creates `hypotheses`, `cases` and `case_members` the same way. Existing evidence, review, phishing and monitor rows are not rewritten. A database whose `user_version` is newer than v7 is rejected with `DATABASE_VERSION_TOO_NEW`. Snapshots keep at most 2000 assets. A partial or deferred monitor command exits nonzero, matching the other collection commands. Package version remains 0.4.0. STIX export and hypothesis evaluation do not add a table. Opening the database is what stamps `user_version`.

## STIX export

`export-stix` and `validate-stix` are read-only. Filters, the suspected-indicator rule, backup, and the release checklist are documented in [PRODUCTION.md](PRODUCTION.md). An analyst `accept` in the bundle is an opinion. It does not confirm phishing, identity, or ownership.

## Temporal network graph

Query an exact scoped hostname, an IP address, or both. An IP lookup returns DNS answers already recorded for hosts inside the workspace scope.

```bash
node src/cli.js timeline --host api.example.com --since 2026-09-01T00:00:00Z --until 2026-10-01T00:00:00Z --as-of 2026-09-30T23:59:59Z
node src/cli.js timeline --ip 192.0.2.10 --since 2026-09-01T00:00:00Z --until 2026-10-01T00:00:00Z --as-of 2026-10-03T00:00:00Z
```

MCP `temporal_graph` accepts `host`, `ip`, `since`, `until`, and `as_of`. The observation window includes `since` and excludes `until`. An observation must also fall on or before `as_of`, and the workspace must have captured and finished processing it by that cutoff. Reuse the filters and `as_of` when passing `next_cursor` as `cursor` for the next page.

Each edge includes `observed_at`, `collected_at`, `known_at`, and the originating run and observation IDs. A Wayback record can carry a historical observation date and a much later collection date. DNS and HTTP imports without an original timestamp use the parser's observation time at import. The reader uses completed or partial originating captures with provenance and excludes cached copies and mirrors. Workspaces predating capture provenance have no reconstructed history for those older rows.

The query returns point observations for `resolves_to`, `serves`, and `historically_served`. Multiple answers can coexist. Continuous validity, current activity, and ownership require separate evidence.

## Pinned native integration lab

```bash
npm run lab:install
npm run test:lab
```

Installation explicitly downloads official release archives listed in native-tools.lock.json, verifies SHA-256 before extraction and writes binaries only into .lab. Linux requires unzip; Windows uses its included tar utility. It does not install tools globally or install Npcap.

The lab uses loopback HTTP, UDP DNS and a selected TCP-connect port; target fixtures never contact external organizations. Linux CI tests httpx, dnsx and naabu with libpcap-dev. Windows tests httpx/dnsx; naabu is skipped because Npcap is not provisioned. Current installer platforms are Linux/Windows x64.

Regular npm test does not download or run the native binaries. Native cases are skipped there and executed in their separate CI job. Use the pinned lab alongside synthetic parsing, recovery, quota, cancellation and real MCP tests.

## Remaining work

Calibrated confidence, complete graph exports, a hosted dashboard, cross-machine orchestration and stronger per-tool isolation remain roadmap items. Analyst decisions, candidate links and contradiction flags are stored locally; see the evidence-review commands above. v0.4 adds Cert Spotter/Wayback discovery, evidence packages and benchmark controls; see [the release guide](V0.4.md). The HTML report is an offline investigation view, not a multi-user web service.
