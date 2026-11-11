# Production operations and release checklist

Package version remains **0.4.0**. This document describes how to run a workspace and how to record a reproducible check of the tree. It does not cut a release: do not bump `package.json`, do not create a git tag, and do not publish a GitHub release from this checklist.

SQLite schema **v7** is unchanged by STIX export. Export only reads stored rows. Hypothesis and case tables are created when the database is opened, not when a bundle is exported.

## Install

Requires Node.js 24.14 or newer and Git. Install from the lockfile and do not run dependency lifecycle scripts:

```bash
git clone https://github.com/jenmar23rondon-ux/OSINT_POWER.git
cd OSINT_POWER
npm ci --ignore-scripts
node src/cli.js init
```

`init` refuses to overwrite `config.json`. The demo and `npm test` send no traffic. Node may print an experimental SQLite warning on stderr. Stdout of the CLI stays JSON.

External binaries (subfinder, dnsx, httpx, naabu, and the others in the source matrix) are not installed by `npm ci`. Enable one only after it is on `PATH` and, for the pinned lab, after `npm run lab:install`.

## Configuration, scope, and active mode

```bash
node src/cli.js doctor --skip-probes
```

`network: false` blocks remote collectors. `active: false` blocks DNS, HTTP, and port checks even if `network` is true. `enabledAdapters` is the allowlist. Export, review, planning, and bundle verification do not turn those switches on and do not contact sources.

```json
{
  "version": 1,
  "scope": {
    "domains": ["example.com"],
    "excludeDomains": ["excluded.example.com"],
    "ips": [],
    "emails": []
  },
  "network": false,
  "active": false,
  "enabledAdapters": ["crtsh"]
}
```

Use one database per scope. The file is `.osint-power/state.sqlite` next to the configuration unless `--db` or `OSINT_POWER_DB` is set. Opening a database with a different scope fingerprint fails with `SCOPE_DATABASE_MISMATCH`. A discovered IP is not permission to scan it. Excluded domains win over included parents.

The MCP server reads `OSINT_POWER_CONFIG` and `OSINT_POWER_DB`. Stdout is the protocol. Diagnostics stay on stderr.

## Monitors from cron or CI

There is no scheduler in this process. `interval_hint` is a note for the operator. A cron entry or a CI schedule must call the CLI itself:

```bash
node src/cli.js monitor run --id MONITOR_UUID --config config.json --db .osint-power/state.sqlite
node src/cli.js monitor diff --id MONITOR_UUID --format markdown --output changes.md
```

`monitor run` re-checks the current scope and the network, active, and adapter gates. It does not enable a source that the configuration already disables. A deferred run collects nothing and does not replace the previous snapshot. New entities stay unreviewed. Alerts stay in SQLite unless a webhook URL was stored and `network` is already true. See [OPERATIONS.md](OPERATIONS.md) for coverage gaps and the significance rules.

Do not point cron at a workspace whose scope you do not control. Overlapping runs share the SQLite lease and provider reservations; they do not bypass them.

## Backup and restore

Stop every CLI and MCP process that has the database open before copying it. Windows keeps the WAL and shared-memory files locked until those handles close.

```bash
node --input-type=module -e '
import { DatabaseSync } from "node:sqlite";
const db = new DatabaseSync(".osint-power/state.sqlite");
db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
db.close();
'
cp .osint-power/state.sqlite backups/state-$(date -u +%Y%m%dT%H%M%SZ).sqlite
```

On Windows, close the processes, run the same checkpoint, then copy `state.sqlite`. After `wal_checkpoint(TRUNCATE)` the `-wal` and `-shm` sidecars should be empty or absent. If a checkpoint cannot run, copy the database together with both sidecars or the restored file will be missing the latest commits.

Restore only while nothing has the destination open. Replace `state.sqlite` with the backup. Do not copy a backup from a newer build onto an older checkout: if `PRAGMA user_version` is newer than this code, open fails with `DATABASE_VERSION_TOO_NEW` and the file is not rewritten.

A backup contains the scope, evidence, review history, phishing leads, and monitor snapshots. Treat it as the investigation, not as a redacted report.

## Schema migration

Opening a database creates any missing v6 and v7 tables with `CREATE TABLE IF NOT EXISTS` and sets `user_version` to 7. Existing evidence, decisions, phishing rows, monitor rows, and jobs are not rewritten. v4, v5 and v6 databases gain the later tables on open. Pre-v0.3 runs still cannot be reconstructed as historical snapshots.

STIX export does not add a table and does not change `user_version`. A failed export leaves the previous rows in place.

## Retention and redaction

Nothing in this project deletes old observations, decisions, or monitor history on a timer. Review decisions are append-only. Monitor asset snapshots keep at most 2000 assets per run; older runs remain until an operator removes them. Cache rows expire by their TTL. The database is not encrypted.

`export-stix` copies in-scope stored values into a JSON file the operator asked for. Emails, URLs, titles, and notes are included when they passed scope and the filters. Out-of-scope entities are omitted. Suspected lookalikes of an in-scope apex are included only as suspected indicators. The exporter does not edit the database to redact it.

Before handing a bundle, backup, or HTML report to anyone else, review it. To keep a value out of an export, do not store it, or remove that row with your own SQL while the application is stopped, then export again. There is no separate redaction pass and no claim that free-text evidence has been scrubbed.

## STIX 2.1 export

```bash
node src/cli.js export-stix --target example.com --output bundle.json
node src/cli.js export-stix --investigation company --review accepted --since 2026-06-01T00:00:00.000Z --until 2026-06-30T23:59:59.000Z
node src/cli.js validate-stix --file bundle.json
```

`--output` writes only the STIX bundle, mode `0600` on platforms that honor it, and refuses to overwrite. Stdout stays the CLI JSON summary. Without `--output`, the summary includes the bundle. `validate-stix` reads a file of at most 50 MB and does not open a workspace or the network.

MCP tool `export_stix` takes the same filters (`investigation`, `target`, `review_status`, `since`, `until`) and returns the bundle. It is read-only. `export_case_stix` calls that exporter for the case's investigations and targets, then adds each hypothesis as a note. `investigation_graph` reads one case or one investigation as JSON or a self-contained offline HTML file. Candidate links are not rendered as confirmed. Existing tool names and output schemas are unchanged. The server exposes **44** tools.

| Filter            | Effect                                                                                                                                   |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `target`          | In-scope domain, IP, email, or declared person. Anything else is `OUT_OF_SCOPE` or `INVALID_INPUT`.                                      |
| `investigation`   | Workflow name (`company`, `phishing`, `collectors`, …), a monitor UUID, or a run/job UUID. An unknown UUID is `INVESTIGATION_NOT_FOUND`. |
| `review`          | `any` (default), `accepted`, `rejected`, `needs-more-evidence`, or `unreviewed`, using the latest entity decision.                       |
| `since` / `until` | Inclusive observation, lead, or decision times. `accepted` still does not mean confirmed.                                                |

The bundle contains:

- An `identity` for the investigated organization and a separate system identity for the exporter.
- `domain-name`, `ipv4-addr`, `ipv6-addr`, `email-addr`, and `url` objects for stored values that have those types.
- `x509-certificate` objects from stored certificate names, issuers, and validity. A certificate-transparency record id is not copied into `serial_number`.
- `indicator` objects for suspected lookalikes. `labels` is `suspected`, confidence is the stored heuristic rescaled and capped at 85, and the description quotes the stored basis. The pattern is not a confirmed verdict.
- `observed-data` and `relationship` objects that cite the stored observation id and source. `resolves-to` is used only for a stored domain-to-address edge. Other stored relations, including impersonation, are `related-to` and keep the original relation name in the description.
- `opinion` and `note` objects for analyst decisions. `accept` becomes `agree`, `reject` becomes `disagree`, and `needs-more-evidence` becomes `neutral`. The text says the decision does not confirm identity, ownership, or phishing.
- `note` objects for stored entity links. A candidate stays a candidate. A link that the database already marks confirmed is copied with that stored status and is not promoted by the exporter.

Identifiers are UUIDv5 (RFC 4122) from the content key, using the DNS namespace and the prefix `osint-power.stix.2.1`. Exporting the same database with the same filters twice yields the same bundle. Changing a stored row changes the objects that depend on it. The bundle is not a signature and not a publisher attestation.

At most 200 entities and 10 observations per entity are exported. `truncated: true` means the bundle is a deterministic subset. Entity types without a STIX cyber-observable become notes. With no investigation filter and a review filter of `any` or `unreviewed`, the configured apex may appear as a `domain-name` that records scope, not a new sighting.

`src/stix-validate.js` checks the object types this exporter produces: required properties, identifier and timestamp syntax, confidence range, and that relationship, observed-data, note, and opinion references resolve inside the bundle. It does not download the OASIS schema suite and it will reject object types this project does not emit. A passing validation means the bundle matches those rules. It does not mean every fact in the bundle is true.

## Release checklist

Run this on a clean checkout of the commit you intend to record. Keep the command output with the commit SHA. Do not change the version, do not tag, and do not open a GitHub release as part of the check.

```bash
git rev-parse HEAD
npm ci --ignore-scripts
npm test
npm run lint
npm run schema
git diff --exit-code -- schema/
npm run benchmark
npm ls --all > npm-ls.txt
git archive --format=tar HEAD | sha256sum
```

`npm ci --ignore-scripts` installs the committed lockfile without lifecycle scripts. `npm test` is `node --test` and must stay free of live target traffic. `npm run lint` is ESLint plus Prettier. `npm run schema` rewrites the JSON Schema files from the Zod contracts; the diff must be empty after it runs, so a contract change has to be committed on purpose. `npm run benchmark` runs the labeled synthetic corpus. It is a regression control, not a field-accuracy number.

`npm ls --all` is the dependency inventory for this checklist. The repository does not add a CycloneDX or SPDX tool. `npm-ls.txt` is an operator artifact; do not commit a workspace-specific copy unless you mean to vendor that inventory. `git archive` hashes the tree git will put in a tarball. It does not sign it. Record the SHA-256 next to `git rev-parse HEAD` in the place your team keeps release evidence.

Optional, still without tagging:

```bash
npm audit --audit-level=moderate
node src/cli.js demo
```

CI on this repository already runs the test, benchmark, lint, schema diff, audit, and demo steps on `ubuntu-latest` and `windows-latest`, plus the pinned native lab on Linux. A green checklist on one machine does not replace that matrix. Windows can leave SQLite WAL sidecars locked; tests checkpoint with `PRAGMA wal_checkpoint(TRUNCATE)` and remove temporary directories with retries. Do the same before deleting a local database by hand.

What this checklist does not do: bump 0.4.0, push a tag, build a GitHub release, sign the archive, or claim the benchmark measures production precision.
