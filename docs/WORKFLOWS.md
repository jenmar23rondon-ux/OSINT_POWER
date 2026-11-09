# Investigation workflows

The seven English workflow names are **people, company, places, users, emails, exposures and correlation**. They share the same engine, scope, cache and evidence store. Original Spanish command names remain compatibility aliases; responses use the English names.

## Offline examples

```bash
node src/cli.js import --config examples/config.workflows.json --adapter business-context --file examples/business-context.jsonl
node src/cli.js import --config examples/config.workflows.json --adapter breach-summary --file examples/breach-summary.jsonl
node src/cli.js workflow --config examples/config.workflows.json --workflow people --target "Alex Rivera"
node src/cli.js workflow --config examples/config.workflows.json --workflow company --target example.com
node src/cli.js workflow --config examples/config.workflows.json --workflow correlation --target example.com
```

All example data is synthetic. Imports write local state. Workflow commands without `--execute` only plan and read local state: they send no traffic and do not create runs or findings.

## Execute configured stages

```bash
node src/cli.js workflow --workflow company --target example.com --execute --max-targets 3 --max-calls 10
```

Use your configured domain. Execution preserves `network`, `active`, `enabledAdapters` and per-source controls. Later stages are recalculated after earlier discoveries.

`maxTargets` limits candidates per stage to 1–10. `maxCalls` limits logical adapter invocations to 1–30, default 10. An adapter may make multiple underlying requests: RDAP needs bootstrap and registry calls, retries may repeat requests, and external binaries have internal behavior. Cached calls also consume this workflow budget.

Unavailable sources remain explicit. Partial runs retain completed evidence. No pending stage is automatically scheduled after the workflow finishes.

| Status                                                | Meaning                                                  |
| ----------------------------------------------------- | -------------------------------------------------------- |
| planned                                               | Local plan without writes or network                     |
| completed / context_available                         | Executed stage or local evidence available               |
| adapter_disabled / network_disabled / active_disabled | Configuration prevents collection                        |
| deferred / needs_input                                | A dependency or target is missing                        |
| needs_import / needs_host_search                      | Supply a sourced import or host search result            |
| candidate_only                                        | Derived alias retained without cross-platform collection |
| exact_account_required                                | HIBP requires the exact configured account               |
| budget_exhausted                                      | Logical call budget reached                              |
| partial / failed                                      | Inspect errors and retained results                      |

## People

Declare professional subjects in `scope.people`. The workflow accepts an unambiguous configured name or alias. It generates at most 20 name/surname/initial variants, separators and configured numeric suffixes. It does not infer birth dates.

```json
{
  "scope": {
    "domains": ["example.com"],
    "people": [
      {
        "name": "Alex Rivera",
        "companyDomain": "example.com",
        "aliases": ["arivera"]
      }
    ]
  },
  "collectors": {
    "sherlockSites": ["GitHub", "GitLab"],
    "harvesterSources": ["crtsh"],
    "usernameSuffixes": ["1", "01"]
  }
}
```

Merge this fragment into a complete version-1 configuration. Enable Sherlock/GitHub adapters separately when needed. Sherlock runs one alias per process against 1–3 configured professional sites, with a local catalog, timeout and temporary CSV. Its platform checks generate HTTP traffic.

LinkedIn, GitHub and X search queries combine the declared name and company. The host can execute them with its own search tools and import evidence through `business-context`. There is no automatic LinkedIn/X scraper or identity confirmation. Roles, technologies, corporate emails and source assertions link to declared professional subjects.

WhatsMyName is a dataset; upstream removed its bundled checker scripts. Its import bridge accepts `username`, `url` and `status` (found/not_found/unknown), rather than inventing an executable. [Official project](https://github.com/WebBreacher/WhatsMyName).

## Company

The company workflow coordinates crt.sh/subfinder/Amass, theHarvester, DNS/HTTP checks for the first scoped hosts, RDAP and RIPEstat. HTTP observations retain title, technology and certificate CN/issuer when provided by httpx.

RDAP uses IANA's HTTPS bootstrap and an exact RIR host allowlist without redirects. RIPEstat reports the prefix and announcing ASN from routing observations. Neither is proof of ownership, corporate location or authority to scan a whole range. Passive enrichment of a discovered IP does not expand active scope.

Job listings and organization claims are sourced imports. A technology inferred from a listing stays low-confidence. Routing data uses [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info), without scraping bgp.he.net.

TheHarvester's configured crtsh/certspotter sources may mainly provide hosts rather than emails. No results does not prove that no corporate email addresses exist.

## Places

The places workflow links reviewed **public corporate office** records to the company. Import `business-context` with `kind: place`, `place_kind: public_office` and a source URL such as a corporate contact page or business registry.

There is no image downloader, GPS extractor, geocoder or residential-location inference. Existing ExifTool metadata can be reviewed, but a corporate-location assertion needs independent source evidence. IP geolocation or registration country never becomes an office node automatically.

## Users and emails

Users derives candidate aliases from the local part of scoped corporate email addresses and retains the email → alias relationship. Platform collection only runs for explicitly scoped aliases or variants of configured professional subjects. A derived email alias is not a confirmed account or identity.

Emails combines public collection/imports, syntax normalization and cached DNS MX checks. `mx_present` describes DNS records. `null_mx` indicates a domain's declaration not to accept mail. No explicit MX does not rule out SMTP A/AAAA fallback. Mailbox existence and catch-all remain `unknown`; no SMTP probing or test messages are sent.

Certificates provide infrastructure names, not an email directory. GitHub imports only publicly listed emails that pass scope. Paste scraping and global credential searches are not implemented.

## Exposures

HIBP queries exact configured accounts and retains breach names and dates when available. It uses `HIBP_API_KEY` from the server environment. A breach association does not establish a current password or account compromise.

Gitleaks/TruffleHog imports retain file, rule and line. Raw, Secret, Match, prefixes and scanner credential-verification claims are discarded. Generic secret observations also reconstruct their value from location metadata and force an unverified assessment.

DeHashed/LeakCheck support is a strict `breach-summary` import containing provider, email, breach, date and timestamp. Password fields are rejected. There are no live password-retrieval or credential-testing connectors.

Secret references belong to the workspace until separate association evidence exists; they are not automatically attributed to the selected company.

## Sourced business context

```json
{
  "company_domain": "example.com",
  "kind": "role",
  "person": "Alex Rivera",
  "value": "Engineer",
  "source_url": "https://example.com/team",
  "status": "observed",
  "timestamp": "2026-11-07T00:00:00.000Z"
}
```

Kinds: employee, role, technology, place, profile, email and job. Observed means a source assertion, not independent identity verification. Inferred lowers confidence. Source URL queries and fragments are removed.

Strict contracts are exported as [business-context](../schema/business-context.schema.json), [breach-summary](../schema/breach-summary.schema.json) and [workflow](../schema/workflow.schema.json) schemas.

## Correlation

Correlation presents professional evidence coverage, company-scoped breach associations and observed services requiring defensive review. It does not rank employees as attack targets or assert an entry point from an alias, breach, MX or open port.

The summary is bounded: up to 100 domain/IP/email samples and 10 defensive review candidates. Correlation totals are computed separately from samples. It is not a full export or calibrated risk score. Use paginated entity/evidence/graph queries to investigate. Workflow findings contain up to 25 normalized domain-context observations.

## MCP

Call the `workflow` tool:

```json
{
  "workflow": "people",
  "target": "Alex Rivera",
  "execute": false,
  "maxTargets": 3,
  "maxCalls": 10
}
```

The default is a local plan. Setting execute to true requests configured stages; it does not grant access to arbitrary commands or change scope.

## Compatibility and validation

Empty new people defaults preserve the scope fingerprint of v0.1 workspaces. Adding people or changing scope requires a different database, as before. Use `--db` or `OSINT_POWER_DB`.

Tests use mocked sources, external-file contracts and a real MCP session. Verify installed upstream binary versions locally. Import bridges are not equivalent to live API connectors.

## Phishing leads

`phishing-scan` is separate from the seven workflows. It accepts one configured apex domain, such as `example.com`, and generates a capped, deterministic set of lookalikes: character omissions, duplications, transpositions, adjacent-key typos, digit substitutions, single-character homoglyphs stored as punycode, final-label TLD swaps, `login`/`secure`/`support` additions, and hyphenation. The protected label must be 4–32 characters and must not already contain a hyphen. The final label is treated as the public suffix. Variants beyond the cap are a coverage gap.

```bash
node src/cli.js phishing-scan --target example.com --max-candidates 10
node src/cli.js phishing-scan --target example.com --execute --max-candidates 10 --max-calls 10
node src/cli.js phishing-report --target example.com --format html --output leads.html
```

Without `--execute`, the command only plans. It does not store leads or send traffic. With `--execute`, suspected domain entities are stored and enter the existing review queue. The stored status is always `suspected`. `accept` records an analyst decision; it does not confirm phishing. Rejected entities can leave the queue while the lead status stays `suspected`.

Enrichment runs only for names this command just generated. It uses configured crt.sh, Cert Spotter, IANA domain RDAP and Wayback when `network` is on. Each source is one attempt and one page. Those calls do not advance the in-scope historical cursors and do not download site or archive bodies. Domain RDAP hosts come from the IANA bootstrap; links inside the registry body are ignored. DNS A, MX and NS run only when `active` is on and the `mx` adapter is enabled, through the same system resolver as MX. An MX record does not prove a mailbox. No port scan, HTTP probe, form submission, credential check, or phishing-kit download is added.

The JSON, Markdown and offline HTML reports label the set as unverified leads and list the basis and source of each signal: name similarity, registration within 400 days, MX presence, a certificate name that contains the brand label, and an address shared by two candidates enriched in the same run. Recommended notification or takedown text is advisory and still requires the analyst decision.

MCP tools are `run_phishing_workflow` and `phishing_report`. The scan is synchronous. It is not a durable resumable job.

## Incremental monitor

```bash
node src/cli.js monitor add --name edge --workflow company --target example.com --sources crtsh,naabu --interval 24h
node src/cli.js monitor run --id MONITOR_UUID
node src/cli.js monitor diff --id MONITOR_UUID --format markdown --output changes.md
```

`company`, the other six workflows, `phishing` and `collectors` are stored as the investigation label. A phishing monitor may list only `crtsh`, `certspotter`, `wayback`, `rdap` and `mx`. Collection still goes through the existing adapters and the phishing workflow; the monitor does not add a source or bypass a gate. `interval_hint` is not a schedule. Cron or CI calls `monitor run`.

The diff can raise a local alert for a new certificate that names the brand, a suspected lookalike that gained an MX record, or a newly observed service. Those rules state their basis and do not confirm ownership, phishing, a mailbox, or a vulnerability. New entities enter the review queue unreviewed. Markdown and JSON stay on disk unless a webhook URL was set and network access is enabled. See [OPERATIONS.md](OPERATIONS.md).

## v0.3 execution and snapshots

v0.4 additionally includes one historical-discovery call for each enabled Cert Spotter/Wayback adapter in the company workflow. Existing call budgets apply. Each result is a page with incomplete historical coverage, not a complete census. See [the v0.4 guide](V0.4.md).

Execution now creates durable jobs with recoverable steps and sealed snapshot IDs. Resume uses a new per-invocation budget while retaining lifetime and per-step caps. Correlation totals are exact for stored scoped entities; displayed samples remain bounded. See [OPERATIONS.md](OPERATIONS.md) for queue/resume/cancel, provider coordination and immutable run comparisons.
