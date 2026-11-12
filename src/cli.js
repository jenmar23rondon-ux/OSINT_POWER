#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFileSync, writeFileSync, statSync } from "node:fs";
import { Engine, openEngine } from "./engine.js";
import { Store } from "./store.js";
import { report } from "./report.js";
import { reportHTML } from "./dashboard.js";
import { doctor } from "./doctor.js";
import { planInvestigation } from "./planning.js";
import { compareRuns, explainEntity } from "./state.js";
import { JobListInput } from "./schema.js";
import { completeEvidence, verifyEvidence } from "./bundles.js";
import { exportStix } from "./stix.js";
import { validateStixBundle } from "./stix-validate.js";
import { recordDecision, reviewQueue, showEntity } from "./review.js";
import {
  phishingHTML,
  phishingReport,
  runPhishingWorkflow,
} from "./phishing.js";
import {
  createMonitor,
  listMonitors,
  monitorChanges,
  monitorMarkdown,
  runMonitor,
} from "./monitor.js";
import { assessAssets, explainAsset } from "./evidence-intelligence.js";
import {
  caseReport,
  caseSummary,
  closeHypothesis,
  createCase,
  createHypothesis,
  evaluateHypothesis,
  exportCaseStix,
  listCases,
  listHypotheses,
  updateHypothesis,
} from "./cases.js";
import { investigationGraph } from "./graph-export.js";
import { temporalGraph } from "./temporal-graph.js";
import { inspectImageFile } from "./image-forensics.js";

const HELP = {
  project: "OSINT_POWER",
  version: "0.4.0",
  commands: {
    "analyze-image": "analyze-image --file PATH",
    bundle:
      "bundle --id SNAPSHOT_UUID --output evidence.json (complete capture, at most 10000 observations/40 MB)",
    "verify-bundle":
      "verify-bundle --file evidence.json (offline integrity verification)",
    "export-stix":
      "export-stix [--target DOMAIN] [--investigation NAME_OR_UUID] [--review any|accepted|rejected|needs-more-evidence|unreviewed] [--since ISO] [--until ISO] [--output bundle.json]",
    "validate-stix":
      "validate-stix --file bundle.json (offline STIX 2.1 checks; no network)",
    doctor: "doctor [--skip-probes] (local diagnostics only)",
    plan: "plan --workflow company --target example.com (ranked actions; no collection)",
    resume: "resume --id JOB_UUID [--max-calls 10]",
    cancel: "cancel --id JOB_UUID",
    jobs: "jobs [--limit 20] [--offset 0]",
    job: "job --id JOB_UUID",
    runs: "runs [--limit 20] [--offset 0]",
    compare:
      "compare --before RUN_UUID --after RUN_UUID [--limit 25] [--cursor HASH]",
    explain: "explain --id ENTITY_HASH [--limit 10]",
    assess:
      "assess [--type domain|ip|asn|url|technology] [--id ENTITY_HASH [--challenge]] [--limit 25] [--cursor HASH]",
    "review-queue":
      "review-queue [--limit 25] [--cursor HASH] (unreviewed entities, candidate links, contradictions)",
    decide:
      "decide --subject entity|finding --id HASH --decision accept|reject|needs-more-evidence --reason TEXT --analyst ID",
    "show-entity":
      "show-entity --id ENTITY_HASH (candidates, contradictions, independence, decision history)",
    "phishing-scan":
      "phishing-scan --target example.com [--execute] [--max-candidates 20] [--max-calls 10] (suspected lookalikes; not confirmed phishing)",
    "phishing-report":
      "phishing-report --target example.com [--format json|markdown|html --output PATH]",
    "monitor add":
      "monitor add --name NAME --workflow company|phishing|collectors --target example.com --sources crtsh,naabu [--interval 24h] [--minimum notable] [--webhook URL]",
    "monitor run":
      "monitor run --id MONITOR_UUID [--max-calls 10] (invoked by cron or CI; no built-in scheduler)",
    "monitor diff":
      "monitor diff --id MONITOR_UUID [--run RUN_UUID] [--format json|markdown --output PATH]",
    "monitor list": "monitor list [--limit 25] [--offset 0]",
    "hypothesis create":
      "hypothesis create --statement TEXT --claim current-activity|historical-existence|organization-attribution|entity-association --entities HASH[,HASH] [--evidence HASH] [--case UUID] [--note TEXT] (stores an open hypothesis; not a finding)",
    "hypothesis update":
      "hypothesis update --id UUID [--statement TEXT] [--claim CLAIM] [--entities HASH,HASH] [--evidence HASH] [--case UUID] [--note TEXT]",
    "hypothesis close":
      "hypothesis close --id UUID --status rejected|analyst-confirmed --reason TEXT --analyst ID (analyst-confirmed only from this command)",
    "hypothesis list":
      "hypothesis list [--case UUID] [--status STATUS] [--limit 25] [--cursor UUID]",
    "hypothesis evaluate":
      "hypothesis evaluate --id UUID (read-only assessment; suggestions are not executed)",
    "case create":
      "case create --title TEXT --summary TEXT [--investigation NAME] [--target DOMAIN] [--hypothesis UUID] [--decision UUID] [--note TEXT]",
    "case list": "case list [--limit 25] [--cursor UUID]",
    "case summary": "case summary --id UUID",
    "case report":
      "case report --id UUID [--review-budget 1..20] [--format json|markdown --output PATH]",
    "case export-stix":
      "case export-stix --id UUID [--output bundle.json] (reuses STIX export; hypotheses stay notes)",
    health: "health (persisted provider quotas and cooldowns)",
    workflow:
      "workflow --workflow company --target example.com [--execute | --queue] [--max-targets 3] [--max-calls 10]",
    demo: "Offline example: node src/cli.js demo",
    init: "Write a new config.json without overwriting: node src/cli.js init",
    capabilities: "List configured collectors, importers and scope",
    run: "run --adapter crtsh --target example.com [--restart for certspotter/wayback]",
    pipeline:
      "pipeline --target example.com (passive configured collectors only)",
    import: "import --adapter subfinder --file examples/subdomains.txt",
    query: "query [--type domain] [--limit 25] [--cursor HASH]",
    evidence: "evidence --id ENTITY_HASH [--limit 25] [--offset 0]",
    graph:
      "graph [--limit 25] [--offset 0] OR graph --case UUID | --investigation NAME [--format json|html --output PATH] (read-only; candidates are not shown as confirmed)",
    timeline:
      "timeline [--host DOMAIN] [--ip ADDRESS] --since ISO --until ISO --as-of ISO [--limit 25 --cursor CURSOR]",
    report:
      "report [--format json|html --output PATH]; interactive HTML requires an explicit output path",
  },
  options:
    "--config config.json --db PATH; all CLI responses are JSON; diagnostics use stderr",
};
let engine;
try {
  const { values: v, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      execute: { type: "boolean", default: false },
      queue: { type: "boolean", default: false },
      restart: { type: "boolean", default: false },
      "skip-probes": { type: "boolean", default: false },
      challenge: { type: "boolean", default: false },
      ...Object.fromEntries(
        [
          "config",
          "db",
          "adapter",
          "target",
          "file",
          "type",
          "limit",
          "cursor",
          "id",
          "offset",
          "workflow",
          "max-targets",
          "max-calls",
          "before",
          "after",
          "format",
          "output",
          "decision",
          "reason",
          "analyst",
          "subject",
          "max-candidates",
          "name",
          "sources",
          "interval",
          "webhook",
          "minimum",
          "run",
          "investigation",
          "review",
          "review-budget",
          "since",
          "until",
          "as-of",
          "host",
          "ip",
          "statement",
          "claim",
          "entities",
          "evidence",
          "case",
          "note",
          "title",
          "summary",
          "hypothesis",
          "decision",
          "status",
        ].map((k) => [k, { type: "string" }]),
      ),
    },
  });
  const command = positionals[0] ?? "help";
  const subcommand = positionals[1];
  if (v.challenge && (command !== "assess" || !v.id))
    throw new Error("CHALLENGE_REQUIRES_ASSET_ID");
  if (v.restart && command !== "run")
    throw new Error("RESTART_ONLY_FOR_COLLECTION");
  if (command === "monitor") {
    if (
      positionals.length !== 2 ||
      !["add", "run", "diff", "list"].includes(subcommand)
    )
      throw new Error("UNKNOWN_COMMAND");
  } else if (command === "hypothesis") {
    if (
      positionals.length !== 2 ||
      !["create", "update", "close", "list", "evaluate"].includes(subcommand)
    )
      throw new Error("UNKNOWN_COMMAND");
  } else if (command === "case") {
    if (
      positionals.length !== 2 ||
      !["create", "list", "summary", "report", "export-stix"].includes(
        subcommand,
      )
    )
      throw new Error("UNKNOWN_COMMAND");
  } else if (positionals.length > 1) throw new Error("UNEXPECTED_ARGUMENT");
  let result;
  if (command === "help") result = HELP;
  else if (command === "analyze-image") result = await inspectImageFile(v.file);
  else if (command === "init") {
    const path = v.config ?? "config.json";
    writeFileSync(
      path,
      readFileSync(new URL("../config.example.json", import.meta.url)),
      { flag: "wx" },
    );
    result = { status: "created", config: path, network: false, active: false };
  } else if (command === "verify-bundle") {
    if (!v.file || statSync(v.file).size > 50_000_000)
      throw new Error("INVALID_BUNDLE_FILE");
    result = verifyEvidence(JSON.parse(readFileSync(v.file, "utf8")));
  } else if (command === "validate-stix") {
    if (!v.file || statSync(v.file).size > 50_000_000)
      throw new Error("INVALID_STIX_FILE");
    let bundle;
    try {
      bundle = JSON.parse(readFileSync(v.file, "utf8"));
    } catch {
      throw new Error("INVALID_STIX_FILE");
    }
    const errors = validateStixBundle(bundle).slice(0, 50);
    result = {
      status: errors.length ? "failed" : "completed",
      valid: errors.length === 0,
      error_count: errors.length,
      errors,
      object_count: Array.isArray(bundle?.objects) ? bundle.objects.length : 0,
    };
  } else if (command === "demo") {
    const config = JSON.parse(
      readFileSync(new URL("../config.example.json", import.meta.url), "utf8"),
    );
    engine = new Engine(config, new Store(v.db ?? ":memory:"));
    const root = new URL("../examples/", import.meta.url);
    for (const [adapter, name] of [
      ["subfinder", "subdomains.txt"],
      ["dnsx", "dnsx.jsonl"],
      ["httpx", "httpx.jsonl"],
    ])
      engine.import({
        adapter,
        data: readFileSync(new URL(name, root), "utf8"),
      });
    result = report(engine);
  } else {
    engine = openEngine(
      v.config ?? process.env.OSINT_POWER_CONFIG ?? "config.json",
      v.db ?? process.env.OSINT_POWER_DB,
    );
    const page = {
      ...(v.type ? { type: v.type } : {}),
      ...(v.limit ? { limit: Number(v.limit) } : {}),
      ...(v.cursor ? { cursor: v.cursor } : {}),
    };
    if (command === "capabilities") result = engine.capabilities();
    else if (command === "doctor")
      result = await doctor(engine, { probe: !v["skip-probes"] });
    else if (command === "health") result = engine.providers.health();
    else if (command === "plan")
      result = await planInvestigation(engine, {
        workflow: v.workflow,
        target: v.target,
        maxTargets: Number(v["max-targets"] ?? 3),
        maxCalls: Number(v["max-calls"] ?? 10),
      });
    else if (command === "resume")
      result = await engine.resume({
        id: v.id,
        ...(v["max-calls"] ? { maxCalls: Number(v["max-calls"]) } : {}),
      });
    else if (command === "cancel") result = engine.jobs.cancel({ id: v.id });
    else if (command === "job") result = engine.jobs.inspect({ id: v.id });
    else if (command === "jobs")
      result = engine.jobs.list({
        limit: Number(v.limit ?? 20),
        offset: Number(v.offset ?? 0),
      });
    else if (command === "runs") {
      const { limit, offset } = JobListInput.parse({
        limit: Number(v.limit ?? 20),
        offset: Number(v.offset ?? 0),
      });
      const total = engine.store.db
        .prepare("SELECT COUNT(*) AS n FROM runs")
        .get().n;
      result = {
        items: engine.store.runs(limit, offset),
        total,
        next_offset: offset + limit < total ? offset + limit : null,
      };
    } else if (command === "compare")
      result = compareRuns(engine.store, {
        before: v.before,
        after: v.after,
        limit: Number(v.limit ?? 25),
        ...(v.cursor ? { cursor: v.cursor } : {}),
      });
    else if (command === "explain")
      result = explainEntity(engine.store, v.id, Number(v.limit ?? 10));
    else if (command === "assess") {
      const gates = {
        network: engine.config.network,
        active: engine.config.active,
        enabledAdapters: engine.config.enabledAdapters,
      };
      result = v.id
        ? explainAsset(engine.store, engine.scope, gates, {
            entity_id: v.id,
            challenge: v.challenge,
          })
        : assessAssets(engine.store, engine.scope, gates, {
            ...(v.type ? { type: v.type } : {}),
            ...(v.limit ? { limit: Number(v.limit) } : {}),
            ...(v.cursor ? { cursor: v.cursor } : {}),
          });
    } else if (command === "review-queue")
      result = reviewQueue(engine.store, {
        ...(v.limit ? { limit: Number(v.limit) } : {}),
        ...(v.cursor ? { cursor: v.cursor } : {}),
      });
    else if (command === "decide")
      result = recordDecision(engine.store, {
        subject_kind: v.subject,
        subject_id: v.id,
        decision: v.decision,
        reason: v.reason,
        analyst_id: v.analyst,
      });
    else if (command === "show-entity")
      result = showEntity(engine.store, { entity_id: v.id });
    else if (command === "phishing-scan")
      result = await runPhishingWorkflow(engine, {
        target: v.target,
        execute: v.execute,
        ...(v["max-candidates"]
          ? { maxCandidates: Number(v["max-candidates"]) }
          : {}),
        ...(v["max-calls"] ? { maxCalls: Number(v["max-calls"]) } : {}),
      });
    else if (command === "monitor" && subcommand === "add")
      result = createMonitor(engine, {
        name: v.name,
        investigation: v.workflow,
        target: v.target,
        sources: (v.sources ?? "")
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
        ...(v.interval ? { interval_hint: v.interval } : {}),
        ...(v.minimum ? { thresholds: { minimum: v.minimum } } : {}),
        ...(v.webhook ? { webhook_url: v.webhook } : {}),
        ...(v["max-candidates"]
          ? { max_candidates: Number(v["max-candidates"]) }
          : {}),
      });
    else if (command === "monitor" && subcommand === "run")
      result = await runMonitor(engine, {
        id: v.id,
        ...(v["max-calls"] ? { max_calls: Number(v["max-calls"]) } : {}),
      });
    else if (command === "monitor" && subcommand === "list")
      result = listMonitors(engine.store, {
        ...(v.limit ? { limit: Number(v.limit) } : {}),
        ...(v.offset ? { offset: Number(v.offset) } : {}),
      });
    else if (command === "monitor" && subcommand === "diff") {
      const format = v.format ?? "json";
      if (!["json", "markdown"].includes(format))
        throw new Error("INVALID_REPORT_FORMAT");
      const body = monitorChanges(engine.store, {
        id: v.id,
        ...(v.run ? { run_id: v.run } : {}),
        ...(v.limit ? { limit: Number(v.limit) } : {}),
        ...(v.cursor ? { cursor: v.cursor } : {}),
      });
      if (v.output) {
        writeFileSync(
          v.output,
          format === "markdown"
            ? monitorMarkdown(body)
            : JSON.stringify(body, null, 2) + "\n",
          { mode: 0o600, flag: "wx" },
        );
        result = {
          status: "completed",
          format,
          path: v.output,
          total: body.total,
          alert_count: body.alert_count,
        };
      } else if (format === "markdown")
        result = { ...body, markdown: monitorMarkdown(body) };
      else result = body;
    } else if (command === "hypothesis" || command === "case") {
      const gates = {
        network: engine.config.network === true,
        active: engine.config.active === true,
        enabledAdapters: engine.config.enabledAdapters ?? [],
      };
      const hashes = (value) =>
        (value ?? "")
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean);
      if (command === "hypothesis" && subcommand === "create")
        result = createHypothesis(engine.store, engine.scope, {
          statement: v.statement,
          claim: v.claim,
          entity_ids: hashes(v.entities),
          ...(v.evidence ? { evidence_ids: hashes(v.evidence) } : {}),
          ...(v.case ? { case_id: v.case } : {}),
          ...(v.note ? { note: v.note } : {}),
        });
      else if (command === "hypothesis" && subcommand === "update")
        result = updateHypothesis(engine.store, engine.scope, {
          id: v.id,
          ...(v.statement ? { statement: v.statement } : {}),
          ...(v.claim ? { claim: v.claim } : {}),
          ...(v.entities ? { entity_ids: hashes(v.entities) } : {}),
          ...(v.evidence ? { evidence_ids: hashes(v.evidence) } : {}),
          ...(v.case ? { case_id: v.case } : {}),
          ...(v.note ? { note: v.note } : {}),
        });
      else if (command === "hypothesis" && subcommand === "close")
        result = closeHypothesis(engine.store, {
          id: v.id,
          status: v.status,
          reason: v.reason,
          analyst_id: v.analyst,
        });
      else if (command === "hypothesis" && subcommand === "list")
        result = listHypotheses(engine.store, {
          ...(v.case ? { case_id: v.case } : {}),
          ...(v.status ? { status: v.status } : {}),
          ...(v.limit ? { limit: Number(v.limit) } : {}),
          ...(v.cursor ? { cursor: v.cursor } : {}),
        });
      else if (command === "hypothesis" && subcommand === "evaluate")
        result = evaluateHypothesis(engine.store, engine.scope, gates, {
          id: v.id,
        });
      else if (command === "case" && subcommand === "create")
        result = createCase(engine.store, engine.scope, {
          title: v.title,
          summary: v.summary,
          ...(v.investigation ? { investigations: [v.investigation] } : {}),
          ...(v.target ? { targets: [v.target] } : {}),
          ...(v.hypothesis ? { hypothesis_ids: [v.hypothesis] } : {}),
          ...(v.decision ? { decision_ids: [v.decision] } : {}),
          ...(v.note ? { notes: [v.note] } : {}),
        });
      else if (command === "case" && subcommand === "list")
        result = listCases(engine.store, {
          ...(v.limit ? { limit: Number(v.limit) } : {}),
          ...(v.cursor ? { cursor: v.cursor } : {}),
        });
      else if (command === "case" && subcommand === "summary")
        result = caseSummary(engine.store, engine.scope, { case_id: v.id });
      else if (command === "case" && subcommand === "report") {
        const format = v.format ?? "json";
        if (!["json", "markdown"].includes(format))
          throw new Error("INVALID_REPORT_FORMAT");
        const body = caseReport(engine.store, engine.scope, gates, {
          case_id: v.id,
          format,
          ...(v["review-budget"] === undefined
            ? {}
            : { review_budget: Number(v["review-budget"]) }),
        });
        if (v.output) {
          writeFileSync(
            v.output,
            format === "markdown"
              ? body.markdown
              : JSON.stringify(body, null, 2) + "\n",
            { mode: 0o600, flag: "wx" },
          );
          result = {
            status: "completed",
            format,
            path: v.output,
            hypotheses: body.sections.hypotheses.length,
            decisions: body.sections.confirmed_analyst_decisions.length,
          };
        } else result = body;
      } else if (command === "case" && subcommand === "export-stix") {
        const exported = exportCaseStix(engine.store, engine.scope, {
          case_id: v.id,
        });
        if (v.output) {
          writeFileSync(
            v.output,
            JSON.stringify(exported.bundle, null, 2) + "\n",
            { mode: 0o600, flag: "wx" },
          );
          const { bundle, ...rest } = exported;
          result = {
            status: "completed",
            path: v.output,
            object_count: bundle.objects.length,
            ...rest,
          };
        } else result = exported;
      } else throw new Error("UNKNOWN_COMMAND");
    } else if (command === "phishing-report") {
      const format = v.format ?? "json";
      if (!["json", "markdown", "html"].includes(format))
        throw new Error("INVALID_REPORT_FORMAT");
      if (format === "html" && !v.output)
        throw new Error("OUTPUT_PATH_REQUIRED");
      const body = phishingReport(engine, { target: v.target });
      if (v.output) {
        writeFileSync(
          v.output,
          format === "html"
            ? phishingHTML(body)
            : format === "markdown"
              ? body.markdown
              : JSON.stringify(body, null, 2) + "\n",
          { mode: 0o600, flag: "wx" },
        );
        result = {
          status: "completed",
          format,
          path: v.output,
          classification: body.classification,
          returned: body.returned,
        };
      } else result = body;
    } else if (command === "run")
      result = await engine.run({
        adapter: v.adapter,
        target: v.target,
        restart: v.restart,
      });
    else if (command === "export-stix") {
      const exported = exportStix(engine.store, engine.scope, {
        ...(v.investigation ? { investigation: v.investigation } : {}),
        ...(v.target ? { target: v.target } : {}),
        ...(v.review ? { review_status: v.review } : {}),
        ...(v.since ? { since: v.since } : {}),
        ...(v.until ? { until: v.until } : {}),
      });
      if (v.output) {
        writeFileSync(
          v.output,
          JSON.stringify(exported.bundle, null, 2) + "\n",
          { mode: 0o600, flag: "wx" },
        );
        const { bundle, ...summary } = exported;
        result = {
          status: "completed",
          path: v.output,
          object_count: bundle.objects.length,
          ...summary,
        };
      } else result = exported;
    } else if (command === "bundle") {
      if (!v.output) throw new Error("OUTPUT_PATH_REQUIRED");
      const bundle = completeEvidence(engine.store, v.id);
      writeFileSync(v.output, JSON.stringify(bundle, null, 2) + "\n", {
        mode: 0o600,
        flag: "wx",
      });
      result = {
        status: "completed",
        path: v.output,
        captures: bundle.captures.length,
        integrity: bundle.integrity,
      };
    } else if (command === "pipeline") result = await engine.pipeline(v.target);
    else if (command === "workflow") {
      if (v.queue && v.execute) throw new Error("QUEUE_AND_EXECUTE_CONFLICT");
      const request = {
        workflow: v.workflow,
        target: v.target,
        execute: v.execute,
        maxTargets: Number(v["max-targets"] ?? 3),
        maxCalls: Number(v["max-calls"] ?? 10),
      };
      result = v.queue
        ? engine.jobs.create(request)
        : await engine.workflow(request);
    } else if (command === "import") {
      if (!v.file || statSync(v.file).size > engine.config.limits.maxBytes)
        throw new Error("INVALID_IMPORT_FILE");
      result = engine.import({
        adapter: v.adapter,
        data: readFileSync(v.file, "utf8"),
      });
    } else if (command === "query") result = engine.store.query(page);
    else if (command === "evidence")
      result = engine.store.evidence(
        v.id ?? "",
        Number(v.limit ?? 25),
        Number(v.offset ?? 0),
      );
    else if (command === "timeline")
      result = temporalGraph(engine.store, engine.scope, {
        ...(v.host !== undefined ? { host: v.host } : {}),
        ...(v.ip !== undefined ? { ip: v.ip } : {}),
        since: v.since,
        until: v.until,
        as_of: v["as-of"],
        limit: Number(v.limit ?? 25),
        cursor: v.cursor,
      });
    else if (command === "graph" && (v.case || v.investigation)) {
      if (v.case && v.investigation) throw new Error("INVALID_INPUT");
      const format = v.format ?? "json";
      if (!["json", "html"].includes(format))
        throw new Error("INVALID_GRAPH_FORMAT");
      if (format === "html" && !v.output)
        throw new Error("OUTPUT_PATH_REQUIRED");
      const exported = investigationGraph(
        engine.store,
        engine.scope,
        {
          network: engine.config.network === true,
          active: engine.config.active === true,
          enabledAdapters: engine.config.enabledAdapters ?? [],
        },
        {
          ...(v.case ? { case_id: v.case } : {}),
          ...(v.investigation ? { investigation: v.investigation } : {}),
          format,
        },
      );
      if (v.output) {
        writeFileSync(
          v.output,
          format === "html"
            ? exported.html
            : JSON.stringify(exported.graph, null, 2) + "\n",
          { mode: 0o600, flag: "wx" },
        );
        result = {
          status: "completed",
          format,
          path: v.output,
          nodes: exported.graph.counts.nodes,
          edges: exported.graph.counts.edges,
          read_only: true,
          truncated: exported.truncated,
        };
      } else result = exported;
    } else if (command === "graph")
      result = engine.store.graph(Number(v.limit ?? 25), Number(v.offset ?? 0));
    else if (command === "report") {
      const format = v.format ?? "json";
      if (!["json", "html"].includes(format))
        throw new Error("INVALID_REPORT_FORMAT");
      if (format === "html" && !v.output)
        throw new Error("OUTPUT_PATH_REQUIRED");
      result = report(engine);
      if (v.output) {
        writeFileSync(
          v.output,
          format === "html"
            ? reportHTML(result)
            : JSON.stringify(result, null, 2) + "\n",
          { mode: 0o600 },
        );
        result = {
          status: "completed",
          format,
          path: v.output,
          total_entities: result.findings.total,
          returned_entities: result.findings.returned,
        };
      }
    } else throw new Error("UNKNOWN_COMMAND");
  }
  process.stdout.write(
    JSON.stringify(
      {
        ok: ![
          "failed",
          "partial",
          "cancelled",
          "interrupted",
          "deferred",
        ].includes(result.status),
        result,
      },
      null,
      2,
    ) + "\n",
  );
  if (
    ["failed", "partial", "cancelled", "interrupted", "deferred"].includes(
      result.status,
    )
  )
    process.exitCode = 1;
} catch (error) {
  const code =
    error.code === "ENOENT"
      ? "FILE_NOT_FOUND"
      : error.code === "EEXIST"
        ? "CONFIG_EXISTS"
        : /^[A-Z_0-9]+$/.test(error.message)
          ? error.message
          : "INVALID_INPUT";
  process.stdout.write(JSON.stringify({ ok: false, error: { code } }) + "\n");
  process.exitCode = 1;
} finally {
  engine?.store.close();
}
