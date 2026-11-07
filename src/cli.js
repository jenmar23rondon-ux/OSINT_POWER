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

const HELP = {
  project: "OSINT_POWER",
  version: "0.4.0",
  commands: {
    bundle:
      "bundle --id SNAPSHOT_UUID --output evidence.json (complete capture, at most 10000 observations/40 MB)",
    "verify-bundle":
      "verify-bundle --file evidence.json (offline integrity verification)",
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
    graph: "graph [--limit 25] [--offset 0]",
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
        ].map((k) => [k, { type: "string" }]),
      ),
    },
  });
  const command = positionals[0] ?? "help";
  if (v.restart && command !== "run")
    throw new Error("RESTART_ONLY_FOR_COLLECTION");
  if (positionals.length > 1) throw new Error("UNEXPECTED_ARGUMENT");
  let result;
  if (command === "help") result = HELP;
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
    else if (command === "run")
      result = await engine.run({
        adapter: v.adapter,
        target: v.target,
        restart: v.restart,
      });
    else if (command === "bundle") {
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
    else if (command === "graph")
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
