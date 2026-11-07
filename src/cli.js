#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFileSync, writeFileSync, statSync } from "node:fs";
import { Engine, openEngine } from "./engine.js";
import { Store } from "./store.js";
import { report } from "./report.js";

const HELP = {
  project: "OSINT_POWER",
  version: "0.2.0",
  commands: {
    workflow:
      "workflow --workflow company --target example.com [--execute] [--max-targets 3] [--max-calls 10]",
    demo: "Offline example: node src/cli.js demo",
    init: "Write a new config.json without overwriting: node src/cli.js init",
    capabilities: "List configured collectors, importers and scope",
    run: "run --adapter crtsh --target example.com",
    pipeline:
      "pipeline --target example.com (passive configured collectors only)",
    import: "import --adapter subfinder --file examples/subdomains.txt",
    query: "query [--type domain] [--limit 25] [--cursor HASH]",
    evidence: "evidence --id ENTITY_HASH [--limit 25] [--offset 0]",
    graph: "graph [--limit 25] [--offset 0]",
    report: "Print a bounded JSON report to stdout",
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
        ].map((k) => [k, { type: "string" }]),
      ),
    },
  });
  const command = positionals[0] ?? "help";
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
    else if (command === "run")
      result = await engine.run({ adapter: v.adapter, target: v.target });
    else if (command === "pipeline") result = await engine.pipeline(v.target);
    else if (command === "workflow")
      result = await engine.workflow({
        workflow: v.workflow,
        target: v.target,
        execute: v.execute,
        maxTargets: Number(v["max-targets"] ?? 3),
        maxCalls: Number(v["max-calls"] ?? 10),
      });
    else if (command === "import") {
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
    else if (command === "report") result = report(engine);
    else throw new Error("UNKNOWN_COMMAND");
  }
  process.stdout.write(
    JSON.stringify(
      { ok: result.status !== "failed" && result.status !== "partial", result },
      null,
      2,
    ) + "\n",
  );
  if (result.status === "failed" || result.status === "partial")
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
