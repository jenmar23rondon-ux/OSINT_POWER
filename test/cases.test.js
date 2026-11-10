import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Engine } from "../src/engine.js";
import { Store, hash } from "../src/store.js";
import { SCHEMA_VERSION, recordDecision } from "../src/review.js";
import { RESULT_SCHEMAS, toolResponse } from "../src/contracts.js";
import { validateStixBundle } from "../src/stix-validate.js";
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
} from "../src/cases.js";

const asOf = "2026-11-10T00:00:00.000Z";
const recent = "2026-10-20T00:00:00.000Z";
const settings = {
  version: 1,
  scope: { domains: ["example.com"], usernames: ["alex"] },
  network: false,
  active: false,
  enabledAdapters: ["crtsh"],
};
function gates(extra = {}) {
  return {
    network: false,
    active: false,
    enabledAdapters: ["crtsh"],
    ...extra,
  };
}
function workspace(t, config = settings) {
  const store = new Store();
  t.after(() => store.close());
  return { store, engine: new Engine(config, store) };
}
function line(row) {
  return JSON.stringify({
    confidence: 0.6,
    timestamp: recent,
    ...row,
    evidence: row.evidence ?? {},
  });
}
function load(engine, rows) {
  const result = engine.import({
    adapter: "jsonl",
    data: rows.map(line).join("\n"),
  });
  assert.equal(result.invalid, 0);
  assert.equal(result.skipped, 0);
  return result;
}
function releaseStore(store) {
  try {
    store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } catch {
    // The handle may already be closed.
  }
  store.close();
}
function removeTemp(dir) {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
function section(markdown, heading) {
  const start = markdown.indexOf(`## ${heading}`);
  assert.notEqual(start, -1, heading);
  const rest = markdown.slice(start + heading.length + 3);
  const next = rest.indexOf("\n## ");
  return next === -1 ? rest : rest.slice(0, next);
}

test("schema v7 adds hypothesis and case tables without rewriting evidence", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-case-migrate-"));
  t.after(() => removeTemp(dir));
  const path = join(dir, "legacy.sqlite");
  const id = hash(["domain", "kept.example.com"]);
  const legacy = new DatabaseSync(path);
  legacy.exec(`CREATE TABLE entities(
    id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)`);
  legacy
    .prepare("INSERT INTO entities VALUES(?,?,?,?,?)")
    .run(
      id,
      "domain",
      "kept.example.com",
      "2020-01-01T00:00:00.000Z",
      "2020-01-01T00:00:00.000Z",
    );
  legacy.exec("PRAGMA user_version=6");
  legacy.close();
  const store = new Store(path);
  t.after(() => releaseStore(store));
  assert.equal(
    store.db.prepare("PRAGMA user_version").get().user_version,
    SCHEMA_VERSION,
  );
  assert.equal(SCHEMA_VERSION, 7);
  const kept = store.db
    .prepare("SELECT value, last_seen FROM entities WHERE id=?")
    .get(id);
  assert.equal(kept.value, "kept.example.com");
  assert.equal(kept.last_seen, "2020-01-01T00:00:00.000Z");
  for (const name of ["hypotheses", "cases", "case_members", "monitors"])
    assert.equal(
      store.db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
        .get(name).name,
      name,
    );
  releaseStore(store);
  const bumped = new DatabaseSync(path);
  bumped.exec(`PRAGMA user_version=${SCHEMA_VERSION + 1}`);
  bumped.close();
  assert.throws(() => new Store(path), /DATABASE_VERSION_TOO_NEW/);
  const preserved = new DatabaseSync(path);
  assert.equal(
    preserved.prepare("SELECT value FROM entities WHERE id=?").get(id).value,
    "kept.example.com",
  );
  preserved.close();
});

test("contradicting evidence weakens a hypothesis and support is not confirmation", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
    {
      type: "domain",
      value: "owned.example.com",
      source: "filing-a",
      evidence: { company: "example.com" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "owned.example.com",
      source: "filing-b",
      evidence: { company: "example.com" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "split.example.com",
      source: "filing-a",
      evidence: { company: "example.com" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "split.example.com",
      source: "filing-c",
      evidence: { company: "elsewhere.invalid" },
    },
  ]);
  const ownedId = hash(["domain", "owned.example.com"]);
  const created = createHypothesis(store, engine.scope, {
    statement: "owned.example.com belongs to the in-scope organization",
    claim: "organization-attribution",
    entity_ids: [ownedId],
  });
  assert.equal(created.hypothesis.status, "open");
  assert.equal(created.hypothesis.confirmed, false);
  assert.equal(created.hypothesis.finding, false);
  assert.equal(created.executes, false);
  assert.equal(created.network, false);
  assert.equal(created.collection, false);
  const supported = evaluateHypothesis(
    store,
    engine.scope,
    gates(),
    { id: created.hypothesis.id },
    { asOf },
  );
  assert.equal(supported.assessed_status, "supported-pending-review");
  assert.equal(supported.stored_status, "supported-pending-review");
  assert.equal(supported.confirmed, false);
  assert.equal(supported.finding, false);
  assert.equal(supported.supporting.length >= 1, true);
  assert.equal(
    listHypotheses(store).items[0].status,
    "supported-pending-review",
  );
  recordDecision(store, {
    subject_kind: "entity",
    subject_id: ownedId,
    decision: "accept",
    reason: "The filings name the in-scope organization.",
    analyst_id: "analyst-1",
  });
  const accepted = evaluateHypothesis(
    store,
    engine.scope,
    gates(),
    { id: created.hypothesis.id },
    { asOf },
  );
  assert.equal(accepted.confirmed, false);
  assert.equal(accepted.stored_status, "supported-pending-review");
  assert.equal(accepted.finding, false);
  const closed = closeHypothesis(store, {
    id: created.hypothesis.id,
    status: "analyst-confirmed",
    reason: "Analyst agrees with the stored organization evidence.",
    analyst_id: "analyst-1",
  });
  assert.equal(closed.hypothesis.status, "analyst-confirmed");
  assert.equal(closed.hypothesis.confirmed, true);
  assert.equal(closed.hypothesis.finding, false);
  const split = createHypothesis(store, engine.scope, {
    statement: "split.example.com belongs only to the in-scope organization",
    claim: "organization-attribution",
    entity_ids: [hash(["domain", "split.example.com"])],
  });
  const weakened = evaluateHypothesis(
    store,
    engine.scope,
    gates(),
    { id: split.hypothesis.id },
    { asOf },
  );
  assert.equal(weakened.assessed_status, "weakened");
  assert.equal(weakened.confirmed, false);
  assert.equal(weakened.finding, false);
  assert.equal(weakened.contradicting.length >= 1, true);
  assert.equal(
    weakened.next_steps.every((item) => item.executes === false),
    true,
  );
  assert.throws(
    () =>
      updateHypothesis(store, engine.scope, {
        id: created.hypothesis.id,
        statement: "rewrite a closed hypothesis",
      }),
    /HYPOTHESIS_CLOSED/,
  );
  assert.equal(
    RESULT_SCHEMAS.evaluate_hypothesis.safeParse(weakened).success,
    true,
  );
  assert.equal(toolResponse("evaluate_hypothesis", weakened).ok, true);
});

test("out-of-scope entities and evidence cannot be attached", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
    {
      type: "domain",
      value: "kept.example.com",
      source: "crtsh",
      evidence: { record: "1" },
    },
  ]);
  store.ingest([
    {
      type: "domain",
      value: "out.invalid",
      source: "manual",
      confidence: 0.2,
      timestamp: recent,
      evidence: {},
    },
  ]);
  assert.throws(
    () =>
      createHypothesis(store, engine.scope, {
        statement: "out.invalid is ours",
        claim: "organization-attribution",
        entity_ids: [hash(["domain", "out.invalid"])],
      }),
    /OUT_OF_SCOPE/,
  );
  const foreign = store.ingest([
    {
      type: "domain",
      value: "out.invalid",
      source: "foreign",
      confidence: 0.2,
      timestamp: recent,
      evidence: {},
    },
  ]);
  assert.equal(foreign.inserted, 1);
  const foreignId = store.db
    .prepare("SELECT id FROM observations WHERE source='foreign'")
    .get().id;
  assert.throws(
    () =>
      createHypothesis(store, engine.scope, {
        statement: "kept.example.com is ours",
        claim: "organization-attribution",
        entity_ids: [hash(["domain", "kept.example.com"])],
        evidence_ids: [foreignId],
      }),
    /OUT_OF_SCOPE/,
  );
});

test("hypothesis and case tools do not call a fetcher or a collector", async (t) => {
  let fetches = 0;
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(settings, store, {
    fetcher: async () => {
      fetches += 1;
      throw new Error("NETWORK_CALLED");
    },
  });
  const calls = [];
  engine.run = async () => {
    calls.push("run");
    throw new Error("COLLECTION_CALLED");
  };
  engine.workflow = async () => {
    calls.push("workflow");
    throw new Error("COLLECTION_CALLED");
  };
  engine.pipeline = async () => {
    calls.push("pipeline");
    throw new Error("COLLECTION_CALLED");
  };
  const previous = globalThis.fetch;
  globalThis.fetch = async () => {
    fetches += 1;
    throw new Error("NETWORK_CALLED");
  };
  t.after(() => {
    globalThis.fetch = previous;
  });
  load(engine, [
    {
      type: "domain",
      value: "idle.example.com",
      source: "crtsh",
      timestamp: "2019-01-01T00:00:00.000Z",
      evidence: { historical: true, record: "9" },
    },
  ]);
  const id = hash(["domain", "idle.example.com"]);
  const created = createHypothesis(store, engine.scope, {
    statement: "idle.example.com is active now",
    claim: "current-activity",
    entity_ids: [id],
  });
  const evaluation = evaluateHypothesis(
    store,
    engine.scope,
    gates(),
    { id: created.hypothesis.id },
    { asOf },
  );
  assert.equal(evaluation.assessed_status, "open");
  assert.equal(evaluation.confirmed, false);
  const blocked = evaluation.next_steps.find((item) => item.requires_gate);
  assert.equal(blocked.requires_gate, "network");
  assert.equal(blocked.within_gates, false);
  assert.equal(blocked.executes, false);
  const openGates = evaluateHypothesis(
    store,
    engine.scope,
    gates({ network: true, active: true, enabledAdapters: ["crtsh", "dnsx"] }),
    { id: created.hypothesis.id },
    { asOf },
  );
  const suggested = openGates.next_steps.find(
    (item) => item.action === "collect recent in-scope DNS evidence",
  );
  assert.equal(suggested.executes, false);
  assert.equal(suggested.within_gates, true);
  assert.equal(suggested.requires_gate, null);
  const folder = createCase(store, engine.scope, {
    title: "Idle name",
    summary: "Historical name with no current observation.",
    targets: ["example.com"],
    hypothesis_ids: [created.hypothesis.id],
    notes: ["Do not collect from this case."],
  });
  assert.equal(folder.collection, false);
  assert.equal(folder.network, false);
  const report = caseReport(store, engine.scope, gates(), {
    case_id: folder.id,
  });
  assert.equal(report.collection, false);
  assert.equal(report.executes, false);
  const exported = exportCaseStix(store, engine.scope, { case_id: folder.id });
  assert.equal(exported.read_only, true);
  listCases(store);
  listHypotheses(store);
  caseSummary(store, engine.scope, { case_id: folder.id });
  assert.equal(fetches, 0);
  assert.deepEqual(calls, []);
});

test("a case report separates decisions, candidates, hypotheses and limitations", (t) => {
  const { store, engine } = workspace(t, {
    ...settings,
    scope: { domains: ["example.com"], usernames: ["alex"] },
  });
  load(engine, [
    {
      type: "domain",
      value: "owned.example.com",
      source: "filing-a",
      evidence: { company: "example.com" },
    },
    {
      type: "username",
      value: "alex",
      source: "site-a",
      evidence: { name: "Alex Example" },
    },
    {
      type: "profile",
      value: "https://github.com/alex",
      source: "site-a",
      evidence: { username: "alex", name: "Alex Example" },
    },
    {
      type: "profile",
      value: "https://gitlab.com/alex",
      source: "site-b",
      evidence: { username: "alex", name: "Alex Example" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "owned.example.com",
      source: "filing-b",
      evidence: { company: "example.com" },
    },
  ]);
  const domainId = hash(["domain", "owned.example.com"]);
  const hypothesis = createHypothesis(store, engine.scope, {
    statement: "owned.example.com is the organization's domain",
    claim: "organization-attribution",
    entity_ids: [domainId],
  });
  const association = createHypothesis(store, engine.scope, {
    statement: "The alex profiles are the same person",
    claim: "entity-association",
    entity_ids: [
      hash(["username", "alex"]),
      hash(["profile", "https://github.com/alex"]),
      hash(["profile", "https://gitlab.com/alex"]),
    ],
  });
  evaluateHypothesis(
    store,
    engine.scope,
    gates(),
    { id: hypothesis.hypothesis.id },
    { asOf },
  );
  const decision = recordDecision(store, {
    subject_kind: "entity",
    subject_id: domainId,
    decision: "accept",
    reason: "Two filings name example.com.",
    analyst_id: "analyst-1",
  });
  const created = createCase(store, engine.scope, {
    title: "Organization domain",
    summary: "Review the stored filings separately from the hypothesis.",
    targets: ["owned.example.com"],
    hypothesis_ids: [hypothesis.hypothesis.id, association.hypothesis.id],
    decision_ids: [decision.current.id],
    notes: ["Keep the hypothesis out of the decision section."],
  });
  const report = caseReport(store, engine.scope, gates(), {
    case_id: created.id,
    format: "markdown",
  });
  assert.equal(report.executes, false);
  assert.equal(report.network, false);
  assert.equal(report.collection, false);
  const confirmed = section(report.markdown, "Confirmed analyst decisions");
  const candidates = section(report.markdown, "Candidates");
  const hypotheses = section(report.markdown, "Hypotheses");
  const limitations = section(report.markdown, "Limitations");
  assert.equal(confirmed.includes(hypothesis.hypothesis.statement), false);
  assert.equal(hypotheses.includes(hypothesis.hypothesis.statement), true);
  assert.equal(confirmed.includes("Two filings name example.com."), true);
  assert.equal(candidates.includes("not a confirmed identity"), true);
  assert.equal(limitations.includes("not findings"), true);
  assert.equal(
    report.sections.hypotheses.every(
      (item) => item.finding === false && item.confirmed === false,
    ),
    true,
  );
  assert.equal(
    report.sections.confirmed_analyst_decisions.every(
      (item) => item.finding === false && item.kind === "review-decision",
    ),
    true,
  );
  assert.equal(report.sections.candidates.length >= 1, true);
  assert.equal(
    report.sections.candidates.every((item) => item.status === "candidate"),
    true,
  );
  assert.equal(
    report.sections.hypotheses.find(
      (item) => item.claim === "organization-attribution",
    ).assessed_status,
    "supported-pending-review",
  );
  assert.equal(
    report.sections.hypotheses.find(
      (item) => item.claim === "entity-association",
    ).assessed_status,
    "open",
  );
  assert.equal(RESULT_SCHEMAS.case_report.safeParse(report).success, true);
});

test("case STIX export reuses the exporter and keeps hypotheses as notes", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
    {
      type: "domain",
      value: "owned.example.com",
      source: "crtsh",
      evidence: { record: "1" },
    },
  ]);
  const hypothesis = createHypothesis(store, engine.scope, {
    statement: "owned.example.com was issued a certificate",
    claim: "historical-existence",
    entity_ids: [hash(["domain", "owned.example.com"])],
  });
  const created = createCase(store, engine.scope, {
    title: "Certificate note",
    summary: "Export the stored name without promoting the hypothesis.",
    targets: ["example.com"],
    hypothesis_ids: [hypothesis.hypothesis.id],
  });
  const exported = exportCaseStix(store, engine.scope, { case_id: created.id });
  assert.equal(exported.read_only, true);
  assert.equal(validateStixBundle(exported.bundle).length, 0);
  assert.equal(
    RESULT_SCHEMAS.export_case_stix.safeParse(exported).success,
    true,
  );
  const notes = exported.bundle.objects.filter(
    (object) => object.type === "note" && object.labels?.includes("hypothesis"),
  );
  assert.equal(notes.length, 1);
  assert.equal(notes[0].content.includes("not a finding"), true);
  assert.equal(
    exported.bundle.objects.some(
      (object) =>
        object.type === "indicator" &&
        JSON.stringify(object).includes(hypothesis.hypothesis.statement),
    ),
    false,
  );
});

test("CLI hypothesis and case commands stay local", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-case-cli-"));
  const config = join(dir, "config.json");
  const db = join(dir, "state.sqlite");
  const file = join(dir, "rows.jsonl");
  writeFileSync(config, JSON.stringify(settings));
  writeFileSync(
    file,
    line({
      type: "domain",
      value: "owned.example.com",
      source: "filing-a",
      evidence: { company: "example.com" },
    }),
  );
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const call = (args) =>
    JSON.parse(
      execFileSync(
        process.execPath,
        [cli, ...args, "--config", config, "--db", db],
        { encoding: "utf8" },
      ),
    );
  t.after(() => {
    releaseStore(new Store(db));
    removeTemp(dir);
  });
  assert.equal(
    call(["import", "--adapter", "jsonl", "--file", file]).result.inserted,
    1,
  );
  writeFileSync(
    file,
    line({
      type: "domain",
      value: "owned.example.com",
      source: "filing-b",
      timestamp: "2026-10-21T00:00:00.000Z",
      evidence: { company: "example.com" },
    }),
  );
  assert.equal(
    call(["import", "--adapter", "jsonl", "--file", file]).result.inserted,
    1,
  );
  const id = hash(["domain", "owned.example.com"]);
  const created = call([
    "hypothesis",
    "create",
    "--statement",
    "owned.example.com is the organization domain",
    "--claim",
    "organization-attribution",
    "--entities",
    id,
  ]).result;
  assert.equal(created.hypothesis.finding, false);
  assert.equal(created.collection, false);
  const evaluation = call([
    "hypothesis",
    "evaluate",
    "--id",
    created.hypothesis.id,
  ]).result;
  assert.equal(evaluation.assessed_status, "supported-pending-review");
  assert.equal(evaluation.confirmed, false);
  assert.equal(evaluation.executes, false);
  const folder = call([
    "case",
    "create",
    "--title",
    "CLI case",
    "--summary",
    "Local case over stored filings.",
    "--target",
    "example.com",
    "--hypothesis",
    created.hypothesis.id,
  ]).result;
  const report = call([
    "case",
    "report",
    "--id",
    folder.id,
    "--format",
    "markdown",
  ]).result;
  assert.equal(report.sections.hypotheses.length, 1);
  assert.equal(
    section(report.markdown, "Hypotheses").includes(
      "owned.example.com is the organization domain",
    ),
    true,
  );
  assert.equal(
    section(report.markdown, "Confirmed analyst decisions").includes(
      "owned.example.com is the organization domain",
    ),
    false,
  );
});

test(
  "MCP hypothesis and case tools are additive and do not collect",
  { timeout: 20_000 },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "osint-case-mcp-"));
    const config = join(dir, "config.json");
    writeFileSync(config, JSON.stringify(settings));
    const client = new Client({ name: "case-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../src/mcp.js", import.meta.url))],
      env: {
        ...process.env,
        OSINT_POWER_CONFIG: config,
        OSINT_POWER_DB: join(dir, "state.sqlite"),
      },
      stderr: "pipe",
    });
    t.after(async () => {
      await client.close();
      try {
        releaseStore(new Store(join(dir, "state.sqlite")));
      } catch {
        // The server may already have closed the file.
      }
      removeTemp(dir);
    });
    await client.connect(transport);
    const names = (await client.listTools()).tools.map((tool) => tool.name);
    assert.equal(names.length, 43);
    for (const name of [
      "create_hypothesis",
      "update_hypothesis",
      "close_hypothesis",
      "list_hypotheses",
      "evaluate_hypothesis",
      "create_case",
      "list_cases",
      "case_summary",
      "case_report",
      "export_case_stix",
      "investigation_graph",
    ])
      assert.equal(names.includes(name), true);
    const descriptions = Object.fromEntries(
      (await client.listTools()).tools.map((tool) => [
        tool.name,
        tool.description,
      ]),
    );
    assert.equal(
      descriptions.evaluate_hypothesis.includes("not executed"),
      true,
    );
    assert.equal(
      descriptions.evaluate_hypothesis.includes("analyst-confirmed"),
      true,
    );
    assert.equal(
      descriptions.create_hypothesis.includes("not a finding"),
      true,
    );
    await client.callTool({
      name: "import_findings",
      arguments: {
        adapter: "jsonl",
        data: line({
          type: "domain",
          value: "owned.example.com",
          source: "filing-a",
          evidence: { company: "example.com" },
        }),
      },
    });
    await client.callTool({
      name: "import_findings",
      arguments: {
        adapter: "jsonl",
        data: line({
          type: "domain",
          value: "owned.example.com",
          source: "filing-b",
          timestamp: "2026-10-21T00:00:00.000Z",
          evidence: { company: "example.com" },
        }),
      },
    });
    const created = (
      await client.callTool({
        name: "create_hypothesis",
        arguments: {
          statement: "owned.example.com is the organization domain",
          claim: "organization-attribution",
          entity_ids: [hash(["domain", "owned.example.com"])],
        },
      })
    ).structuredContent;
    assert.equal(created.ok, true);
    assert.equal(created.result.hypothesis.finding, false);
    assert.equal(created.result.collection, false);
    const evaluation = (
      await client.callTool({
        name: "evaluate_hypothesis",
        arguments: { id: created.result.hypothesis.id },
      })
    ).structuredContent;
    assert.equal(evaluation.ok, true);
    assert.equal(evaluation.collection_status, "not_applicable");
    assert.equal(evaluation.result.confirmed, false);
    assert.equal(evaluation.result.finding, false);
    assert.equal(evaluation.result.assessed_status, "supported-pending-review");
    assert.equal(
      evaluation.result.next_steps.every((item) => item.executes === false),
      true,
    );
    const folder = (
      await client.callTool({
        name: "create_case",
        arguments: {
          title: "MCP case",
          summary: "Stored filings only.",
          targets: ["example.com"],
          hypothesis_ids: [created.result.hypothesis.id],
        },
      })
    ).structuredContent;
    assert.equal(folder.ok, true);
    const report = (
      await client.callTool({
        name: "case_report",
        arguments: { case_id: folder.result.id },
      })
    ).structuredContent.result;
    assert.equal(report.sections.hypotheses[0].finding, false);
    assert.equal(report.collection, false);
    const graph = (
      await client.callTool({
        name: "investigation_graph",
        arguments: { case_id: folder.result.id, format: "json" },
      })
    ).structuredContent;
    assert.equal(graph.ok, true);
    assert.equal(graph.result.collection, false);
    assert.equal(graph.result.network, false);
    assert.equal(graph.result.read_only, true);
    assert.equal(
      graph.result.graph.edges.some(
        (edge) => edge.kind === "candidate-link" && edge.confirmed,
      ),
      false,
    );
    assert.equal(
      graph.result.graph.nodes.some(
        (node) =>
          node.kind === "hypothesis" &&
          node.status === "supported-pending-review" &&
          node.confirmed,
      ),
      false,
    );
  },
);
