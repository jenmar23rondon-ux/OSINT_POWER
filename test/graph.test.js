import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Engine } from "../src/engine.js";
import { Store, hash } from "../src/store.js";
import { SCHEMA_VERSION, recordDecision } from "../src/review.js";
import { createCase, createHypothesis } from "../src/cases.js";
import {
  graphHTML,
  investigationGraph,
  presentationClass,
} from "../src/graph-export.js";
import { RESULT_SCHEMAS, toolResponse } from "../src/contracts.js";

const at = "2026-10-20T00:00:00.000Z";
const payload = "</script><img src=x onerror=alert(1)>";
const settings = {
  version: 1,
  scope: {
    domains: ["example.com"],
    usernames: ["alice"],
    documents: ["config.txt"],
  },
  network: false,
  active: false,
  enabledAdapters: ["crtsh"],
};

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
function workspace(t) {
  const store = new Store();
  t.after(() => store.close());
  return { store, engine: new Engine(settings, store) };
}
function line(row) {
  return JSON.stringify({
    confidence: 0.5,
    timestamp: at,
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
function entityId(type, value) {
  return hash([type, value]);
}

test("presentation never paints a candidate as confirmed", () => {
  assert.equal(
    presentationClass({
      kind: "candidate-link",
      status: "candidate",
      confirmed: false,
    }),
    "candidate",
  );
  assert.equal(
    presentationClass({
      kind: "candidate-link",
      status: "confirmed",
      confirmed: true,
    }),
    "candidate",
  );
  assert.equal(
    presentationClass({
      kind: "confirmed-link",
      status: "confirmed",
      confirmed: true,
    }),
    "confirmed",
  );
  assert.equal(
    presentationClass({
      kind: "hypothesis",
      status: "supported-pending-review",
      confirmed: false,
    }),
    "other",
  );
  assert.equal(
    presentationClass({
      kind: "hypothesis",
      status: "analyst-confirmed",
      confirmed: true,
    }),
    "confirmed",
  );
});

test("investigation graph is read-only, escapes HTML, and keeps candidates distinct", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
    {
      type: "email",
      value: "alice@example.com",
      source: "directory",
      evidence: { name: "Alice Doe", public_company: "North" },
    },
  ]);
  load(engine, [
    {
      type: "profile",
      value: "https://example.com/alice",
      source: "site-a",
      evidence: {
        username: "alice",
        name: "Alice Doe",
        public_company: "South",
      },
    },
  ]);
  load(engine, [
    {
      type: "profile",
      value: "https://github.com/alice",
      source: "github-profile",
      evidence: { username: "alice", account: "alice@example.com" },
    },
  ]);
  load(engine, [
    {
      type: "email",
      value: "alice@example.com",
      source: "business-context",
      timestamp: "2026-10-21T00:00:00.000Z",
      evidence: { profile_url: "https://github.com/alice" },
    },
  ]);
  store.ingest([
    {
      type: "secret",
      value: payload,
      source: "fixture",
      confidence: 0.4,
      timestamp: at,
      evidence: { document: "config.txt" },
    },
    {
      type: "domain",
      value: "out.invalid",
      source: "manual",
      confidence: 0.2,
      timestamp: at,
      evidence: {},
    },
  ]);
  const secretId = entityId("secret", payload);
  const emailId = entityId("email", "alice@example.com");
  const hypothesis = createHypothesis(store, engine.scope, {
    statement: payload,
    claim: "entity-association",
    entity_ids: [emailId, secretId],
  });
  const decision = recordDecision(store, {
    subject_kind: "entity",
    subject_id: secretId,
    decision: "needs-more-evidence",
    reason: payload,
    analyst_id: "analyst-1",
  });
  const created = createCase(store, engine.scope, {
    title: "Graph",
    summary: payload,
    targets: ["example.com"],
    hypothesis_ids: [hypothesis.hypothesis.id],
    decision_ids: [decision.current.id],
  });
  const before = {
    hypotheses: store.db.prepare("SELECT COUNT(*) AS n FROM hypotheses").get()
      .n,
    decisions: store.db
      .prepare("SELECT COUNT(*) AS n FROM review_decisions")
      .get().n,
    links: store.db.prepare("SELECT COUNT(*) AS n FROM entity_links").get().n,
    status: store.db
      .prepare("SELECT status FROM hypotheses WHERE id=?")
      .get(hypothesis.hypothesis.id).status,
    version: store.db.prepare("PRAGMA user_version").get().user_version,
  };
  const gates = { network: false, active: false, enabledAdapters: ["crtsh"] };
  const first = investigationGraph(store, engine.scope, gates, {
    case_id: created.id,
    format: "html",
  });
  const second = investigationGraph(store, engine.scope, gates, {
    case_id: created.id,
    format: "html",
  });
  assert.deepEqual(first, second);
  assert.equal(first.read_only, true);
  assert.equal(first.executes, false);
  assert.equal(first.network, false);
  assert.equal(first.collection, false);
  assert.equal(
    RESULT_SCHEMAS.investigation_graph.safeParse(first).success,
    true,
  );
  assert.equal(toolResponse("investigation_graph", first).ok, true);
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM hypotheses").get().n,
    before.hypotheses,
  );
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM review_decisions").get().n,
    before.decisions,
  );
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM entity_links").get().n,
    before.links,
  );
  assert.equal(
    store.db
      .prepare("SELECT status FROM hypotheses WHERE id=?")
      .get(hypothesis.hypothesis.id).status,
    before.status,
  );
  assert.equal(
    store.db.prepare("PRAGMA user_version").get().user_version,
    before.version,
  );
  assert.equal(before.version, SCHEMA_VERSION);
  const html = first.html;
  assert.equal(html.includes("cdn."), false);
  assert.equal(html.includes('src="http'), false);
  assert.equal(html.includes('href="http'), false);
  assert.equal((html.match(/<script/g) ?? []).length, 2);
  assert.equal((html.match(/<\/script>/g) ?? []).length, 2);
  assert.equal(html.includes("</script><img"), false);
  assert.equal(html.includes("<img"), false);
  assert.equal(html.includes("\\u003c/script\\u003e\\u003cimg"), true);
  assert.equal(html.includes("connect-src 'none'"), true);
  assert.equal(
    first.graph.nodes.some((node) => node.label.includes(payload)),
    true,
  );
  assert.equal(
    first.graph.nodes.some((node) => node.label.includes("out.invalid")),
    false,
  );
  const candidates = first.graph.edges.filter(
    (edge) => edge.kind === "candidate-link",
  );
  const confirmed = first.graph.edges.filter(
    (edge) => edge.kind === "confirmed-link",
  );
  assert.equal(candidates.length > 0, true);
  assert.equal(confirmed.length > 0, true);
  assert.equal(
    candidates.every((edge) => edge.status === "candidate" && !edge.confirmed),
    true,
  );
  assert.equal(
    confirmed.every((edge) => edge.status === "confirmed" && edge.confirmed),
    true,
  );
  assert.equal(
    first.graph.nodes.every(
      (node) => node.status !== "supported-pending-review" || !node.confirmed,
    ),
    true,
  );
  assert.equal(html.includes('class="candidate"'), false);
  assert.equal(html.includes(".candidate{"), true);
  assert.equal(html.includes(".confirmed{"), true);
  assert.equal(html.includes(".contradicted{"), true);
  assert.equal(graphHTML(first.graph), html);
});

test("CLI graph pagination stays in place and the case export is an offline file", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-graph-"));
  const config = join(dir, "config.json");
  const db = join(dir, "state.sqlite");
  const html = join(dir, "graph.html");
  writeFileSync(config, JSON.stringify(settings));
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
  const file = join(dir, "rows.jsonl");
  writeFileSync(
    file,
    line({
      type: "domain",
      value: "api.example.com",
      source: "dnsx",
      evidence: {},
    }) +
      "\n" +
      line({
        type: "ip",
        value: "192.0.2.20",
        source: "dnsx",
        evidence: { host: "api.example.com" },
      }),
  );
  assert.equal(
    call(["import", "--adapter", "jsonl", "--file", file]).result.inserted,
    2,
  );
  const page = call(["graph", "--limit", "1"]);
  assert.equal(page.ok, true);
  assert.equal(page.result.items.length, 1);
  assert.equal(page.result.note.includes("not ownership"), true);
  const id = hash(["domain", "api.example.com"]);
  const hypothesis = call([
    "hypothesis",
    "create",
    "--statement",
    "api.example.com is active",
    "--claim",
    "current-activity",
    "--entities",
    id,
  ]).result;
  const created = call([
    "case",
    "create",
    "--title",
    "CLI graph",
    "--summary",
    "Stored import only.",
    "--target",
    "example.com",
    "--hypothesis",
    hypothesis.hypothesis.id,
  ]).result;
  const written = call([
    "graph",
    "--case",
    created.id,
    "--format",
    "html",
    "--output",
    html,
  ]);
  assert.equal(written.ok, true);
  assert.equal(written.result.read_only, true);
  const body = readFileSync(html, "utf8");
  assert.equal(body.includes("<!doctype html>"), true);
  assert.equal(body.includes("cdn."), false);
  assert.equal((body.match(/<script/g) ?? []).length, 2);
  const json = call(["graph", "--case", created.id, "--format", "json"]);
  assert.equal(
    json.result.graph.edges.some(
      (edge) => edge.confirmed && edge.kind === "candidate-link",
    ),
    false,
  );
  assert.equal(json.result.network, false);
});
