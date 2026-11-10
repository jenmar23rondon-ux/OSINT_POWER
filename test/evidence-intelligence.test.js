import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Engine } from "../src/engine.js";
import { Store } from "../src/store.js";
import { explainEntity } from "../src/state.js";
import { RESULT_SCHEMAS, toolResponse } from "../src/contracts.js";
import { SCHEMA_VERSION, recordDecision } from "../src/review.js";
import { assessAssets, explainAsset } from "../src/evidence-intelligence.js";

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
function asset(page, type, value) {
  const found = page.items.find(
    (item) => item.type === type && item.value === value,
  );
  assert.ok(found, `${type} ${value}`);
  return found;
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

test("duplicate and derived sources are not independent corroboration", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
    {
      type: "domain",
      value: "once.example.com",
      source: "alpha",
      evidence: { company: "example.com" },
    },
    {
      type: "domain",
      value: "once.example.com",
      source: "beta",
      evidence: { company: "example.com" },
    },
  ]);
  const sharedRun = assessAssets(store, engine.scope, gates(), {}, { asOf });
  const once = asset(sharedRun, "domain", "once.example.com");
  assert.equal(once.ownership.status, "unverified");
  assert.equal(once.ownership.basis, "duplicate_or_single_source");
  assert.equal(once.ownership.independent_sources, 1);
  assert.equal(once.source_independence.independent_groups, 1);
  assert.equal(once.next_action.executes, false);
  load(engine, [
    {
      type: "domain",
      value: "up.example.com",
      source: "adapter-a",
      evidence: { company: "example.com", upstream: "iana" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "up.example.com",
      source: "adapter-b",
      evidence: { company: "example.com", upstream: "iana" },
    },
  ]);
  const upstream = asset(
    assessAssets(store, engine.scope, gates(), { limit: 100 }, { asOf }),
    "domain",
    "up.example.com",
  );
  assert.equal(upstream.ownership.status, "unverified");
  assert.equal(upstream.ownership.independent_sources, 1);
  load(engine, [
    {
      type: "domain",
      value: "mirror.example.com",
      source: "origin",
      evidence: { company: "example.com" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "mirror.example.com",
      source: "copy",
      evidence: { company: "example.com", mirror_of: "origin" },
    },
  ]);
  const mirror = asset(
    assessAssets(store, engine.scope, gates(), { limit: 100 }, { asOf }),
    "domain",
    "mirror.example.com",
  );
  assert.equal(mirror.ownership.independent_sources, 1);
  assert.equal(mirror.ownership.status, "unverified");
});

test("two independent organization-domain assertions can verify a name and nothing else", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
    {
      type: "domain",
      value: "example.com",
      source: "annual-report",
      evidence: { company: "example.com" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "example.com",
      source: "registry-extract",
      evidence: { company: "example.com" },
    },
  ]);
  const page = assessAssets(
    store,
    engine.scope,
    gates(),
    { limit: 100 },
    { asOf },
  );
  const name = asset(page, "domain", "example.com");
  assert.equal(name.ownership.status, "verified");
  assert.equal(name.ownership.basis, "independent_in_scope_org_domain");
  assert.equal(name.ownership.independent_sources, 2);
  assert.equal(name.ownership.evidence_ids.length, 2);
  assert.equal(name.review.status, "unreviewed");
  assert.equal(
    name.next_action.action,
    "request human review before attribution",
  );
  assert.equal(name.next_action.executes, false);
  assert.equal(
    explainEntity(store, name.entity_id).assessment.ownership,
    "not_established",
  );
  assert.equal(toolResponse("assess_evidence", page).ok, true);
  assert.equal(RESULT_SCHEMAS.assess_evidence.safeParse(page).success, true);
});

test("shared IP, CDN and hosting ASN never verify ownership", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
    {
      type: "domain",
      value: "a.example.com",
      source: "dnsx",
      evidence: {},
    },
    {
      type: "domain",
      value: "b.example.com",
      source: "dnsx",
      evidence: {},
    },
    {
      type: "ip",
      value: "192.0.2.77",
      source: "dnsx",
      evidence: { host: "a.example.com", company: "example.com" },
    },
  ]);
  load(engine, [
    {
      type: "ip",
      value: "192.0.2.77",
      source: "dns-other",
      evidence: { host: "b.example.com", company: "example.com" },
    },
  ]);
  load(engine, [
    {
      type: "ip",
      value: "192.0.2.88",
      source: "httpx",
      evidence: {
        host: "a.example.com",
        company: "example.com",
        technology: ["cloudflare"],
        status: 200,
      },
    },
  ]);
  load(engine, [
    {
      type: "ip",
      value: "192.0.2.88",
      source: "edge",
      evidence: {
        host: "a.example.com",
        company: "example.com",
        technology: ["cloudflare"],
        status: 200,
      },
    },
  ]);
  load(engine, [
    {
      type: "asn",
      value: "AS64500",
      source: "routing",
      evidence: {
        host: "a.example.com",
        ip: "192.0.2.77",
        company: "example.com",
      },
    },
  ]);
  load(engine, [
    {
      type: "asn",
      value: "AS64500",
      source: "rdap",
      evidence: {
        host: "a.example.com",
        ip: "192.0.2.77",
        company: "example.com",
      },
    },
  ]);
  const page = assessAssets(
    store,
    engine.scope,
    gates(),
    { limit: 100 },
    { asOf },
  );
  const shared = asset(page, "ip", "192.0.2.77");
  const cdn = asset(page, "ip", "192.0.2.88");
  const asn = asset(page, "asn", "AS64500");
  assert.equal(shared.ownership.status, "unverified");
  assert.equal(shared.ownership.basis, "shared_ip");
  assert.equal(shared.ownership.independent_sources, 2);
  assert.equal(shared.current_activity.status, "confirmed");
  assert.equal(cdn.ownership.status, "unverified");
  assert.equal(cdn.ownership.basis, "cdn");
  assert.equal(cdn.ownership.independent_sources, 2);
  assert.equal(asn.ownership.status, "unverified");
  assert.equal(asn.ownership.basis, "hosting_or_registry");
  assert.equal(asn.ownership.independent_sources, 2);
  assert.equal(
    page.items.some((item) => item.ownership.status === "verified"),
    false,
  );
});

test("shared names stay candidates and historical evidence is not current activity", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
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
    {
      type: "domain",
      value: "old.example.com",
      source: "wayback",
      timestamp: "2019-01-01T00:00:00.000Z",
      evidence: { historical: true },
    },
    {
      type: "url",
      value: "https://old.example.com/legacy",
      source: "wayback",
      timestamp: "2019-01-01T00:00:00.000Z",
      evidence: { historical: true, status: "200" },
    },
  ]);
  const before = store.db
    .prepare("SELECT COUNT(*) AS n FROM entity_links")
    .get().n;
  const page = assessAssets(
    store,
    engine.scope,
    gates(),
    { limit: 100 },
    { asOf },
  );
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM entity_links").get().n,
    before,
  );
  assert.equal(
    store.db.prepare("PRAGMA user_version").get().user_version,
    SCHEMA_VERSION,
  );
  assert.equal(page.identity_resolution.confirmed_count, 0);
  assert.equal(page.identity_resolution.candidate_count >= 1, true);
  assert.equal(
    page.identity_resolution.candidates.every(
      (link) => link.status === "candidate",
    ),
    true,
  );
  const archived = asset(page, "url", "https://old.example.com/legacy");
  assert.equal(archived.historical_existence.status, "documented");
  assert.equal(archived.current_activity.status, "not_confirmed");
  assert.equal(archived.ownership.status, "unverified");
  assert.equal(page.executes, false);
  assert.equal(page.network, false);
  assert.equal(page.mutation, false);
});

test("historical and recent disagreements are listed and do not confirm ownership", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
    {
      type: "url",
      value: "https://old.example.com/legacy",
      source: "wayback",
      timestamp: "2019-06-01T00:00:00.000Z",
      evidence: { historical: true, status: "200" },
    },
  ]);
  load(engine, [
    {
      type: "url",
      value: "https://old.example.com/legacy",
      source: "httpx",
      evidence: { status: 404 },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "app.example.com",
      source: "dnsx",
      evidence: {},
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "app.example.com",
      source: "dnsx",
      evidence: { status: "nxdomain" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "example.com",
      source: "filing-a",
      evidence: { company: "example.com" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "example.com",
      source: "filing-b",
      evidence: { company: "elsewhere.invalid" },
    },
  ]);
  const page = assessAssets(
    store,
    engine.scope,
    gates(),
    { limit: 100 },
    { asOf },
  );
  const url = asset(page, "url", "https://old.example.com/legacy");
  assert.equal(url.historical_existence.status, "documented");
  assert.equal(url.current_activity.status, "confirmed");
  assert.equal(
    url.conflicts.some((item) => item.kind === "historical_versus_recent"),
    true,
  );
  assert.equal(url.ownership.status, "unverified");
  assert.equal(
    url.next_action.action,
    "request human review before attribution",
  );
  const dns = asset(page, "domain", "app.example.com");
  assert.equal(dns.current_activity.status, "contradicted");
  assert.equal(dns.current_activity.evidence_ids.length, 2);
  assert.equal(dns.historical_existence.status, "not_documented");
  const org = asset(page, "domain", "example.com");
  assert.equal(org.ownership.status, "contradicted");
  assert.equal(org.ownership.basis, "foreign_org_domain");
  assert.equal(org.conflicts.length >= 1, true);
  const view = explainAsset(
    store,
    engine.scope,
    gates(),
    { entity_id: url.entity_id },
    { asOf },
  );
  assert.equal(RESULT_SCHEMAS.explain_asset.safeParse(view).success, true);
  assert.equal(view.identity_resolution.confirmed_count, 0);
});

test("analyst accept does not verify ownership and DNS is suggested only inside gates", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [
    {
      type: "domain",
      value: "old.example.com",
      source: "certspotter",
      timestamp: "2019-01-01T00:00:00.000Z",
      evidence: { historical: true, company: "example.com" },
    },
  ]);
  const id = store
    .query({ type: "domain", limit: 10 })
    .items.find((item) => item.value === "old.example.com").id;
  recordDecision(store, {
    subject_kind: "entity",
    subject_id: id,
    decision: "accept",
    reason: "Name is in the authorized namespace.",
    analyst_id: "analyst-1",
  });
  const closed = explainAsset(
    store,
    engine.scope,
    gates(),
    { entity_id: id },
    { asOf },
  );
  assert.equal(closed.review.status, "accept");
  assert.equal(closed.ownership.status, "unverified");
  assert.equal(closed.current_activity.status, "not_confirmed");
  assert.equal(closed.historical_existence.status, "documented");
  assert.equal(
    closed.next_action.action,
    "request human review before attribution",
  );
  assert.equal(closed.next_action.adapter, null);
  const open = explainAsset(
    store,
    engine.scope,
    gates({
      network: true,
      active: true,
      enabledAdapters: ["crtsh", "dnsx"],
    }),
    { entity_id: id },
    { asOf },
  );
  assert.equal(open.next_action.action, "collect recent in-scope DNS evidence");
  assert.equal(open.next_action.adapter, "dnsx");
  assert.equal(open.next_action.target, "old.example.com");
  assert.equal(open.next_action.executes, false);
  assert.equal(open.ownership.status, "unverified");
  assert.throws(
    () => explainAsset(store, engine.scope, gates(), { entity_id: "nope" }),
    /INVALID_INPUT/,
  );
});

test("assess is read-only from the CLI and stays inside the asset page", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-assess-"));
  const config = join(dir, "config.json");
  const db = join(dir, "state.sqlite");
  const file = join(dir, "rows.jsonl");
  writeFileSync(
    config,
    JSON.stringify({
      version: 1,
      scope: { domains: ["example.com"] },
      network: false,
      active: false,
    }),
  );
  writeFileSync(
    file,
    [
      line({
        type: "domain",
        value: "one.example.com",
        source: "subfinder",
        evidence: {},
      }),
      line({
        type: "domain",
        value: "two.example.com",
        source: "subfinder",
        evidence: {},
      }),
    ].join("\n"),
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
    const store = new Store(db);
    releaseStore(store);
    removeTemp(dir);
  });
  assert.equal(
    call(["import", "--adapter", "jsonl", "--file", file]).result.inserted,
    2,
  );
  const page = call(["assess", "--type", "domain", "--limit", "1"]).result;
  assert.equal(page.returned, 1);
  assert.equal(page.total, 2);
  assert.equal(page.executes, false);
  assert.equal(page.mutation, false);
  const next = call([
    "assess",
    "--type",
    "domain",
    "--limit",
    "1",
    "--cursor",
    page.next_cursor,
  ]).result;
  assert.equal(next.returned, 1);
  assert.equal(next.next_cursor, null);
  assert.notEqual(next.items[0].entity_id, page.items[0].entity_id);
  const one = call(["assess", "--id", page.items[0].entity_id]).result;
  assert.equal(one.entity_id, page.items[0].entity_id);
  assert.equal(one.next_action.executes, false);
  const version = new Store(db);
  assert.equal(
    version.db.prepare("PRAGMA user_version").get().user_version,
    SCHEMA_VERSION,
  );
  releaseStore(version);
});

test(
  "MCP assess_evidence and explain_asset are additive and read-only",
  { timeout: 20_000 },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "osint-assess-mcp-"));
    const config = join(dir, "config.json");
    writeFileSync(
      config,
      JSON.stringify({
        version: 1,
        scope: { domains: ["example.com"] },
        network: false,
        active: false,
      }),
    );
    const client = new Client({ name: "assess-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../src/mcp.js", import.meta.url))],
      env: { ...process.env, OSINT_POWER_CONFIG: config },
      stderr: "pipe",
    });
    t.after(async () => {
      await client.close();
      try {
        releaseStore(new Store(join(dir, ".osint-power", "state.sqlite")));
      } catch {
        // The server may already have removed the file.
      }
      removeTemp(dir);
    });
    await client.connect(transport);
    const names = (await client.listTools()).tools.map((tool) => tool.name);
    assert.equal(names.length, 32);
    assert.equal(names.includes("assess_evidence"), true);
    assert.equal(names.includes("explain_asset"), true);
    assert.equal(names.includes("explain_entity"), true);
    await client.callTool({
      name: "import_findings",
      arguments: {
        adapter: "jsonl",
        data: line({
          type: "domain",
          value: "api.example.com",
          source: "crtsh",
          evidence: { record: "1" },
        }),
      },
    });
    const page = (
      await client.callTool({
        name: "assess_evidence",
        arguments: { type: "domain", limit: 10 },
      })
    ).structuredContent.result;
    assert.equal(page.executes, false);
    assert.equal(page.items[0].value, "api.example.com");
    assert.equal(page.items[0].historical_existence.status, "documented");
    assert.equal(page.items[0].current_activity.status, "not_confirmed");
    assert.equal(page.items[0].ownership.status, "unverified");
    const explained = (
      await client.callTool({
        name: "explain_asset",
        arguments: { entity_id: page.items[0].entity_id },
      })
    ).structuredContent.result;
    assert.equal(explained.entity_id, page.items[0].entity_id);
    assert.equal(explained.next_action.executes, false);
  },
);
