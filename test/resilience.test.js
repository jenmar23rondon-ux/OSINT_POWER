import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store, hash } from "../src/store.js";
import { Engine } from "../src/engine.js";
import { compareRuns, explainEntity, sourceFamily } from "../src/state.js";
import { ProviderGate } from "../src/providers.js";
import { Config } from "../src/schema.js";
import { runProcess, OperationError } from "../src/transport.js";
import { doctor } from "../src/doctor.js";
import { planInvestigation } from "../src/planning.js";
import { report } from "../src/report.js";
import { reportHTML } from "../src/dashboard.js";

const settings = (extra) =>
  Config.parse({
    version: 1,
    scope: { domains: ["example.com"] },
    network: true,
    enabledAdapters: ["crtsh"],
    limits: { minIntervalMs: 0, cacheTtlSeconds: 0, attempts: 1 },
    ...extra,
  });
const openStores = new Map();
function fileStore(path) {
  const store = new Store(path);
  const stores = openStores.get(path) ?? [];
  stores.push(store);
  openStores.set(path, stores);
  return store;
}
function temporary(t) {
  const dir = mkdtempSync(join(tmpdir(), "osint-v03-"));
  const path = join(dir, "state.sqlite");
  t.after(() => {
    for (const store of openStores.get(path) ?? []) store.close();
    openStores.delete(path);
    rmSync(dir, { recursive: true, force: true });
  });
  return path;
}
const response = () =>
  new Response('[{"name_value":"api.example.com","id":1}]');
const normalized = (type, value, evidence = {}) => ({
  type,
  value,
  source: "fixture",
  confidence: 0.6,
  timestamp: new Date().toISOString(),
  evidence,
});

test("partial workflow resumes across process state without recollecting a completed source", async (t) => {
  const path = temporary(t);
  let calls = 0;
  let engine = new Engine(settings(), fileStore(path), {
    fetcher: async () => {
      calls++;
      return response();
    },
  });
  const first = await engine.workflow({
    workflow: "company",
    target: "example.com",
    execute: true,
    maxTargets: 1,
    maxCalls: 1,
  });
  assert.equal(first.status, "partial");
  assert.equal(calls, 1);
  const id = first.run_id;
  const snapshotCount = engine.store.db
    .prepare("SELECT COUNT(*) AS n FROM run_observations WHERE run_id=?")
    .get(first.snapshot_id).n;
  engine.store.close();
  engine = new Engine(settings(), fileStore(path), {
    fetcher: async () => {
      calls++;
      throw new Error("must not recollect");
    },
  });
  t.after(() => engine.store.close());
  const resumed = await engine.resume({ id, maxCalls: 2 });
  assert.equal(calls, 1);
  assert.equal(
    engine.store.db
      .prepare("SELECT COUNT(*) AS n FROM run_observations WHERE run_id=?")
      .get(first.snapshot_id).n,
    snapshotCount,
  );
  assert.throws(
    () =>
      compareRuns(engine.store, {
        before: first.run_id,
        after: resumed.snapshot_id,
      }),
    /USE_IMMUTABLE_SNAPSHOT_ID/,
  );
  assert.equal(
    resumed.steps.some((s) => s.adapter === "crtsh" && s.checkpoint_reused),
    true,
  );
  const job = engine.jobs.inspect({ id });
  assert.equal(job.calls, 1);
  assert.equal(job.lease_active, false);
  assert.equal(
    job.steps.some((s) => s.status === "completed"),
    true,
  );
});
test("expired worker lease recovers a completed child run and validates immutable job settings", async (t) => {
  const path = temporary(t);
  let calls = 0;
  const engine = new Engine(settings(), fileStore(path), {
    fetcher: async () => {
      calls++;
      return response();
    },
  });
  t.after(() => engine.store.close());
  const child = await engine.run({ adapter: "crtsh", target: "example.com" });
  const job = engine.jobs.create({
    workflow: "company",
    target: "example.com",
    maxTargets: 1,
  });
  engine.store.db
    .prepare(
      "UPDATE jobs SET owner='dead',lease_until=1,status='running' WHERE id=?",
    )
    .run(job.id);
  engine.store.db
    .prepare("INSERT INTO job_steps VALUES(?,?,?,?,?,?,?,?,?,?)")
    .run(
      job.id,
      hash(["passive_domains", "crtsh", "example.com"]),
      "passive_domains",
      "crtsh",
      '{"target":"example.com"}',
      "running",
      1,
      child.run_id,
      null,
      new Date().toISOString(),
    );
  const resumed = await engine.resume({ id: job.id });
  assert.equal(calls, 1);
  assert.equal(
    resumed.steps.some((s) => s.checkpoint_reused),
    true,
  );
  const second = engine.jobs.create({
    workflow: "company",
    target: "example.com",
  });
  engine.config.limits.ports = [8080];
  await assert.rejects(
    engine.resume({ id: second.id }),
    /JOB_CONFIGURATION_CHANGED/,
  );
});
test("two workers cannot claim an active lease; cancellation aborts an in-flight HTTP call", async (t) => {
  const path = temporary(t);
  let started;
  const ready = new Promise((resolve) => (started = resolve));
  const one = new Engine(settings(), fileStore(path), {
    fetcher: async (_url, options) =>
      new Promise((_resolve, reject) => {
        started();
        options.signal.addEventListener(
          "abort",
          () => reject(options.signal.reason),
          { once: true },
        );
      }),
  });
  const two = new Engine(settings(), fileStore(path));
  t.after(() => {
    one.store.close();
    two.store.close();
  });
  const job = one.jobs.create({
    workflow: "company",
    target: "example.com",
    maxTargets: 1,
  });
  const pending = one.resume({ id: job.id });
  await ready;
  await assert.rejects(two.resume({ id: job.id }), /JOB_BUSY/);
  assert.equal(
    two.jobs.cancel({ id: job.id }).status,
    "cancellation_requested",
  );
  const result = await pending;
  assert.equal(result.status, "cancelled");
  assert.equal(one.jobs.inspect({ id: job.id }).lease_active, false);
  await assert.rejects(one.resume({ id: job.id }), /JOB_CANCELLED/);
});
test("queued job can be cancelled without collection; subprocess cancellation stops local work", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(settings(), store);
  const job = engine.jobs.create({
    workflow: "company",
    target: "example.com",
  });
  assert.equal(engine.jobs.cancel({ id: job.id }).status, "cancelled");
  const controller = new AbortController();
  const pending = runProcess(
    process.execPath,
    ["-e", "setInterval(()=>{},1000)"],
    { timeoutMs: 5000, maxBytes: 100 },
    "",
    { signal: controller.signal },
  );
  controller.abort(new OperationError("CANCELLED"));
  await assert.rejects(pending, /CANCELLED/);
});
test("immutable run comparison separates additions, evidence changes and unobserved records", (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(settings(), store);
  const first = engine.import({
    adapter: "jsonl",
    data: JSON.stringify([
      normalized("domain", "old.example.com"),
      normalized("url", "https://api.example.com/", { technology: ["nginx"] }),
    ]),
  });
  const second = engine.import({
    adapter: "jsonl",
    data: JSON.stringify([
      normalized("domain", "new.example.com"),
      normalized("url", "https://api.example.com/", { technology: ["Apache"] }),
    ]),
  });
  const result = compareRuns(store, {
    before: first.run_id,
    after: second.run_id,
    limit: 1,
  });
  assert.equal(result.counts.added, 1);
  assert.equal(result.counts.not_observed, 1);
  assert.equal(result.counts.evidence_changed, 1);
  assert.equal(result.total, 3);
  assert.equal(result.returned, 1);
  const next = compareRuns(store, {
    before: first.run_id,
    after: second.run_id,
    limit: 100,
    cursor: result.next_cursor,
  });
  assert.equal(next.returned, 2);
  assert.equal(store.query({ type: "domain" }).total, 2);
  assert.equal(JSON.stringify(result).includes('"removed"'), false);
});
test("provider failure produces coverage gaps, and cached snapshots retain original collection time", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  let failed = false;
  const engine = new Engine(settings(), store, {
    fetcher: async () =>
      failed ? new Response("", { status: 503 }) : response(),
  });
  const first = await engine.run({ adapter: "crtsh", target: "example.com" });
  failed = true;
  const second = await engine.run({ adapter: "crtsh", target: "example.com" });
  const compared = compareRuns(store, {
    before: first.run_id,
    after: second.run_id,
  });
  assert.equal(compared.counts.coverage_gap, 1);
  assert.equal(compared.counts.not_observed, undefined);
  engine.config.limits.cacheTtlSeconds = 3600;
  failed = false;
  const fresh = await engine.run({ adapter: "crtsh", target: "example.com" });
  const cached = await engine.run({ adapter: "crtsh", target: "example.com" });
  assert.equal(cached.cached, true);
  assert.equal(cached.collected_at, fresh.collected_at);
  const snapshot = store.db
    .prepare("SELECT provenance FROM run_observations WHERE run_id=?")
    .get(cached.run_id);
  const provenance = JSON.parse(snapshot.provenance);
  assert.equal(provenance.from_cache, true);
  assert.equal(provenance.origin_run_id, fresh.run_id);
  assert.equal(
    compareRuns(store, { before: fresh.run_id, after: cached.run_id }).counts
      .unchanged,
    1,
  );
});
test("provider quotas persist between workers and reset at the configured window", async (t) => {
  const path = temporary(t);
  let now = 100000;
  const config = settings({
    limits: {
      minIntervalMs: 0,
      providers: {
        defaults: {
          maxRequests: 1,
          windowMs: 1000,
          minIntervalMs: 0,
          failureThreshold: 3,
          cooldownMs: 100,
        },
        maxWaitMs: 0,
      },
    },
  });
  const one = fileStore(path),
    two = fileStore(path);
  t.after(() => {
    one.close();
    two.close();
  });
  const a = new ProviderGate(one, config.limits, { now: () => now }),
    b = new ProviderGate(two, config.limits, { now: () => now });
  await a.before("crt.sh");
  await assert.rejects(b.before("crt.sh"), /PROVIDER_QUOTA_EXHAUSTED/);
  assert.equal(b.health().providers[0].requests, 1);
  now += 1001;
  await b.before("crt.sh");
  assert.equal(b.health().providers[0].requests, 2);
});
test("Retry-After cooldown survives restart and prevents another request", async (t) => {
  const path = temporary(t);
  let calls = 0;
  const config = settings();
  let engine = new Engine(config, fileStore(path), {
    fetcher: async () => {
      calls++;
      return new Response("", {
        status: 429,
        headers: { "retry-after": "120" },
      });
    },
  });
  await engine.run({ adapter: "crtsh", target: "example.com" });
  engine.store.close();
  engine = new Engine(config, fileStore(path), {
    fetcher: async () => {
      calls++;
      return response();
    },
  });
  t.after(() => engine.store.close());
  const result = await engine.run({ adapter: "crtsh", target: "example.com" });
  assert.equal(result.code, "PROVIDER_COOLDOWN");
  assert.equal(calls, 1);
  assert.equal(engine.providers.health().providers[0].status, "cooldown");
});
test("doctor catches wrong tool dialect, emits no raw probe output, and planner is local", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  let calls = 0;
  const engine = new Engine(
    settings({ enabledAdapters: ["httpx", "crtsh"], active: true }),
    store,
    {
      locateBinary: () => "/fixture/httpx",
      diagnosticRunner: async (_path, args) =>
        args[0] === "-h"
          ? "Python httpx --help"
          : "httpx v1.0.0 SECRET_DO_NOT_PRINT",
      fetcher: async () => {
        calls++;
        return response();
      },
    },
  );
  const diagnosed = await doctor(engine);
  assert.equal(diagnosed.binaries[0].compatibility, "incompatible");
  assert.equal(
    JSON.stringify(diagnosed).includes("SECRET_DO_NOT_PRINT"),
    false,
  );
  const plan = await planInvestigation(engine, {
    workflow: "company",
    target: "example.com",
  });
  assert.equal(plan.network, false);
  assert.equal(calls, 0);
  assert.equal(store.runs().length, 0);
  assert.equal(plan.actions[0].arguments.adapter, "crtsh");
});
test("provenance retains source families without claiming independence; database migrations preserve evidence", async (t) => {
  const path = temporary(t);
  let store = fileStore(path);
  let engine = new Engine(settings(), store, {
    fetcher: async () => response(),
  });
  await engine.run({ adapter: "crtsh", target: "example.com" });
  const id = store.query().items[0].id;
  assert.equal(
    explainEntity(store, id).history[0].provenance.source_family,
    "certificate_transparency",
  );
  assert.equal(
    sourceFamily("subfinder", { upstream: "crtsh" }),
    "certificate_transparency",
  );
  store.db.exec("PRAGMA user_version=1");
  store.close();
  store = fileStore(path);
  assert.equal(store.query().total, 1);
  assert.equal(store.db.prepare("PRAGMA user_version").get().user_version, 4);
  store.db.exec("PRAGMA user_version=5");
  store.close();
  assert.throws(() => fileStore(path), /DATABASE_VERSION_TOO_NEW/);
});
test("correlation totals remain exact beyond samples, and HTML export escapes untrusted script content", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(settings(), store);
  engine.import({
    adapter: "subfinder",
    data: Array.from({ length: 120 }, (_, i) => `host${i}.example.com`).join(
      "\n",
    ),
  });
  const correlated = await engine.workflow({
    workflow: "correlation",
    target: "example.com",
  });
  assert.equal(correlated.correlation.counts.domains, 120);
  assert.equal(correlated.correlation.samples.domains, 100);
  assert.equal(correlated.correlation.truncated, true);
  const data = report(engine);
  data.findings.items[0].value = "</script><script>alert(1)</script>";
  const html = reportHTML(data);
  assert.equal(html.includes("</script><script>alert(1)"), false);
  assert.equal(html.includes("\\u003c/script"), true);
  assert.equal(html.includes("connect-src 'none'"), true);
  assert.equal(html.includes(".innerHTML"), false);
});
