import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Engine } from "../src/engine.js";
import { Store } from "../src/store.js";
import { compareRuns } from "../src/state.js";
import { decodeDiscovery } from "../src/discovery.js";
import { planInvestigation } from "../src/planning.js";

const config = (limits = {}) => ({
  version: 1,
  scope: { domains: ["example.com"], excludeDomains: ["excluded.example.com"] },
  network: true,
  enabledAdapters: ["certspotter", "wayback"],
  limits: { minIntervalMs: 0, attempts: 1, cacheTtlSeconds: 0, ...limits },
});
const cert = (id, names = ["api.example.com"]) =>
  JSON.stringify([{ id, dns_names: names }]);
const header = ["timestamp", "original", "statuscode", "digest"];
const cdx = (name = "api", cursor) =>
  JSON.stringify([
    header,
    [
      "20190101000000",
      `https://${name}.example.com/old?token=discard`,
      "200",
      name,
    ],
    ...(cursor ? [[], [cursor]] : []),
  ]);

test("Cert Spotter cursor and evidence survive restart; empty polling respects successful Retry-After", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-discovery-"));
  const path = join(dir, "state.sqlite");
  const stores = [];
  t.after(() => {
    stores.forEach((s) => s.close());
    rmSync(dir, { recursive: true, force: true });
  });
  const urls = [];
  let body = cert("one"),
    now = 100000;
  const fetcher = async (url) => {
    urls.push(new URL(url));
    return new Response(
      body,
      body === "[]" ? { headers: { "retry-after": "120" } } : {},
    );
  };
  let store = new Store(path);
  stores.push(store);
  let engine = new Engine(config(), store, { fetcher, now: () => now });
  assert.equal(
    (await engine.run({ adapter: "certspotter", target: "example.com" }))
      .discovery.cursor_advanced,
    true,
  );
  assert.equal(urls[0].searchParams.has("after"), false);
  store.close();
  store = new Store(path);
  stores.push(store);
  engine = new Engine(config(), store, { fetcher, now: () => now });
  body = "[]";
  const empty = await engine.run({
    adapter: "certspotter",
    target: "example.com",
  });
  assert.equal(urls[1].searchParams.get("after"), "one");
  assert.equal(empty.discovery.exhausted, true);
  assert.equal(
    store.db.prepare("SELECT cursor FROM discovery_state").get().cursor,
    "one",
  );
  const deferred = await engine.run({
    adapter: "certspotter",
    target: "example.com",
  });
  assert.equal(deferred.status, "deferred");
  assert.equal(urls.length, 2);
  now += 120001;
  body = cert("two", ["new.example.com"]);
  assert.equal(
    (await engine.run({ adapter: "certspotter", target: "example.com" }))
      .inserted,
    1,
  );
  assert.equal(urls[2].searchParams.get("after"), "one");
});

test("Wayback resumes JSON continuation, marks historical edges and requires explicit restart after exhaustion", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  const urls = [];
  let body = cdx("api", "opaque%2Bkey");
  const engine = new Engine(config(), store, {
    fetcher: async (url) => {
      urls.push(new URL(url));
      return new Response(body);
    },
  });
  engine.import({ adapter: "subfinder", data: "api.example.com" });
  const first = await engine.run({ adapter: "wayback", target: "example.com" });
  assert.equal(first.http_requests, 1);
  assert.equal(first.coverage_complete, false);
  assert.equal(JSON.stringify(first).includes("opaque%2Bkey"), false);
  assert.equal(store.graph().items[0].relation, "historically_served");
  assert.equal(
    store.query({ type: "url" }).items[0].value,
    "https://api.example.com/old",
  );
  body = cdx("new");
  const second = await engine.run({
    adapter: "wayback",
    target: "example.com",
  });
  assert.equal(urls[1].searchParams.get("resumeKey"), "opaque%2Bkey");
  const third = await engine.run({ adapter: "wayback", target: "example.com" });
  assert.equal(third.attempts, 0);
  assert.equal(urls.length, 2);
  const plan = await planInvestigation(engine, {
    workflow: "company",
    target: "example.com",
  });
  assert.equal(
    plan.actions.find((a) => a.arguments.adapter === "wayback").eligibility,
    "discovery_exhausted_restart_required",
  );
  await engine.run({
    adapter: "wayback",
    target: "example.com",
    restart: true,
  });
  assert.equal(urls[2].searchParams.has("resumeKey"), false);
  assert.equal(
    compareRuns(store, { before: first.run_id, after: second.run_id }).counts
      .coverage_gap,
    2,
  );
});

test("record limits and malformed archive dates never advance continuation past unparsed evidence", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  let body = cert("one", ["a.example.com", "b.example.com"]);
  const engine = new Engine(config({ maxRecords: 1 }), store, {
    fetcher: async () => new Response(body),
  });
  const first = await engine.run({
    adapter: "certspotter",
    target: "example.com",
  });
  assert.equal(first.status, "partial");
  assert.equal(first.discovery.cursor_advanced, false);
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM discovery_state").get().n,
    0,
  );
  engine.config.limits.maxRecords = 10;
  await engine.run({ adapter: "certspotter", target: "example.com" });
  body = JSON.stringify([
    header,
    ["20260230000000", "https://api.example.com/", "200", "x"],
    [],
    ["later"],
  ]);
  const invalid = await engine.run({
    adapter: "wayback",
    target: "example.com",
  });
  assert.equal(invalid.invalid, 1);
  assert.equal(invalid.discovery.cursor_advanced, false);
  assert.equal(
    store.db
      .prepare(
        "SELECT COUNT(*) AS n FROM discovery_state WHERE adapter='wayback'",
      )
      .get().n,
    0,
  );
});

test("concurrent discovery workers cannot regress a committed cursor or partially ingest a rejected page", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  let release;
  const slow = new Engine(config(), store, {
    fetcher: () =>
      new Promise((resolve) => {
        release = () =>
          resolve(new Response(cert("slow", ["slow.example.com"])));
      }),
  });
  const fast = new Engine(config(), store, {
    fetcher: async () => new Response(cert("fast", ["fast.example.com"])),
  });
  const pending = slow.run({ adapter: "certspotter", target: "example.com" });
  while (!release) await new Promise((r) => setImmediate(r));
  await fast.run({ adapter: "certspotter", target: "example.com" });
  release();
  const result = await pending;
  assert.equal(result.code, "DISCOVERY_CURSOR_CONFLICT");
  assert.equal(
    store.db.prepare("SELECT cursor FROM discovery_state").get().cursor,
    "fast",
  );
  assert.equal(
    store.query().items.some((e) => e.value === "slow.example.com"),
    false,
  );
});

test("malformed continuations, schema drift and cursor stalling fail without progress", async (t) => {
  for (const data of [
    [header, [], ["a"], ["b"]],
    [["original"], ["https://api.example.com"]],
    [header, [], ["bad\nkey"]],
  ])
    assert.throws(() => decodeDiscovery("wayback", JSON.stringify(data)));
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(config(), store, {
    fetcher: async () => new Response(cert("same")),
  });
  await engine.run({ adapter: "certspotter", target: "example.com" });
  assert.equal(
    (await engine.run({ adapter: "certspotter", target: "example.com" })).code,
    "DISCOVERY_CURSOR_STALLED",
  );
  await assert.rejects(
    engine.run({ adapter: "wayback", target: "127.0.0.1" }),
    /DOMAIN_REQUIRED/,
  );
  await assert.rejects(
    engine.run({ adapter: "crtsh", target: "example.com", restart: true }),
    /RESTART_REQUIRES_DISCOVERY_ADAPTER/,
  );
});

test("discovery URL destinations are fixed, keys stay in headers and excluded names are discarded", async (t) => {
  const prior = process.env.CERTSPOTTER_API_KEY;
  process.env.CERTSPOTTER_API_KEY = "synthetic-only-key";
  t.after(() => {
    if (prior === undefined) delete process.env.CERTSPOTTER_API_KEY;
    else process.env.CERTSPOTTER_API_KEY = prior;
  });
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(config(), store, {
    fetcher: async (url, options) => {
      assert.equal(new URL(url).origin, "https://api.certspotter.com");
      assert.equal(options.headers.Authorization, "Bearer synthetic-only-key");
      assert.equal(url.includes("synthetic-only-key"), false);
      return new Response(
        cert("https://evil.invalid/", [
          "api.example.com",
          "excluded.example.com",
          "other.invalid",
        ]),
      );
    },
  });
  const result = await engine.run({
    adapter: "certspotter",
    target: "example.com",
  });
  assert.equal(result.skipped, 2);
  assert.equal(store.query().total, 1);
  assert.equal(
    JSON.stringify(store.runs()).includes("synthetic-only-key"),
    false,
  );
});
