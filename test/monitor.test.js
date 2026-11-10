import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Engine } from "../src/engine.js";
import { Store, hash } from "../src/store.js";
import { Scope } from "../src/scope.js";
import { SCHEMA_VERSION, reviewQueue } from "../src/review.js";
import {
  createMonitor,
  diffAssets,
  listMonitors,
  monitorChanges,
  runMonitor,
  webhookPlan,
} from "../src/monitor.js";

const hex = (char) => char.repeat(64);
function settings(extra = {}) {
  return {
    version: 1,
    scope: { domains: ["example.com"], emails: ["alex@example.com"] },
    network: true,
    active: true,
    enabledAdapters: ["crtsh", "naabu", "mx"],
    limits: {
      minIntervalMs: 0,
      attempts: 1,
      cacheTtlSeconds: 0,
      timeoutMs: 1000,
      providers: {
        defaults: {
          maxRequests: 60,
          windowMs: 60000,
          minIntervalMs: 0,
          failureThreshold: 3,
          cooldownMs: 1000,
        },
        maxWaitMs: 0,
      },
    },
    ...extra,
  };
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
function engineFor(t, config = settings(), dependencies = {}) {
  const store = new Store();
  t.after(() => releaseStore(store));
  return new Engine(config, store, dependencies);
}
function asset(
  key,
  type,
  value,
  attributes,
  observation = hex("a"),
  entity = hex("b"),
) {
  return {
    asset_key: key,
    asset_type: type,
    value,
    attributes,
    observation_ids: [observation],
    entity_ids: [entity],
  };
}

test("diff classifies brand certificates, mail-enabled lookalikes and exposed services", () => {
  const previous = [
    asset("subdomain:api.example.com", "subdomain", "api.example.com", {
      name: "api.example.com",
      historical: false,
    }),
    asset(
      "lookalike:example.net",
      "lookalike",
      "example.net",
      {
        technique: "tld_swap",
        similarity: 0.9,
        has_mx: false,
        mx_collected: true,
        status: "suspected",
      },
      hex("c"),
      hex("d"),
    ),
    asset("host:192.0.2.10", "host", "192.0.2.10", {
      address: "192.0.2.10",
      names: ["api.example.com"],
    }),
  ];
  const current = [
    previous[0],
    asset("subdomain:new.example.com", "subdomain", "new.example.com", {
      name: "new.example.com",
      historical: false,
    }),
    asset(
      "certificate:crtsh:42",
      "certificate",
      "login-example.com",
      { source: "crtsh", record: "42", names: ["login-example.com"] },
      hex("e"),
      hex("f"),
    ),
    asset(
      "lookalike:example.net",
      "lookalike",
      "example.net",
      {
        technique: "tld_swap",
        similarity: 0.9,
        has_mx: true,
        mx_collected: true,
        status: "suspected",
      },
      hex("c"),
      hex("d"),
    ),
    asset(
      "exposure:service:api.example.com:8443",
      "exposure",
      "api.example.com:8443",
      { kind: "service", host: "api.example.com", port: 8443 },
      hex("1"),
      hex("2"),
    ),
  ];
  const diff = diffAssets(
    previous,
    current,
    {},
    {
      subdomain: "comparable",
      certificate: "comparable",
      lookalike: "comparable",
      exposure: "comparable",
      host: "partial",
      dns: "not_collected",
    },
    "example.com",
  );
  assert.deepEqual(diff.alerts.map((item) => item.rule).sort(), [
    "new_certificate_brand_term",
    "new_exposed_service",
    "new_lookalike_with_mx",
  ]);
  assert.equal(
    diff.alerts.every(
      (item) => item.basis.length > 20 && item.observation_ids.length === 1,
    ),
    true,
  );
  assert.equal(
    diff.changes.find((item) => item.asset_key === "subdomain:new.example.com")
      .rule,
    "new_asset",
  );
  assert.equal(
    diff.changes.find((item) => item.asset_key === "host:192.0.2.10").change,
    "coverage_gap",
  );
  assert.equal(
    diff.alerts.some(
      (item) => item.rule === "new_asset" || item.rule === "removed_asset",
    ),
    false,
  );
  const narrowed = diffAssets(
    [],
    current.filter((item) => item.asset_type === "certificate"),
    { include_apex_label: false, brand_terms: [] },
    { certificate: "comparable" },
    "example.com",
  );
  assert.equal(narrowed.alerts.length, 0);
  assert.equal(webhookPlan(false, true, 2).status, "hook_skipped");
  assert.equal(webhookPlan(true, false, 2).status, "disabled");
  assert.equal(webhookPlan(true, true, 0).status, "not_sent");
});

test("schema v6 adds monitor tables without rewriting evidence and rejects a newer database", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-monitor-migrate-"));
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
  legacy.exec("PRAGMA user_version=5");
  legacy.close();
  const store = new Store(path);
  t.after(() => releaseStore(store));
  assert.equal(
    store.db.prepare("PRAGMA user_version").get().user_version,
    SCHEMA_VERSION,
  );
  assert.equal(
    store.db.prepare("SELECT value, last_seen FROM entities WHERE id=?").get(id)
      .value,
    "kept.example.com",
  );
  assert.equal(
    store.db.prepare("SELECT last_seen FROM entities WHERE id=?").get(id)
      .last_seen,
    "2020-01-01T00:00:00.000Z",
  );
  for (const name of [
    "monitors",
    "monitor_runs",
    "monitor_assets",
    "review_decisions",
  ])
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
});

test("monitor runs re-check scope and mode, diff comparable assets, and leave entities unreviewed", async (t) => {
  let certificates = [{ id: 42, name_value: "login.example.com" }];
  let services = '{"host":"login.example.com","port":8443}\n';
  const urls = [];
  const commands = [];
  const engine = engineFor(t, settings(), {
    fetcher: async (url, options = {}) => {
      urls.push({ url: String(url), method: options.method ?? "GET" });
      if (String(url).includes("127.0.0.1")) return new Response("ok");
      return new Response(JSON.stringify(certificates));
    },
    runner: async (command) => {
      commands.push(command);
      if (command === "naabu") return services;
      throw new Error("UNEXPECTED_BINARY");
    },
  });
  assert.throws(
    () =>
      createMonitor(engine, {
        name: "outside",
        investigation: "collectors",
        target: "example.net",
        sources: ["crtsh"],
      }),
    /OUT_OF_SCOPE/,
  );
  assert.throws(
    () =>
      createMonitor(engine, {
        name: "phish-port",
        investigation: "phishing",
        target: "example.com",
        sources: ["crtsh", "naabu"],
      }),
    /SOURCE_NOT_SUPPORTED/,
  );
  assert.throws(
    () =>
      createMonitor(engine, {
        name: "bad-hook",
        investigation: "collectors",
        target: "example.com",
        sources: ["crtsh"],
        webhook_url: "http://user:pass@127.0.0.1/hook",
      }),
    /WEBHOOK_URL_REJECTED/,
  );
  const created = createMonitor(engine, {
    name: "edge",
    investigation: "company",
    target: "example.com",
    sources: ["crtsh", "naabu"],
    interval_hint: "24h",
  });
  assert.equal(created.webhook_enabled, false);
  assert.equal(created.scheduler, "external");
  const first = await runMonitor(engine, { id: created.id, max_calls: 10 });
  assert.equal(first.status, "completed");
  assert.equal(first.coverage_complete, false);
  assert.deepEqual(first.alerts.map((item) => item.rule).sort(), [
    "new_certificate_brand_term",
    "new_exposed_service",
  ]);
  assert.equal(
    first.alerts.every((item) =>
      /not ownership|not a confirmed vulnerability/.test(item.basis),
    ),
    true,
  );
  assert.equal(commands.includes("naabu"), true);
  assert.equal(
    urls.some((item) => item.url.includes("crt.sh")),
    true,
  );
  assert.equal(
    urls.some((item) => item.method === "POST"),
    false,
  );
  assert.equal(first.review.auto_confirmed, false);
  assert.equal(first.review.queued_entities >= 2, true);
  assert.equal(
    engine.store.db.prepare("SELECT COUNT(*) AS n FROM review_decisions").get()
      .n,
    0,
  );
  const queue = reviewQueue(engine.store, { limit: 20 });
  const domain = queue.items.find((item) => item.value === "login.example.com");
  const service = queue.items.find((item) => item.type === "service");
  assert.equal(domain.queue_reasons.includes("needs_decision"), true);
  assert.equal(service.current_decision, null);
  const again = await runMonitor(engine, { id: created.id });
  assert.equal(again.counts.added, 0);
  assert.equal(again.counts.alerts, 0);
  assert.equal(again.previous_run_id, first.run_id);
  engine.store.db
    .prepare("INSERT INTO review_decisions VALUES(?,?,?,?,?,?,?)")
    .run(
      "decision-1",
      "entity",
      domain.entity_id,
      "accept",
      "Reviewed hostname.",
      "analyst-1",
      "2026-01-01T00:00:00.000Z",
    );
  services = '{"host":"login.example.com","port":9443}\n';
  const added = await runMonitor(engine, { id: created.id });
  assert.equal(
    added.alerts.some(
      (item) =>
        item.rule === "new_exposed_service" && item.value.endsWith(":9443"),
    ),
    true,
  );
  assert.equal(
    engine.store.db
      .prepare(
        "SELECT decision FROM review_decisions WHERE subject_id=? ORDER BY recorded_at DESC",
      )
      .get(domain.entity_id).decision,
    "accept",
  );
  assert.equal(
    engine.store.db.prepare("SELECT COUNT(*) AS n FROM review_decisions").get()
      .n,
    1,
  );
  certificates = [];
  services = "";
  const removed = await runMonitor(engine, { id: created.id });
  assert.equal(removed.counts.removed > 0, true);
  assert.equal(
    removed.alerts.some((item) => item.rule === "removed_asset"),
    false,
  );
  assert.match(
    monitorChanges(engine.store, { id: created.id }).items.find(
      (item) => item.change === "removed",
    ).basis,
    /not proof of deletion/,
  );
  const callsBefore = urls.length;
  engine.config.enabledAdapters = ["naabu"];
  engine.config.active = false;
  const skipped = await runMonitor(engine, { id: created.id });
  assert.equal(skipped.status, "deferred");
  assert.equal(urls.length, callsBefore);
  assert.equal(skipped.webhook.status, "disabled");
  engine.scope = new Scope({
    ...engine.config,
    scope: { ...engine.config.scope, domains: ["elsewhere.test"] },
  });
  await assert.rejects(
    () => runMonitor(engine, { id: created.id }),
    /OUT_OF_SCOPE/,
  );
});

test("webhook delivery is opt-in and stays behind the network gate", async (t) => {
  const urls = [];
  const engine = engineFor(
    t,
    settings({ enabledAdapters: ["crtsh"], active: false }),
    {
      fetcher: async (url, options = {}) => {
        urls.push({
          url: String(url),
          method: options.method ?? "GET",
          body: options.body,
        });
        if (String(url).includes("127.0.0.1")) throw new Error("hook down");
        return new Response(
          JSON.stringify([{ id: 7, name_value: "login.example.com" }]),
        );
      },
    },
  );
  const silent = createMonitor(engine, {
    name: "silent",
    investigation: "collectors",
    target: "example.com",
    sources: ["crtsh"],
  });
  const quiet = await runMonitor(engine, { id: silent.id });
  assert.equal(quiet.webhook.status, "disabled");
  assert.equal(
    urls.some((item) => String(item.url).includes("127.0.0.1")),
    false,
  );
  const hooked = createMonitor(engine, {
    name: "hooked",
    investigation: "collectors",
    target: "example.com",
    sources: ["crtsh"],
    webhook_url: "http://127.0.0.1/hook",
  });
  const failed = await runMonitor(engine, { id: hooked.id });
  assert.equal(failed.webhook.attempted, true);
  assert.equal(failed.webhook.status, "hook_failed");
  assert.equal(failed.alerts.length > 0, true);
  assert.equal(
    engine.store.db
      .prepare("SELECT status, channel FROM monitor_alerts WHERE monitor_id=?")
      .get(hooked.id).status,
    "hook_failed",
  );
  const offline = engineFor(
    t,
    settings({ network: false, active: false, enabledAdapters: ["crtsh"] }),
    {
      fetcher: async () => {
        throw new Error("network was used");
      },
    },
  );
  const parked = createMonitor(offline, {
    name: "parked",
    investigation: "collectors",
    target: "example.com",
    sources: ["crtsh"],
    webhook_url: "http://127.0.0.1/hook",
  });
  const deferred = await runMonitor(offline, { id: parked.id });
  assert.equal(deferred.status, "deferred");
  assert.equal(deferred.webhook.attempted, false);
  assert.equal(deferred.counts.alerts, 0);
});

test("phishing monitors keep leads suspected and do not query sources the config disables", async (t) => {
  let resolved = 0;
  const engine = engineFor(
    t,
    settings({ active: false, enabledAdapters: ["crtsh", "mx"] }),
    {
      fetcher: async () => new Response("[]"),
      resolver: {
        async resolve4() {
          resolved++;
          return [];
        },
        async resolveMx() {
          resolved++;
          return [{ priority: 10, exchange: "mail.example.net" }];
        },
        async resolveNs() {
          resolved++;
          return [];
        },
        cancel() {},
      },
    },
  );
  const created = createMonitor(engine, {
    name: "lookalikes",
    investigation: "phishing",
    target: "example.com",
    sources: ["crtsh", "mx"],
    max_candidates: 1,
  });
  const result = await runMonitor(engine, { id: created.id, max_calls: 2 });
  assert.equal(resolved, 0);
  assert.equal(
    result.sources.find((item) => item.source === "mx").status,
    "active_disabled",
  );
  assert.equal(result.review.auto_confirmed, false);
  assert.equal(
    engine.store.db.prepare("SELECT COUNT(*) AS n FROM review_decisions").get()
      .n,
    0,
  );
  const lead = engine.store.db
    .prepare("SELECT status FROM phishing_candidates")
    .get();
  assert.equal(lead.status, "suspected");
  assert.equal(result.review.queued_entities >= 1, true);
  const queued = reviewQueue(engine.store, { limit: 10 });
  assert.equal(
    queued.items.some((item) => item.current_decision === null),
    true,
  );
  assert.equal(
    result.alerts.some((item) => item.rule === "new_lookalike_with_mx"),
    false,
  );
});

test(
  "CLI monitor commands and MCP tools are additive",
  { timeout: 20_000 },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "osint-monitor-cli-"));
    const config = join(dir, "config.json");
    const db = join(dir, "state.sqlite");
    const output = join(dir, "changes.md");
    writeFileSync(
      config,
      JSON.stringify(settings({ network: false, active: false })),
    );
    const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
    const call = (args) => {
      try {
        return JSON.parse(
          execFileSync(
            process.execPath,
            [cli, ...args, "--config", config, "--db", db],
            {
              encoding: "utf8",
            },
          ),
        );
      } catch (error) {
        if (!error.stdout) throw error;
        return JSON.parse(error.stdout);
      }
    };
    let client;
    t.after(async () => {
      if (client) await client.close();
      try {
        const opened = new DatabaseSync(db);
        opened.exec("PRAGMA wal_checkpoint(TRUNCATE)");
        opened.close();
      } catch {
        // The server may already have removed the file.
      }
      removeTemp(dir);
    });
    const added = call([
      "monitor",
      "add",
      "--name",
      "daily",
      "--workflow",
      "collectors",
      "--target",
      "example.com",
      "--sources",
      "crtsh",
      "--interval",
      "24h",
    ]);
    assert.equal(added.ok, true);
    assert.equal(added.result.scheduler, "external");
    assert.equal(call(["monitor", "list"]).result.total, 1);
    const ran = call(["monitor", "run", "--id", added.result.id]);
    assert.equal(ran.ok, false);
    assert.equal(ran.result.status, "deferred");
    const written = call([
      "monitor",
      "diff",
      "--id",
      added.result.id,
      "--format",
      "markdown",
      "--output",
      output,
    ]);
    assert.equal(written.ok, true);
    assert.match(readFileSync(output, "utf8"), /external/);
    assert.match(readFileSync(output, "utf8"), /not sent anywhere/);
    assert.equal(call(["query", "extra"]).error.code, "UNEXPECTED_ARGUMENT");
    assert.equal(call(["monitor"]).error.code, "UNKNOWN_COMMAND");
    client = new Client({ name: "monitor-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../src/mcp.js", import.meta.url))],
      env: { ...process.env, OSINT_POWER_CONFIG: config, OSINT_POWER_DB: db },
      stderr: "pipe",
    });
    transport.stderr.on("data", () => {});
    await client.connect(transport);
    const names = (await client.listTools()).tools.map((tool) => tool.name);
    assert.equal(names.length, 32);
    for (const name of [
      "create_monitor",
      "run_monitor",
      "monitor_changes",
      "list_monitors",
      "export_stix",
      "collect",
    ])
      assert.equal(names.includes(name), true);
    const response = await client.callTool({
      name: "run_monitor",
      arguments: { id: added.result.id },
    });
    assert.equal(response.structuredContent.schema_version, "0.4");
    assert.equal(response.structuredContent.result.status, "deferred");
    assert.equal(response.structuredContent.result.coverage_complete, false);
    const listed = await client.callTool({
      name: "list_monitors",
      arguments: {},
    });
    assert.equal(listed.structuredContent.result.total, 1);
    const empty = new Store(":memory:");
    try {
      assert.equal(listMonitors(empty).total, 0);
    } finally {
      empty.close();
    }
  },
);
