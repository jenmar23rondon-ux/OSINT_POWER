import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Engine } from "../src/engine.js";
import { Store, hash } from "../src/store.js";
import { SCHEMA_VERSION, recordDecision, reviewQueue } from "../src/review.js";
import { RESULT_SCHEMAS, toolResponse } from "../src/contracts.js";
import {
  authorizeApex,
  blockedCandidate,
  generateLookalikes,
  phishingHTML,
  phishingReport,
  rdapDomainUrl,
  runPhishingWorkflow,
} from "../src/phishing.js";
import { Scope } from "../src/scope.js";
import { Config } from "../src/schema.js";

const NOW = Date.parse("2026-11-09T00:00:00.000Z");
function settings(extra = {}) {
  return {
    version: 1,
    scope: {
      domains: ["example.com"],
      excludeDomains: ["excluded.example.com"],
    },
    network: false,
    active: false,
    enabledAdapters: ["crtsh", "certspotter", "wayback", "rdap", "mx"],
    limits: {
      minIntervalMs: 0,
      attempts: 1,
      timeoutMs: 2000,
      providers: {
        defaults: {
          maxRequests: 100,
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
function releaseDatabase(path) {
  try {
    const db = new DatabaseSync(path);
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    db.close();
  } catch {
    // The file may already be gone, or Windows may still be releasing it.
  }
}
function engineFor(t, config = settings(), dependencies = {}) {
  const store = new Store();
  t.after(() => releaseStore(store));
  return new Engine(config, store, { now: () => NOW, ...dependencies });
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
function passiveFetcher(registration = "2026-10-01T00:00:00.000Z") {
  const seen = [];
  const fetcher = async (url) => {
    const parsed = new URL(url);
    seen.push(parsed);
    if (parsed.hostname === "evil.invalid") throw new Error("FOLLOWED_LINK");
    if (parsed.hostname === "crt.sh") {
      assert.equal(parsed.searchParams.get("output"), "json");
      assert.equal(parsed.searchParams.get("q").includes("%"), false);
      return json([
        {
          id: 9,
          name_value: `${parsed.searchParams.get("q")}\nlogin-example.com`,
        },
      ]);
    }
    if (parsed.hostname === "api.certspotter.com")
      return json([
        {
          id: "issuance-1",
          dns_names: [parsed.searchParams.get("domain")],
        },
      ]);
    if (parsed.hostname === "web.archive.org") return json([]);
    if (parsed.hostname === "data.iana.org")
      return json({
        services: [
          [
            [
              "com",
              "net",
              "org",
              "app",
              "io",
              "co",
              "info",
              "biz",
              "xyz",
              "online",
            ],
            [
              "http://rdap.verisign.com/com/v1/",
              "https://user:pass@rdap.verisign.com/com/v1/",
              "https://rdap.verisign.com/com/v1/",
            ],
          ],
        ],
      });
    if (parsed.hostname === "rdap.verisign.com")
      return json({
        events: [{ eventAction: "registration", eventDate: registration }],
        links: [{ href: "https://evil.invalid/kit" }],
      });
    throw new Error(`UNEXPECTED_URL ${url}`);
  };
  return { fetcher, seen };
}
function resolverFor(addresses = ["203.0.113.10"]) {
  const calls = [];
  return {
    calls,
    resolver: {
      cancel() {},
      async resolve4(host) {
        calls.push(["A", host]);
        return addresses;
      },
      async resolveMx(host) {
        calls.push(["MX", host]);
        return [{ priority: 10, exchange: "mx.example.net." }];
      },
      async resolveNs(host) {
        calls.push(["NS", host]);
        return ["ns1.example.net"];
      },
    },
  };
}

test("lookalike generation is deterministic, bounded and stays outside scope", () => {
  const scope = new Scope(Config.parse(settings()));
  const options = {
    maxCandidates: 40,
    reject: (name) => blockedCandidate(scope, name),
  };
  const first = generateLookalikes("example.com", options);
  const second = generateLookalikes("example.com", options);
  assert.deepEqual(first, second);
  assert.equal(first.truncated, true);
  assert.ok(first.variant_count > first.candidates.length);
  assert.equal(
    first.candidates.some((candidate) => candidate.domain === "example.com"),
    false,
  );
  for (const domain of [
    "example.net",
    "examp1e.com",
    "example-login.com",
    "ex-ample.com",
    "eample.com",
  ])
    assert.equal(
      first.candidates.some((candidate) => candidate.domain === domain),
      true,
      domain,
    );
  assert.equal(
    first.candidates.find((candidate) => candidate.domain === "example.net")
      .similarity,
    0.9,
  );
  assert.equal(
    first.candidates.some(
      (candidate) =>
        candidate.technique === "homoglyph" &&
        candidate.domain.startsWith("xn--"),
    ),
    true,
  );
  assert.equal(
    first.candidates.every(
      (candidate) => candidate.similarity > 0 && candidate.similarity <= 0.95,
    ),
    true,
  );
  const excluded = new Scope(
    Config.parse(
      settings({
        scope: {
          domains: ["example.com"],
          excludeDomains: ["example.net"],
        },
      }),
    ),
  );
  const withoutNet = generateLookalikes("example.com", {
    maxCandidates: 40,
    reject: (name) => blockedCandidate(excluded, name),
  });
  assert.equal(
    withoutNet.candidates.some(
      (candidate) => candidate.domain === "example.net",
    ),
    false,
  );
});

test("authorization stays on the configured apex and scope checks are unchanged", async () => {
  const engine = new Engine(
    settings({ network: true, active: true }),
    new Store(),
  );
  try {
    const scope = engine.scope;
    assert.equal(authorizeApex(scope, "example.com"), "example.com");
    assert.throws(() => authorizeApex(scope, "example.net"), /OUT_OF_SCOPE/);
    assert.throws(
      () => authorizeApex(scope, "www.example.com"),
      /APEX_DOMAIN_REQUIRED/,
    );
    assert.throws(
      () => authorizeApex(scope, "excluded.example.com"),
      /OUT_OF_SCOPE/,
    );
    assert.throws(() => authorizeApex(scope, "not a domain"), /INVALID_DOMAIN/);
    assert.throws(
      () =>
        authorizeApex(
          new Scope(
            Config.parse(
              settings({
                scope: { domains: ["ab.com"], excludeDomains: [] },
              }),
            ),
          ),
          "ab.com",
        ),
      /BRAND_LABEL_UNSUPPORTED/,
    );
    await assert.rejects(
      engine.run({ adapter: "crtsh", target: "example.net" }),
      /OUT_OF_SCOPE/,
    );
    await assert.rejects(
      engine.run({ adapter: "httpx", target: "example.net" }),
      /OUT_OF_SCOPE/,
    );
    await assert.rejects(
      engine.run({ adapter: "naabu", target: "example.net" }),
      /OUT_OF_SCOPE/,
    );
  } finally {
    releaseStore(engine.store);
  }
});

test("plan mode does not collect, store or label a candidate as confirmed", async (t) => {
  let called = false;
  const engine = engineFor(t, settings({ network: true, active: true }), {
    fetcher: async () => {
      called = true;
      return json([]);
    },
    resolver: {
      cancel() {},
      async resolve4() {
        called = true;
        return [];
      },
    },
    runner: () => {
      throw new Error("NATIVE_TOOL_INVOKED");
    },
  });
  const plan = await runPhishingWorkflow(engine, {
    target: "example.com",
    maxCandidates: 5,
  });
  assert.equal(plan.mode, "plan");
  assert.equal(plan.status, "planned");
  assert.equal(plan.persisted, false);
  assert.equal(plan.calls, 0);
  assert.equal(plan.http_requests, 0);
  assert.equal(plan.coverage_complete, false);
  assert.equal(called, false);
  assert.equal(
    plan.candidates.every((candidate) => candidate.status === "suspected"),
    true,
  );
  assert.equal(
    plan.candidates.every((candidate) => candidate.entity_id === null),
    true,
  );
  assert.equal(
    engine.store.db
      .prepare("SELECT COUNT(*) AS n FROM phishing_candidates")
      .get().n,
    0,
  );
  assert.equal(engine.store.runs().length, 0);
  assert.equal(
    RESULT_SCHEMAS.run_phishing_workflow.safeParse(plan).success,
    true,
  );
  assert.equal(toolResponse("run_phishing_workflow", plan).ok, true);
  assert.equal(
    toolResponse("run_phishing_workflow", plan).collection_status,
    "not_applicable",
  );
});

test("execute stores suspected leads and enriches only generated candidates", async (t) => {
  const { fetcher, seen } = passiveFetcher();
  const dns = resolverFor();
  const engine = engineFor(t, settings({ network: true, active: true }), {
    fetcher,
    resolver: dns.resolver,
    runner: () => {
      throw new Error("NATIVE_TOOL_INVOKED");
    },
  });
  engine.import({ adapter: "subfinder", data: "example.com\n" });
  const result = await runPhishingWorkflow(engine, {
    target: "example.com",
    execute: true,
    maxCandidates: 2,
    maxCalls: 20,
  });
  assert.equal(result.mode, "execute");
  assert.equal(result.status, "completed");
  assert.equal(result.persisted, true);
  assert.equal(result.calls, 10);
  assert.equal(result.http_requests, 10);
  assert.equal(result.review.queued, 2);
  assert.equal(
    result.candidates.every((candidate) => candidate.status === "suspected"),
    true,
  );
  for (const candidate of result.candidates) {
    const signals = Object.fromEntries(
      candidate.signals.map((item) => [item.signal, item]),
    );
    assert.equal(signals.name_similarity.present, true);
    assert.equal(signals.recently_registered.present, true);
    assert.equal(signals.recently_registered.evidence.threshold_days, 400);
    assert.equal(signals.has_mx.present, true);
    assert.match(signals.has_mx.basis, /Mailbox existence/);
    assert.equal(signals.certificate_brand_terms.present, true);
    assert.equal(signals.shares_infrastructure.present, true);
    assert.equal(signals.certificate_brand_terms.source, "crtsh");
    assert.match(signals.shares_infrastructure.basis, /203\.0\.113\.10/);
  }
  assert.equal(
    seen.some((url) => url.hostname === "evil.invalid"),
    false,
  );
  assert.equal(
    seen.some((url) => url.hostname === "rdap.verisign.com"),
    true,
  );
  const queue = reviewQueue(engine.store, { limit: 20 });
  for (const candidate of result.candidates)
    assert.equal(
      queue.items.some((item) => item.entity_id === candidate.entity_id),
      true,
    );
  const edge = engine.store
    .graph(50)
    .items.find((item) => item.relation === "impersonates");
  assert.equal(edge.to_value, "example.com");
  const evidence = engine.store.evidence(result.candidates[0].entity_id, 20);
  assert.equal(
    evidence.items.some(
      (item) =>
        item.source === "lookalike" &&
        item.untrusted === true &&
        item.evidence.verification === "suspected_impersonation_unconfirmed",
    ),
    true,
  );
  const report = phishingReport(engine, { target: "example.com" });
  assert.equal(report.classification, "unverified_leads");
  assert.match(report.markdown, /Unverified leads/);
  assert.match(report.markdown, /suspected/);
  assert.equal(report.candidates[0].status, "suspected");
  const html = phishingHTML({
    ...report,
    candidates: report.candidates.map((candidate) => ({
      ...candidate,
      basis: "<script>alert(1)</script>",
    })),
  });
  assert.equal(html.includes("<script>alert"), false);
  assert.match(html, /\\u003cscript/);
  assert.match(html, /form-action 'none'/);
  recordDecision(engine.store, {
    subject_kind: "entity",
    subject_id: result.candidates[0].entity_id,
    decision: "accept",
    reason: "Worth a human notice to the brand owner.",
    analyst_id: "analyst-1",
  });
  const accepted = phishingReport(engine, { target: "example.com" });
  const lead = accepted.candidates.find(
    (candidate) => candidate.entity_id === result.candidates[0].entity_id,
  );
  assert.equal(lead.status, "suspected");
  assert.equal(lead.analyst_decision, "accept");
  assert.match(accepted.markdown, /Unverified leads/);
  assert.equal(
    engine.store.db
      .prepare("SELECT status FROM phishing_candidates WHERE entity_id=?")
      .get(lead.entity_id).status,
    "suspected",
  );
  assert.throws(() =>
    engine.store.db
      .prepare("UPDATE phishing_candidates SET status='confirmed'")
      .run(),
  );
  assert.equal(
    engine.store.db.prepare("PRAGMA user_version").get().user_version,
    SCHEMA_VERSION,
  );
});

test("passive and active gates skip sources without weakening them", async (t) => {
  const dns = resolverFor();
  let fetched = false;
  const offline = engineFor(t, settings({ network: false, active: true }), {
    fetcher: async () => {
      fetched = true;
      return json([]);
    },
    resolver: dns.resolver,
  });
  const stored = await runPhishingWorkflow(offline, {
    target: "example.com",
    execute: true,
    maxCandidates: 1,
    maxCalls: 5,
  });
  assert.equal(fetched, false);
  assert.equal(dns.calls.length, 0);
  assert.equal(stored.persisted, true);
  assert.equal(
    stored.candidates[0].enrichment.every(
      (item) => item.status === "network_disabled",
    ),
    true,
  );
  assert.equal(stored.review.queued, 1);
  const activeOff = resolverFor();
  const gated = engineFor(
    t,
    settings({ network: true, active: false, enabledAdapters: ["mx"] }),
    {
      fetcher: async () => {
        throw new Error("PASSIVE_FETCH");
      },
      resolver: activeOff.resolver,
      runner: () => {
        throw new Error("NATIVE_TOOL_INVOKED");
      },
    },
  );
  const passiveSkipped = await runPhishingWorkflow(gated, {
    target: "example.com",
    execute: true,
    maxCandidates: 1,
    maxCalls: 5,
  });
  assert.equal(activeOff.calls.length, 0);
  assert.equal(
    passiveSkipped.candidates[0].enrichment.find(
      (item) => item.source === "dns",
    ).status,
    "active_disabled",
  );
  assert.equal(
    passiveSkipped.candidates[0].signals.find(
      (item) => item.signal === "has_mx",
    ).collected,
    false,
  );
});

test("an old registration is not recent and a one-call budget stops later sources", async (t) => {
  const { fetcher, seen } = passiveFetcher("2010-01-01T00:00:00.000Z");
  const engine = engineFor(
    t,
    settings({
      network: true,
      active: false,
      enabledAdapters: ["crtsh", "rdap"],
    }),
    { fetcher },
  );
  const result = await runPhishingWorkflow(engine, {
    target: "example.com",
    execute: true,
    maxCandidates: 2,
    maxCalls: 2,
  });
  assert.equal(result.status, "partial");
  assert.equal(result.calls, 2);
  assert.equal(seen.length, 3);
  const first = result.candidates[0];
  const registered = first.signals.find(
    (item) => item.signal === "recently_registered",
  );
  assert.equal(registered.present, false);
  assert.equal(registered.collected, true);
  assert.equal(
    first.enrichment.find((item) => item.source === "crtsh").status,
    "completed",
  );
  assert.equal(
    result.candidates[1].enrichment.find((item) => item.source === "crtsh")
      .status,
    "budget_exhausted",
  );
  assert.equal(
    rdapDomainUrl(
      {
        services: [
          [
            ["com"],
            [
              "http://rdap.verisign.com/com/v1/",
              "https://user:pass@rdap.verisign.com/com/v1/",
              "https://rdap.verisign.com/com/v1/",
            ],
          ],
        ],
      },
      "example.com",
    ),
    "https://rdap.verisign.com/com/v1/domain/example.com",
  );
});

test(
  "CLI and MCP expose the workflow without changing the suspected state",
  { timeout: 20_000 },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "osint-phishing-"));
    const config = join(dir, "config.json");
    const db = join(dir, "state.sqlite");
    let client;
    t.after(async () => {
      if (client) await client.close();
      releaseDatabase(db);
      removeTemp(dir);
    });
    writeFileSync(config, JSON.stringify(settings()));
    const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
    const call = (args) =>
      JSON.parse(
        execFileSync(
          process.execPath,
          [cli, ...args, "--config", config, "--db", db],
          { encoding: "utf8" },
        ),
      );
    const plan = call([
      "phishing-scan",
      "--target",
      "example.com",
      "--max-candidates",
      "4",
    ]);
    assert.equal(plan.ok, true);
    assert.equal(plan.result.mode, "plan");
    assert.equal(plan.result.persisted, false);
    const executed = call([
      "phishing-scan",
      "--target",
      "example.com",
      "--execute",
      "--max-candidates",
      "3",
      "--max-calls",
      "2",
    ]);
    assert.equal(executed.ok, true);
    assert.equal(executed.result.persisted, true);
    assert.equal(
      executed.result.candidates.every(
        (candidate) => candidate.status === "suspected",
      ),
      true,
    );
    const report = call(["phishing-report", "--target", "example.com"]);
    assert.equal(report.result.classification, "unverified_leads");
    assert.match(report.result.markdown, /Unverified leads/);
    const htmlPath = join(dir, "leads.html");
    const written = call([
      "phishing-report",
      "--target",
      "example.com",
      "--format",
      "html",
      "--output",
      htmlPath,
    ]);
    assert.equal(written.result.status, "completed");
    const html = readFileSync(htmlPath, "utf8");
    assert.match(html, /UNVERIFIED LEADS/);
    assert.match(html, /connect-src 'none'/);
    assert.throws(() =>
      call(["phishing-scan", "--target", "example.net", "--execute"]),
    );
    client = new Client({ name: "phishing-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../src/mcp.js", import.meta.url))],
      env: { ...process.env, OSINT_POWER_CONFIG: config, OSINT_POWER_DB: db },
      stderr: "pipe",
    });
    transport.stderr.on("data", () => {});
    await client.connect(transport);
    const names = new Set(
      (await client.listTools()).tools.map((tool) => tool.name),
    );
    assert.equal(names.has("run_phishing_workflow"), true);
    assert.equal(names.has("phishing_report"), true);
    assert.equal(names.has("workflow"), true);
    const response = await client.callTool({
      name: "run_phishing_workflow",
      arguments: { target: "example.com", execute: false, maxCandidates: 2 },
    });
    assert.equal(response.isError, undefined);
    assert.equal(response.structuredContent.result.mode, "plan");
    assert.equal(response.structuredContent.result.coverage_complete, false);
    assert.equal(response.structuredContent.schema_version, "0.4");
    const reported = await client.callTool({
      name: "phishing_report",
      arguments: { target: "example.com" },
    });
    assert.equal(
      reported.structuredContent.result.classification,
      "unverified_leads",
    );
    assert.equal(
      hash(["domain", executed.result.candidates[0].domain]).length,
      64,
    );
  },
);
