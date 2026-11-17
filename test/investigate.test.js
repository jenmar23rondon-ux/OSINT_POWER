import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { correlateEntities } from "../src/correlation.js";
import { RESULT_SCHEMAS } from "../src/contracts.js";
import { Engine } from "../src/engine.js";
import { reportHTML } from "../src/dashboard.js";
import { persistOcr } from "../src/ocr-store.js";
import { FINDING_COLUMNS, findingsCsv, report } from "../src/report.js";
import { SCHEMA_VERSION } from "../src/review.js";
import { exportStix } from "../src/stix.js";
import { Store } from "../src/store.js";

const observedAt = "2026-11-01T00:00:00.000Z";

function workspace(overrides = {}) {
  return {
    version: 1,
    scope: {
      domains: ["example.com"],
      excludeDomains: ["excluded.example.com"],
      emails: ["alex@example.com"],
      usernames: ["example-researcher"],
      documents: ["note.txt"],
    },
    network: true,
    active: false,
    enabledAdapters: ["otx", "hackertarget"],
    limits: { minIntervalMs: 0, attempts: 1, cacheTtlSeconds: 0 },
    ...overrides,
  };
}

function engineWith(store, fetcher, config = workspace()) {
  return new Engine(config, store, {
    fetcher: async (url) => {
      const host = new URL(url).hostname;
      const body = fetcher(host, url);
      return new Response(
        typeof body === "string" ? body : JSON.stringify(body),
      );
    },
  });
}

test("underscore in a findings target is a literal character", (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(
    workspace({ network: false, enabledAdapters: [] }),
    store,
  );
  engine.import({
    adapter: "subfinder",
    data: "x.researchxer.example.com\na.example.com\n",
  });
  const wildcard = store.findings("research_er.example.com", 20);
  assert.equal(
    wildcard.items.some((item) => item.value === "x.researchxer.example.com"),
    false,
  );
  const child = store.findings("example.com", 20);
  assert.equal(
    child.items.some((item) => item.value === "a.example.com"),
    true,
  );
});

test("candidate links explain email, username, GitHub, and domain without confirming identity", (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(
    workspace({ network: false, enabledAdapters: [] }),
    store,
  );
  const fixture = JSON.parse(
    readFileSync(
      new URL("./fixtures/correlation-observations.json", import.meta.url),
      "utf8",
    ),
  );
  store.ingest(fixture.map((item) => ({ ...item, timestamp: observedAt })));
  const correlated = correlateEntities(store, engine.scope);
  assert.equal(
    correlated.items.every((link) => link.candidate && !link.identity),
    true,
  );
  assert.equal(
    correlated.items.some((link) => link.confidence > 0.7),
    false,
  );
  const commit = correlated.items.find(
    (link) => link.relation === "github_commit_email",
  );
  const login = correlated.items.find(
    (link) => link.relation === "github_login",
  );
  const mailbox = correlated.items.find(
    (link) =>
      link.relation === "mailbox_on_domain" &&
      link.from_value === "dev@example.com",
  );
  const handle = correlated.items.find(
    (link) => link.relation === "shared_handle",
  );
  const gravatar = correlated.items.find(
    (link) => link.relation === "gravatar_profile",
  );
  assert.equal(commit.from_value, "dev@example.com");
  assert.equal(commit.to_value, "example-researcher");
  assert.equal(commit.confidence, 0.7);
  assert.match(commit.why, /public GitHub event/);
  assert.equal(login.from_value, "example-researcher");
  assert.equal(login.to_value, "https://github.com/example-researcher");
  assert.match(login.why, /does not prove who controls/);
  assert.equal(mailbox.to_value, "example.com");
  assert.match(mailbox.why, /does not show who controls/);
  assert.equal(handle.from_value, "alex@example.com");
  assert.equal(handle.to_value, "alex");
  assert.equal(handle.confidence, 0.25);
  assert.equal(gravatar.from_value, "alex@example.com");
  assert.equal(gravatar.to_value, "https://gravatar.com/alex");
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM entity_links").get().n,
    0,
  );
  const body = report(engine);
  assert.equal(body.executive_summary.correlations >= 5, true);
  assert.match(body.executive_summary.narrative, /not a confirmed identity/);
  assert.equal(body.correlations_truncated, false);
  assert.deepEqual(body.export_columns, FINDING_COLUMNS);
  assert.equal(
    body.timeline.some((item) => item.value === "dev@example.com"),
    true,
  );
  const csv = findingsCsv(body);
  assert.equal(csv.startsWith(FINDING_COLUMNS.join(",") + "\n"), true);
  assert.deepEqual(
    csv
      .trim()
      .split("\n")
      .slice(1)
      .map((line) => line.split(",")[0])
      .sort(),
    body.findings.items.map((item) => item.id).sort(),
  );
  const quoted = findingsCsv({
    findings: {
      items: [
        {
          id: "abc",
          type: "domain",
          value: "a,b",
          sources: ["crtsh", "otx"],
          confidence: 0.5,
          confidence_basis: "x",
          evidence_count: 1,
          first_seen: observedAt,
          last_seen: observedAt,
        },
      ],
    },
  });
  assert.equal(quoted.includes('"a,b"'), true);
  assert.equal(quoted.includes("crtsh|otx"), true);
  const stix = exportStix(store, engine.scope, { target: "example.com" });
  const names = stix.bundle.objects
    .filter((item) => item.type === "domain-name")
    .map((item) => item.value);
  for (const item of body.findings.items.filter(
    (item) => item.type === "domain",
  ))
    assert.equal(names.includes(item.value), true);
  const html = reportHTML(body);
  assert.equal(html.includes("Executive summary"), true);
  assert.equal(html.includes("Candidate links"), true);
  assert.equal(html.includes("Observation timeline"), true);
  assert.equal(html.includes("unpkg"), false);
  assert.equal(html.includes("jsdelivr"), false);
  assert.equal(html.includes("connect-src 'none'"), true);
  assert.equal(html.includes(commit.why), true);
  assert.equal(RESULT_SCHEMAS.get_report.safeParse(body).success, true);
});

test("investigate plans offline, resumes unfinished sources, and diffs the last run", async (t) => {
  const seen = [];
  let hacker = "API count exceeded";
  let extra = false;
  const store = new Store();
  t.after(() => store.close());
  const fetcher = (host) => {
    seen.push(host);
    if (host === "otx.alienvault.com")
      return {
        passive_dns: [
          {
            hostname: "api.example.com",
            address: "192.0.2.10",
            record_type: "A",
          },
          ...(extra
            ? [
                {
                  hostname: "www.example.com",
                  address: "192.0.2.10",
                  record_type: "A",
                },
              ]
            : []),
        ],
      };
    if (host === "api.hackertarget.com") return hacker;
    throw new Error("UNEXPECTED_HOST");
  };
  const engine = engineWith(store, fetcher);
  seen.length = 0;
  const planned = await engine.investigate({ target: "example.com" });
  assert.equal(planned.status, "planned");
  assert.equal(planned.mode, "plan");
  assert.equal(planned.mutation, false);
  assert.equal(planned.network, false);
  assert.equal(planned.active_collection, false);
  assert.equal(planned.id, null);
  assert.equal(seen.length, 0);
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM investigations").get().n,
    0,
  );
  assert.equal(RESULT_SCHEMAS.investigate.safeParse(planned).success, true);
  const first = await engine.investigate({
    target: "Example.COM",
    execute: true,
  });
  assert.equal(first.kind, "domain");
  assert.equal(first.target, "example.com");
  assert.equal(first.status, "partial");
  assert.equal(first.resumed, false);
  assert.equal(first.diff.baseline, "none");
  assert.equal(first.diff.absent.length, 0);
  assert.equal(first.diff.added.length > 0, true);
  assert.equal(
    first.coverage_gaps.some(
      (gap) => gap.source === "hackertarget" && gap.reason === "rate_limited",
    ),
    true,
  );
  assert.equal(seen.includes("www.virustotal.com"), false);
  const calls = seen.length;
  hacker = "api.example.com,192.0.2.10\n";
  seen.length = 0;
  const resumed = await engine.investigate({ resume: true, id: first.id });
  assert.equal(resumed.resumed, true);
  assert.equal(resumed.diff.baseline, "previous_attempt");
  assert.equal(resumed.status, "completed");
  assert.equal(seen.includes("otx.alienvault.com"), false);
  assert.equal(seen.includes("api.hackertarget.com"), true);
  assert.equal(calls > seen.length, true);
  extra = true;
  const second = await engine.investigate({
    target: "example.com",
    execute: true,
  });
  assert.equal(second.id !== first.id, true);
  assert.equal(second.diff.baseline, "previous_investigation");
  assert.equal(second.diff.baseline_id, resumed.id);
  assert.equal(
    second.diff.added.some((item) => item.value === "www.example.com"),
    true,
  );
  assert.equal(second.diff.unchanged > 0, true);
  const stored = await engine.investigate({ id: second.id });
  assert.equal(stored.mode, "stored");
  assert.equal(stored.mutation, false);
  const sources = engine.sources();
  assert.equal(sources.network, false);
  assert.equal(
    sources.adapters.find((item) => item.name === "httpx").active_only,
    true,
  );
  assert.equal(
    sources.adapters.find((item) => item.name === "wayback")
      .cached_when_completed,
    false,
  );
  assert.equal(RESULT_SCHEMAS.list_sources.safeParse(sources).success, true);
  assert.equal(RESULT_SCHEMAS.investigate.safeParse(resumed).success, true);
});

test("sources names missing keys and does not reveal key values", (t) => {
  const previous = process.env.SECURITYTRAILS_API_KEY;
  process.env.SECURITYTRAILS_API_KEY = "super-secret-value";
  const store = new Store();
  t.after(() => {
    store.close();
    if (previous === undefined) delete process.env.SECURITYTRAILS_API_KEY;
    else process.env.SECURITYTRAILS_API_KEY = previous;
  });
  const engine = new Engine(
    workspace({
      network: false,
      enabledAdapters: ["securitytrails", "github-profile"],
    }),
    store,
  );
  const present = engine.sources();
  assert.equal(JSON.stringify(present).includes("super-secret-value"), false);
  assert.equal(
    present.missing_keys.some((item) => item.adapter === "securitytrails"),
    false,
  );
  delete process.env.SECURITYTRAILS_API_KEY;
  const missing = engine.sources();
  assert.deepEqual(
    missing.missing_keys.find((item) => item.adapter === "securitytrails").env,
    ["SECURITYTRAILS_API_KEY"],
  );
  assert.equal(
    missing.adapters.find((item) => item.name === "github-profile").key_status,
    "optional_missing",
  );
  assert.equal(
    missing.missing_keys.some((item) => item.adapter === "github-profile"),
    false,
  );
});

test("OCR text is stored only for a scoped document basename", (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(
    workspace({ network: false, enabledAdapters: [] }),
    store,
  );
  const ocr = {
    sha256: "ab".repeat(32),
    language: "eng",
    text: "VISUAL EVIDENCE 2026",
    text_truncated: false,
  };
  const saved = persistOcr(store, engine.scope, ocr, "notes\\note.txt");
  assert.equal(saved.saved, true);
  assert.equal(saved.reason, "stored");
  const row = store.evidence(saved.entity_id, 5).items[0];
  assert.equal(row.source, "tesseract");
  assert.equal(row.evidence.text, "VISUAL EVIDENCE 2026");
  assert.equal(row.evidence.text_trust, "untrusted");
  const rejected = persistOcr(store, engine.scope, ocr, "other.txt");
  assert.equal(rejected.saved, false);
  assert.equal(rejected.reason, "DOCUMENT_OUT_OF_SCOPE");
});

test("schema v8 adds investigations without rewriting evidence", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "osint-investigate-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, "state.sqlite");
  const legacy = new DatabaseSync(path);
  legacy.exec(
    `CREATE TABLE entities(id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
     INSERT INTO entities VALUES('abc','domain','kept.example.com','2020-01-01T00:00:00.000Z','2020-01-01T00:00:00.000Z');
     PRAGMA user_version=7`,
  );
  legacy.close();
  const store = new Store(path);
  t.after(() => store.close());
  assert.equal(
    store.db.prepare("PRAGMA user_version").get().user_version,
    SCHEMA_VERSION,
  );
  assert.equal(SCHEMA_VERSION, 8);
  assert.equal(
    store.db.prepare("SELECT value FROM entities WHERE id='abc'").get().value,
    "kept.example.com",
  );
  assert.equal(
    store.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='investigations'",
      )
      .get().name,
    "investigations",
  );
});

test("CLI investigate, sources, and CSV stay local", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "osint-investigate-cli-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const config = join(directory, "config.json");
  writeFileSync(
    config,
    JSON.stringify({
      version: 1,
      network: false,
      active: false,
      enabledAdapters: ["crtsh", "securitytrails"],
      scope: {
        domains: ["example.com"],
        usernames: ["example-researcher"],
        documents: ["note.txt"],
      },
    }),
  );
  const db = join(directory, "state.sqlite");
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const run = (args, env = process.env) => {
    const child = spawnSync(process.execPath, [cli, ...args], {
      cwd: directory,
      encoding: "utf8",
      env,
    });
    assert.equal(child.error, undefined);
    return JSON.parse(child.stdout);
  };
  const quiet = { ...process.env };
  delete quiet.SECURITYTRAILS_API_KEY;
  delete quiet.VIRUSTOTAL_API_KEY;
  const planned = run(
    ["investigate", "--target", "example.com", "--config", config, "--db", db],
    quiet,
  );
  assert.equal(planned.ok, true);
  assert.equal(planned.result.status, "planned");
  assert.equal(planned.result.kind, "domain");
  assert.equal(
    planned.result.missing_keys.includes("SECURITYTRAILS_API_KEY"),
    true,
  );
  const username = run([
    "investigate",
    "--target",
    "other-person",
    "--config",
    config,
    "--db",
    db,
  ]);
  assert.equal(username.ok, false);
  assert.equal(username.error.code, "USERNAME_OUT_OF_SCOPE");
  const resume = run([
    "investigate",
    "--resume",
    "--config",
    config,
    "--db",
    db,
  ]);
  assert.equal(resume.error.code, "INVESTIGATION_ID_REQUIRED");
  const env = { ...process.env, SECURITYTRAILS_API_KEY: "super-secret-value" };
  const listed = run(["sources", "--config", config, "--db", db], env);
  assert.equal(listed.ok, true);
  assert.equal(JSON.stringify(listed).includes("super-secret-value"), false);
  assert.equal(
    listed.result.missing_keys.some(
      (item) => item.adapter === "securitytrails",
    ),
    false,
  );
  const imported = run([
    "import",
    "--adapter",
    "subfinder",
    "--file",
    fileURLToPath(new URL("../examples/subdomains.txt", import.meta.url)),
    "--config",
    config,
    "--db",
    db,
  ]);
  assert.equal(imported.ok, true);
  const csvPath = join(directory, "findings.csv");
  const exported = run([
    "report",
    "--format",
    "csv",
    "--output",
    csvPath,
    "--config",
    config,
    "--db",
    db,
  ]);
  assert.equal(exported.ok, true);
  assert.equal(
    readFileSync(csvPath, "utf8").startsWith(FINDING_COLUMNS.join(",")),
    true,
  );
});
