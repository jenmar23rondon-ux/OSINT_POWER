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
import { hash, Store } from "../src/store.js";
import { exportStix, uuidv5 } from "../src/stix.js";
import { validateStixBundle } from "../src/stix-validate.js";
import { SCHEMA_VERSION } from "../src/review.js";
import { toolResponse } from "../src/contracts.js";

const at = "2026-06-01T00:00:00.000Z";
const later = "2026-06-02T00:00:00.000Z";
const settings = {
  version: 1,
  scope: {
    domains: ["example.com"],
    excludeDomains: ["excluded.example.com"],
    ips: ["192.0.2.10"],
  },
  network: true,
  active: true,
  enabledAdapters: ["crtsh", "dnsx", "httpx", "mx"],
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
function line(row) {
  return JSON.stringify({
    confidence: 0.8,
    timestamp: at,
    evidence: {},
    ...row,
  });
}
function workspace(t) {
  const store = new Store(":memory:");
  const engine = new Engine(settings, store, {
    fetcher: () => {
      throw new Error("NETWORK");
    },
  });
  t.after(() => releaseStore(store));
  return { store, engine };
}
function counts(store) {
  const tables = [
    "entities",
    "observations",
    "edges",
    "review_decisions",
    "entity_links",
    "phishing_candidates",
    "phishing_signals",
    "runs",
    "jobs",
    "monitors",
  ];
  return Object.fromEntries(
    tables.map((table) => [
      table,
      store.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n,
    ]),
  );
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
function types(bundle) {
  return bundle.objects.map((object) => object.type);
}
function byType(bundle, type) {
  return bundle.objects.filter((object) => object.type === type);
}

test("uuidv5 matches the RFC 4122 DNS test vector", () => {
  assert.equal(uuidv5("python.org"), "886313e1-3b8a-5372-9b90-0c9aee199e5d");
});

test("validator accepts a hand-built bundle and rejects broken references", () => {
  const identity = "identity--123e4567-e89b-42d3-a456-426614174000";
  const bundle = {
    type: "bundle",
    id: "bundle--123e4567-e89b-42d3-a456-426614174001",
    objects: [
      {
        type: "identity",
        spec_version: "2.1",
        id: identity,
        created: "2026-06-01T00:00:00.000Z",
        modified: "2026-06-01T00:00:00.000Z",
        name: "Example",
        identity_class: "organization",
      },
    ],
  };
  assert.deepEqual(validateStixBundle(bundle), []);
  const missing = structuredClone(bundle);
  delete missing.objects[0].name;
  assert.equal(
    validateStixBundle(missing).some(
      (item) => item.code === "MISSING_PROPERTY",
    ),
    true,
  );
  const stamped = structuredClone(bundle);
  stamped.objects[0].modified = "2026-05-01T00:00:00.000Z";
  assert.equal(
    validateStixBundle(stamped).some((item) => item.code === "TIMESTAMP_ORDER"),
    true,
  );
  const badTime = structuredClone(bundle);
  badTime.objects[0].created = "2026-06-01T00:00:00Z";
  assert.equal(
    validateStixBundle(badTime).some(
      (item) => item.code === "INVALID_TIMESTAMP",
    ),
    true,
  );
  const dangling = structuredClone(bundle);
  dangling.objects.push({
    type: "relationship",
    spec_version: "2.1",
    id: "relationship--123e4567-e89b-42d3-a456-426614174002",
    created: "2026-06-01T00:00:00.000Z",
    modified: "2026-06-01T00:00:00.000Z",
    relationship_type: "related-to",
    source_ref: identity,
    target_ref: "domain-name--123e4567-e89b-42d3-a456-426614174099",
  });
  assert.equal(
    validateStixBundle(dangling).some((item) => item.code === "UNRESOLVED_REF"),
    true,
  );
  const badId = structuredClone(bundle);
  badId.objects[0].id = "identity--not-a-uuid";
  assert.equal(
    validateStixBundle(badId).some((item) => item.code === "OBJECT_ID"),
    true,
  );
});

test("export is a deterministic read of in-scope evidence", (t) => {
  const { store, engine } = workspace(t);
  const imported = load(engine, [
    {
      type: "domain",
      value: "api.example.com",
      source: "crtsh",
      evidence: {
        record: "4242",
        verification: "certificate_name_only",
        valid_from: "2026-01-01T00:00:00.000Z",
        valid_until: "2026-12-01T00:00:00.000Z",
      },
    },
    {
      type: "ip",
      value: "192.0.2.10",
      source: "dnsx",
      evidence: { host: "api.example.com" },
    },
    {
      type: "url",
      value: "https://api.example.com/login",
      source: "httpx",
      evidence: {
        certificate_cn: "api.example.com",
        certificate_issuer: "Example CA",
        host: "api.example.com",
      },
    },
    {
      type: "email",
      value: "ops@example.com",
      source: "workflow",
      confidence: 0.5,
      evidence: {},
    },
    {
      type: "username",
      value: "ops",
      source: "workflow",
      evidence: { account: "ops@example.com" },
    },
  ]);
  load(engine, [
    {
      type: "domain",
      value: "other.example.com",
      source: "crtsh",
      timestamp: later,
      evidence: { record: "4243", verification: "certificate_name_only" },
    },
  ]);
  const lookalike = "examp1e.com";
  const lookalikeId = hash(["domain", lookalike]);
  const emailId = hash(["email", "ops@example.com"]);
  const domainId = hash(["domain", "api.example.com"]);
  store.db
    .prepare("INSERT INTO entities VALUES(?,?,?,?,?)")
    .run(lookalikeId, "domain", lookalike, at, at);
  store.db.prepare("INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)").run(
    hash([lookalikeId, "lookalike", { reason: "omission" }]),
    lookalikeId,
    "lookalike",
    0.5,
    at,
    JSON.stringify({
      reason: "omission",
      verification: "suspected_impersonation_unconfirmed",
      relatedValue: "example.com",
    }),
    at,
    at,
  );
  store.db
    .prepare("INSERT INTO phishing_candidates VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(
      "candidate-1",
      "example.com",
      lookalike,
      lookalikeId,
      "omission",
      0.5,
      "suspected",
      0.5,
      "One character omitted from example.",
      "[]",
      at,
      later,
    );
  store.db
    .prepare("INSERT INTO phishing_signals VALUES(?,?,?,?,?,?,?,?,?)")
    .run(
      "signal-1",
      "candidate-1",
      "name_similarity",
      1,
      1,
      "Edit distance is small.",
      "lookalike",
      "{}",
      at,
    );
  store.db
    .prepare("INSERT INTO review_decisions VALUES(?,?,?,?,?,?,?)")
    .run(
      "11111111-1111-4111-8111-111111111111",
      "entity",
      lookalikeId,
      "accept",
      "Defensive notice only.",
      "analyst-1",
      later,
    );
  const pair = [emailId, domainId].sort();
  store.db
    .prepare("INSERT INTO entity_links VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(
      "link-candidate",
      pair[0],
      pair[1],
      "candidate",
      "shared_handle",
      0.4,
      "Shared handle only.",
      "[]",
      '["ops"]',
      "[]",
      1,
      "[]",
      "shared_name_or_handle_is_not_identity",
      at,
    );
  store.db
    .prepare("INSERT INTO entities VALUES(?,?,?,?,?)")
    .run("e".repeat(64), "domain", "out-of-scope.invalid", at, at);
  store.db
    .prepare("INSERT INTO entities VALUES(?,?,?,?,?)")
    .run(
      hash(["domain", "excluded.example.com"]),
      "domain",
      "excluded.example.com",
      at,
      at,
    );
  store.db
    .prepare("INSERT INTO phishing_candidates VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(
      "candidate-foreign",
      "evil.invalid",
      "evill.invalid",
      "f".repeat(64),
      "omission",
      0.5,
      "suspected",
      0.5,
      "Protected domain is not in scope.",
      "[]",
      at,
      at,
    );
  const before = counts(store);
  const version = store.db.prepare("PRAGMA user_version").get().user_version;
  const exported = exportStix(store, engine.scope, {});
  const again = exportStix(store, engine.scope, {});
  assert.deepEqual(again, exported);
  assert.deepEqual(counts(store), before);
  assert.equal(version, SCHEMA_VERSION);
  assert.equal(
    store.db.prepare("PRAGMA user_version").get().user_version,
    SCHEMA_VERSION,
  );
  assert.equal(validateStixBundle(exported.bundle).length, 0);
  assert.equal(toolResponse("export_stix", exported).ok, true);
  const text = JSON.stringify(exported.bundle);
  assert.equal(text.includes("out-of-scope.invalid"), false);
  assert.equal(text.includes("excluded.example.com"), false);
  assert.equal(text.includes("evil.invalid"), false);
  assert.equal(text.includes("evill.invalid"), false);
  const indicators = byType(exported.bundle, "indicator");
  assert.equal(indicators.length, 1);
  assert.deepEqual(indicators[0].labels, ["suspected"]);
  assert.equal(
    indicators[0].indicator_types.includes("malicious-activity"),
    false,
  );
  assert.match(indicators[0].description, /Not confirmed/);
  assert.match(indicators[0].description, /One character omitted from example/);
  assert.equal(indicators[0].confidence, 50);
  assert.match(indicators[0].pattern, /examp1e\.com/);
  const opinion = byType(exported.bundle, "opinion")[0];
  assert.equal(opinion.opinion, "agree");
  assert.match(opinion.explanation, /does not confirm/);
  assert.equal(opinion.object_refs[0], indicators[0].id);
  const link = byType(exported.bundle, "note").find((item) =>
    item.content.startsWith("Stored link status:"),
  );
  assert.match(link.content, /Stored link status: candidate/);
  assert.match(link.content, /not a confirmed identity/);
  for (const relationship of byType(exported.bundle, "relationship"))
    assert.equal(
      ["related-to", "resolves-to", "based-on"].includes(
        relationship.relationship_type,
      ),
      true,
    );
  assert.equal(
    byType(exported.bundle, "relationship").some(
      (item) => item.relationship_type === "resolves-to",
    ),
    true,
  );
  assert.equal(byType(exported.bundle, "x509-certificate").length >= 2, true);
  assert.equal(
    byType(exported.bundle, "x509-certificate").some(
      (item) => item.serial_number,
    ),
    false,
  );
  assert.equal(byType(exported.bundle, "ipv4-addr")[0].value, "192.0.2.10");
  assert.equal(
    byType(exported.bundle, "email-addr")[0].value,
    "ops@example.com",
  );
  assert.equal(
    byType(exported.bundle, "url").some((item) =>
      item.value.startsWith("https://api.example.com/"),
    ),
    true,
  );
  assert.equal(
    byType(exported.bundle, "identity").some(
      (item) => item.identity_class === "organization",
    ),
    true,
  );
  assert.equal(
    exported.counts.suspected_indicators,
    exported.counts.indicators,
  );
  assert.equal(exported.counts.entities_omitted_out_of_scope >= 2, true);
  assert.equal(exported.read_only, true);
  const scoped = exportStix(store, engine.scope, {
    investigation: imported.run_id,
  });
  const scopedText = JSON.stringify(scoped.bundle);
  assert.equal(scopedText.includes("api.example.com"), true);
  assert.equal(scopedText.includes("other.example.com"), false);
  assert.equal(scopedText.includes(lookalike), false);
  const accepted = exportStix(store, engine.scope, {
    review_status: "accepted",
  });
  const acceptedValues = accepted.bundle.objects
    .filter((object) => object.value)
    .map((object) => object.value);
  assert.equal(acceptedValues.includes(lookalike), true);
  assert.equal(acceptedValues.includes("other.example.com"), false);
  assert.equal(byType(accepted.bundle, "indicator")[0].labels[0], "suspected");
  const windowed = exportStix(store, engine.scope, {
    target: "example.com",
    since: later,
    until: later,
  });
  assert.equal(
    JSON.stringify(windowed.bundle).includes("other.example.com"),
    true,
  );
  assert.equal(
    JSON.stringify(windowed.bundle).includes("api.example.com"),
    false,
  );
  const early = exportStix(store, engine.scope, {
    since: at,
    until: at,
  });
  assert.equal(
    JSON.stringify(early.bundle).includes("other.example.com"),
    false,
  );
  assert.throws(
    () => exportStix(store, engine.scope, { target: "out-of-scope.invalid" }),
    /OUT_OF_SCOPE/,
  );
  assert.throws(
    () => exportStix(store, engine.scope, { target: "excluded.example.com" }),
    /OUT_OF_SCOPE/,
  );
  assert.throws(
    () =>
      exportStix(store, engine.scope, {
        investigation: "11111111-1111-4111-8111-111111111199",
      }),
    /INVESTIGATION_NOT_FOUND/,
  );
  assert.equal(types(exported.bundle).includes("observed-data"), true);
  assert.deepEqual(
    exported.bundle,
    JSON.parse(
      readFileSync(
        new URL("./fixtures/stix-golden.json", import.meta.url),
        "utf8",
      ),
    ),
  );
});

test(
  "CLI export-stix writes a bundle and validate-stix stays offline",
  { timeout: 20_000 },
  (t) => {
    const dir = mkdtempSync(join(tmpdir(), "osint-stix-cli-"));
    const config = join(dir, "config.json");
    const db = join(dir, "state.sqlite");
    const data = join(dir, "in.jsonl");
    const output = join(dir, "bundle.json");
    const bad = join(dir, "bad.json");
    writeFileSync(config, JSON.stringify(settings));
    writeFileSync(
      data,
      `${JSON.stringify({
        type: "domain",
        value: "api.example.com",
        source: "crtsh",
        confidence: 0.6,
        timestamp: at,
        evidence: { record: "77", verification: "certificate_name_only" },
      })}\n`,
    );
    writeFileSync(bad, "{}\n");
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
    t.after(() => {
      try {
        const opened = new DatabaseSync(db);
        opened.exec("PRAGMA wal_checkpoint(TRUNCATE)");
        opened.close();
      } catch {
        // The database may already be gone.
      }
      removeTemp(dir);
    });
    assert.equal(
      call(["import", "--adapter", "jsonl", "--file", data]).ok,
      true,
    );
    const exported = call([
      "export-stix",
      "--target",
      "example.com",
      "--review",
      "any",
      "--output",
      output,
    ]);
    assert.equal(exported.ok, true);
    assert.equal(exported.result.read_only, true);
    assert.equal(exported.result.validation.valid, true);
    const bundle = JSON.parse(readFileSync(output, "utf8"));
    assert.equal(bundle.type, "bundle");
    assert.equal(validateStixBundle(bundle).length, 0);
    assert.equal(call(["validate-stix", "--file", output]).result.valid, true);
    const invalid = call(["validate-stix", "--file", bad]);
    assert.equal(invalid.ok, false);
    assert.equal(invalid.result.valid, false);
    assert.equal(invalid.result.errors.length > 0, true);
  },
);

test(
  "MCP export_stix is additive and read-only",
  { timeout: 20_000 },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "osint-stix-mcp-"));
    const config = join(dir, "config.json");
    writeFileSync(
      config,
      JSON.stringify({ ...settings, network: false, active: false }),
    );
    const client = new Client({ name: "stix-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../src/mcp.js", import.meta.url))],
      env: { ...process.env, OSINT_POWER_CONFIG: config },
      stderr: "pipe",
    });
    t.after(async () => {
      await client.close();
      try {
        const opened = new DatabaseSync(
          join(dir, ".osint-power", "state.sqlite"),
        );
        opened.exec("PRAGMA wal_checkpoint(TRUNCATE)");
        opened.close();
      } catch {
        // The server may already have removed the file.
      }
      removeTemp(dir);
    });
    await client.connect(transport);
    const names = (await client.listTools()).tools.map((tool) => tool.name);
    assert.equal(names.length, 44);
    assert.equal(names.includes("export_stix"), true);
    assert.equal(names.includes("collect"), true);
    await client.callTool({
      name: "import_findings",
      arguments: {
        adapter: "jsonl",
        data: JSON.stringify({
          type: "domain",
          value: "api.example.com",
          source: "crtsh",
          confidence: 0.4,
          timestamp: at,
          evidence: {},
        }),
      },
    });
    const response = await client.callTool({
      name: "export_stix",
      arguments: { target: "example.com", review_status: "unreviewed" },
    });
    assert.equal(response.structuredContent.schema_version, "0.4");
    assert.equal(
      response.structuredContent.collection_status,
      "not_applicable",
    );
    assert.equal(response.structuredContent.result.read_only, true);
    assert.equal(response.structuredContent.result.validation.valid, true);
    assert.equal(
      response.structuredContent.result.bundle.objects.some(
        (object) =>
          object.type === "domain-name" && object.value === "api.example.com",
      ),
      true,
    );
    const rejected = await client.callTool({
      name: "export_stix",
      arguments: { target: "evil.invalid" },
    });
    assert.equal(rejected.isError, true);
    assert.equal(rejected.structuredContent.result.code, "OUT_OF_SCOPE");
  },
);
