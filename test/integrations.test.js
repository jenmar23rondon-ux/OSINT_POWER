import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Engine } from "../src/engine.js";
import { Store } from "../src/store.js";
import { Config } from "../src/schema.js";
import { Scope } from "../src/scope.js";
import { parse } from "../src/parsers.js";
import { fetchText } from "../src/transport.js";

test("HIBP mocked request uses exact account, fixed provider and returns names without raw breach data", async (t) => {
  const original = process.env.HIBP_API_KEY;
  process.env.HIBP_API_KEY = "synthetic-test-key";
  t.after(() => {
    if (original === undefined) delete process.env.HIBP_API_KEY;
    else process.env.HIBP_API_KEY = original;
  });
  const store = new Store();
  t.after(() => store.close());
  const config = {
    version: 1,
    scope: { emails: ["owner@example.com"] },
    network: true,
    enabledAdapters: ["hibp"],
  };
  const engine = new Engine(config, store, {
    fetcher: async (url, options) => {
      assert.equal(new URL(url).hostname, "haveibeenpwned.com");
      assert.equal(options.headers["hibp-api-key"], "synthetic-test-key");
      return new Response(
        '[{"Name":"SyntheticBreach","Password":"never-store"}]',
      );
    },
  });
  const result = await engine.run({
    adapter: "hibp",
    target: "owner@example.com",
  });
  assert.equal(result.status, "completed");
  const evidence = store.evidence(store.query().items[0].id);
  assert.equal(evidence.items[0].evidence.name, "SyntheticBreach");
  assert.equal(JSON.stringify(evidence).includes("never-store"), false);
  assert.equal(
    JSON.stringify(store.runs()).includes("synthetic-test-key"),
    false,
  );
  assert.equal(
    await fetchText(
      "https://haveibeenpwned.com/api/v3/breachedaccount/test",
      engine.config.limits,
      {},
      async () => new Response("", { status: 404 }),
    ),
    "[]",
  );
});
test("remaining import contracts preserve scope and malformed typed fields are partial", () => {
  const scope = new Scope(
    Config.parse({ version: 1, scope: { domains: ["example.com"] } }),
  );
  assert.equal(
    parse("naabu", '{"host":"example.com","ip":"192.0.2.1","port":443}', scope)
      .items[0].type,
    "service",
  );
  assert.equal(
    parse(
      "theharvester",
      '{"emails":["contact@example.com"],"hosts":["api.example.com:192.0.2.1"]}',
      scope,
    ).items.length,
    2,
  );
  assert.equal(
    parse(
      "dnsx",
      '{"host":"api.example.com","a":{}}\n{"host":"www.example.com","a":["192.0.2.2"]}',
      scope,
    ).invalid,
    1,
  );
  const unresolved = {
    type: "unresolved",
    value: "Incomplete email",
    source: "review",
    confidence: 0.2,
    timestamp: new Date().toISOString(),
    evidence: { host: "example.com", reason: "Ambiguous contact" },
  };
  for (const adapter of ["jsonl", "recon-ng", "spiderfoot"])
    assert.equal(
      parse(adapter, JSON.stringify(unresolved), scope).items.length,
      1,
    );
});
test("CLI quickstart demo, init, import and persistent query produce valid JSON; init refuses overwrite", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-cli-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const call = (args) =>
    JSON.parse(
      execFileSync(process.execPath, [cli, ...args], {
        cwd: dir,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }),
    );
  assert.equal(call(["demo"]).result.findings.total, 4);
  assert.equal(call(["init"]).ok, true);
  const before = readFileSync(join(dir, "config.json"), "utf8");
  assert.throws(() => call(["init"]));
  assert.equal(readFileSync(join(dir, "config.json"), "utf8"), before);
  const fixture = fileURLToPath(
    new URL("../examples/subdomains.txt", import.meta.url),
  );
  assert.equal(
    call(["import", "--adapter", "subfinder", "--file", fixture]).result
      .inserted,
    2,
  );
  assert.equal(call(["query", "--type", "domain"]).result.total, 2);
});
