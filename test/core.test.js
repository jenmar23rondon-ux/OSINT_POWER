import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Config } from "../src/schema.js";
import { Scope, domain } from "../src/scope.js";
import { Store, hash } from "../src/store.js";
import { Engine } from "../src/engine.js";
import { parse } from "../src/parsers.js";
import { commandFor } from "../src/adapters.js";
import {
  OperationError,
  retry,
  fetchText,
  runProcess,
} from "../src/transport.js";

const config = (overrides) =>
  Config.parse({
    version: 1,
    scope: {
      domains: ["example.com"],
      excludeDomains: ["excluded.example.com"],
      usernames: ["researcher"],
      documents: ["public.pdf", "config.txt"],
    },
    ...overrides,
  });
const observation = (value, source = "test") => ({
  type: "domain",
  value,
  source,
  confidence: 0.6,
  timestamp: new Date().toISOString(),
  evidence: {},
});

test("defaults populate nested limits and a database cannot silently change scope", (t) => {
  const settings = config();
  assert.equal(settings.limits.timeoutMs, 20000);
  assert.deepEqual(settings.limits.ports, [80, 443]);
  const store = new Store();
  t.after(() => store.close());
  new Engine(settings, store);
  assert.throws(
    () =>
      new Engine(config({ scope: { domains: ["different.invalid"] } }), store),
    /SCOPE_DATABASE_MISMATCH/,
  );
});

test("scope handles IDNs, suffix confusion, exclusions and invalid command arguments", () => {
  const scope = new Scope(config());
  assert.equal(domain("EXAMPLE.COM."), "example.com");
  assert.equal(domain("mañana.example.com"), "xn--maana-pta.example.com");
  assert.equal(scope.host("api.example.com"), true);
  for (const name of [
    "example.com.evil.invalid",
    "badexample.com",
    "x.excluded.example.com",
  ])
    assert.equal(scope.host(name), false);
  for (const input of [
    "--help",
    "example.com;whoami",
    "https://example.com",
    "example.com\ninvalid.com",
  ])
    assert.throws(() => scope.target("subfinder", input));
});
test("discovered IPs and matching usernames do not expand collection scope", () => {
  const scope = new Scope(config());
  assert.equal(
    scope.allows("ip", "192.0.2.1", { host: "api.example.com" }),
    true,
  );
  assert.throws(() => scope.target("naabu", "192.0.2.1"), /OUT_OF_SCOPE/);
  assert.equal(
    scope.allows("profile", "https://example.net/researcher", {
      username: "researcher",
    }),
    true,
  );
  assert.equal(
    scope.allows("profile", "https://example.net/other", { username: "other" }),
    false,
  );
  assert.throws(
    () => scope.target("hibp", "person@example.com"),
    /OUT_OF_SCOPE/,
  );
});
test("canonical evidence hashes and repeated observations do not duplicate entities", (t) => {
  const store = new Store();
  t.after(() => store.close());
  assert.equal(hash({ a: 1, b: 2 }), hash({ b: 2, a: 1 }));
  assert.equal(store.ingest([observation("API.EXAMPLE.COM.")]).inserted, 1);
  assert.equal(store.ingest([observation("api.example.com")]).repeated, 1);
  store.ingest([observation("api.example.com", "second")]);
  const page = store.query();
  assert.equal(page.total, 1);
  assert.equal(page.items[0].evidence_count, 2);
  assert.equal(page.items[0].confidence, 0.6);
});
test("batch validation is atomic, cursor pages are stable, and SQLite survives restart", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-store-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "state.sqlite");
  let store = new Store(path);
  assert.throws(() =>
    store.ingest([observation("a.example.com"), observation("invalid")]),
  );
  assert.equal(store.query().total, 0);
  store.ingest(["a", "b", "c"].map((x) => observation(`${x}.example.com`)));
  const first = store.query({ limit: 2 });
  const second = store.query({ limit: 2, cursor: first.next_cursor });
  assert.equal(
    new Set([...first.items, ...second.items].map((x) => x.id)).size,
    3,
  );
  assert.equal(second.next_cursor, null);
  assert.throws(() => store.query({ limit: 1000 }));
  store.close();
  store = new Store(path);
  assert.equal(store.query().total, 3);
  store.close();
});
test("parsers preserve scoped records, count malformed lines, redact queries and report truncation", () => {
  const scope = new Scope(config());
  const names = parse(
    "crtsh",
    '[{"id":1,"name_value":"*.example.com\\napi.example.com\\nunrelated.invalid"}]',
    scope,
  );
  assert.equal(names.items.length, 2);
  assert.equal(names.skipped, 1);
  const http = parse(
    "httpx",
    '{"url":"https://api.example.com/?token=secret","status_code":200}\nBAD JSON\n{"url":"https://www.example.com"}',
    scope,
  );
  assert.equal(http.items.length, 2);
  assert.equal(http.invalid, 1);
  assert.equal(http.items[0].value.includes("token"), false);
  assert.equal(
    parse("subfinder", "a.example.com\nb.example.com", scope, 1).truncated,
    true,
  );
});
test("Sherlock CSV marks identity uncertain, gitleaks drops raw matches, exiftool selects metadata", () => {
  const scope = new Scope(config());
  const sherlock = parse(
    "sherlock",
    'username,name,url_main,url_user,exists,http_status,response_time_s\r\nresearcher,"A, B",https://example.net,https://example.net/researcher,Claimed,200,0.1\r\nresearcher,C,https://example.net,https://example.net/no,Available,404,0.1\r\n',
    scope,
  );
  assert.equal(sherlock.items.length, 2);
  assert.equal(sherlock.items[1].evidence.inferred, true);
  const leaks = parse(
    "gitleaks",
    '[{"File":"config.txt","StartLine":2,"RuleID":"api-key","Secret":"DO_NOT_PERSIST","Match":"DO_NOT_PERSIST"}]',
    scope,
  );
  assert.equal(leaks.items.length, 1);
  assert.equal(JSON.stringify(leaks).includes("DO_NOT_PERSIST"), false);
  const exif = parse(
    "exiftool",
    '[{"SourceFile":"public.pdf","Producer":"Demo","GPSPosition":"private"}]',
    scope,
  );
  assert.equal(exif.items.length, 2);
  assert.equal(JSON.stringify(exif).includes("GPSPosition"), false);
});
test("network and active controls prevent provider/process calls", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  let called = false;
  const engine = new Engine(config(), store, {
    fetcher: () => {
      called = true;
    },
  });
  await assert.rejects(
    engine.run({ adapter: "crtsh", target: "example.com" }),
    /NETWORK_DISABLED/,
  );
  engine.config.network = true;
  engine.config.enabledAdapters = ["dnsx"];
  await assert.rejects(
    engine.run({ adapter: "dnsx", target: "api.example.com" }),
    /ACTIVE_DISABLED/,
  );
  assert.equal(called, false);
});
test("retry caps attempts, respects Retry-After and avoids retrying permanent failures", async () => {
  let calls = 0;
  const waits = [];
  await assert.rejects(
    retry(
      async () => {
        calls++;
        throw new OperationError("HTTP_429", true, 2000);
      },
      { attempts: 3, minIntervalMs: 0 },
      async (delay) => waits.push(delay),
    ),
    /HTTP_429/,
  );
  assert.equal(calls, 3);
  assert.deepEqual(waits, [2000, 2000]);
  calls = 0;
  await assert.rejects(
    retry(
      async () => {
        calls++;
        throw new OperationError("HTTP_401");
      },
      { attempts: 3 },
    ),
    /HTTP_401/,
  );
  assert.equal(calls, 1);
});
test("HTTP response bytes are bounded and redirects are disabled", async () => {
  const limits = config().limits;
  await assert.rejects(
    fetchText(
      "https://crt.sh/",
      { ...limits, maxBytes: 5 },
      {},
      async (_url, options) => {
        assert.equal(options.redirect, "error");
        return new Response("123456");
      },
    ),
    /RESPONSE_TOO_LARGE/,
  );
  await assert.rejects(
    fetchText(
      "https://crt.sh/",
      limits,
      {},
      async () => new Response("", { status: 403 }),
    ),
    /HTTP_403/,
  );
});
test("pipeline keeps successful findings on missing binary and caches repeated collection", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  let calls = 0;
  const engine = new Engine(
    config({
      network: true,
      enabledAdapters: ["crtsh", "subfinder"],
      limits: { minIntervalMs: 0 },
    }),
    store,
    {
      fetcher: async () => {
        calls++;
        return new Response('[{"id":1,"name_value":"api.example.com"}]');
      },
      runner: async () => {
        throw new OperationError("TOOL_NOT_INSTALLED");
      },
    },
  );
  const result = await engine.pipeline("example.com");
  assert.equal(result.status, "partial");
  assert.equal(store.query().total, 1);
  const again = await engine.run({ adapter: "crtsh", target: "example.com" });
  assert.equal(again.cached, true);
  assert.equal(calls, 1);
  assert.equal(again.inserted, 0);
  assert.equal(
    store.runs().some((r) => r.status === "failed"),
    true,
  );
});
test("import preserves valid JSONL rows while reporting malformed and excluded records", (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(config(), store);
  const result = engine.import({
    adapter: "jsonl",
    data: JSON.stringify(observation("api.example.com")) + "\nBROKEN",
  });
  assert.equal(result.status, "partial");
  assert.equal(result.invalid, 1);
  assert.equal(store.query().total, 1);
  assert.equal(
    engine.import({
      adapter: "exiftool",
      data: '[{"SourceFile":"private.pdf","Author":"Someone"}]',
    }).skipped,
    2,
  );
});
test("binary arguments contain explicit rates and ports and never follow HTTP redirects", () => {
  const limits = config().limits;
  assert.equal(
    commandFor("naabu", "example.com", limits).args.includes("80,443"),
    true,
  );
  assert.equal(
    commandFor("amass", "example.com", limits).args.includes("-passive"),
    true,
  );
  assert.equal(
    commandFor("httpx", "example.com", limits).args.includes(
      "-follow-redirects",
    ),
    false,
  );
});
test("process limits stop local fixtures and missing binaries return a bounded error", async () => {
  const limits = { timeoutMs: 2000, maxBytes: 100 };
  await assert.rejects(
    runProcess(
      process.execPath,
      ["-e", 'process.stdout.write("x".repeat(101))'],
      limits,
    ),
    /RESPONSE_TOO_LARGE/,
  );
  await assert.rejects(
    runProcess(process.execPath, ["-e", "setTimeout(()=>{},10000)"], {
      ...limits,
      timeoutMs: 100,
    }),
    /PROCESS_TIMEOUT/,
  );
  await assert.rejects(
    runProcess("osint-power-nonexistent-fixture", [], limits),
    /TOOL_NOT_INSTALLED/,
  );
});
