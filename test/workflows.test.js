import test from "node:test";
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Engine } from "../src/engine.js";
import { Store, hash } from "../src/store.js";
import { Config } from "../src/schema.js";
import { Scope } from "../src/scope.js";
import { usernameVariants } from "../src/identity.js";
import { collectExtra, collectMX, rdapBase } from "../src/collectors.js";

const settings = (extra) =>
  Config.parse({
    version: 1,
    scope: {
      domains: ["example.com", "other.invalid"],
      documents: ["config.txt"],
      people: [
        {
          name: "Ana Pérez",
          companyDomain: "example.com",
          aliases: ["aperez"],
        },
      ],
    },
    ...extra,
  });
const setup = (t, config = settings(), dependencies = {}) => {
  const store = new Store();
  t.after(() => store.close());
  return new Engine(config, store, dependencies);
};
const timestamp = "2026-11-07T00:00:00.000Z";
const business = (extra) => ({
  company_domain: "example.com",
  kind: "role",
  person: "Ana Pérez",
  value: "Engineer",
  source_url: "https://example.com/team",
  timestamp,
  ...extra,
});

test("seven workflow plans are offline, bounded, and do not write state", async (t) => {
  let called = false;
  const engine = setup(t, settings(), {
    fetcher: () => {
      called = true;
    },
  });
  for (const workflow of engine.capabilities().workflows) {
    const result = await engine.workflow({
      workflow,
      target: workflow === "people" ? "Ana Pérez" : "example.com",
    });
    assert.equal(result.status, "planned");
    assert.equal(result.next_actions.length, 3);
  }
  assert.equal(called, false);
  assert.equal(engine.store.query().total, 0);
  assert.equal(engine.store.runs().length, 0);
  await assert.rejects(
    engine.workflow({ workflow: "personas", target: "Unconfigured Person" }),
    /PERSON_OUT_OF_SCOPE/,
  );
  await assert.rejects(
    engine.workflow({ workflow: "empresa", target: "outside.invalid" }),
    /OUT_OF_SCOPE/,
  );
});
test("username variants normalize accents, preserve aliases and reject command flags", (t) => {
  const values = usernameVariants("Ana Pérez", ["aperez"]);
  assert.equal(values.includes("ana.perez"), true);
  assert.equal(values.includes("aperez1"), true);
  assert.equal(values.length <= 20, true);
  const scope = new Scope(settings());
  assert.equal(scope.username("ana.perez01"), true);
  assert.throws(() => scope.target("sherlock", "--help"));
  const cfg = settings();
  const store = new Store();
  t.after(() => store.close());
  new Engine(cfg, store);
  assert.equal(
    store.db.prepare("SELECT value FROM settings WHERE key='scope'").get()
      .value === hash(cfg.scope),
    true,
  );
});
test("professional context imports role, technology and public office edges with provenance", (t) => {
  const engine = setup(t);
  const records = [
    business({}),
    business({ kind: "technology", value: "TypeScript", status: "inferred" }),
    business({
      kind: "place",
      person: undefined,
      value: "Demo office, City",
      place_kind: "public_office",
      source_url: "https://example.com/contact?token=remove",
    }),
  ];
  assert.equal(
    engine.import({
      adapter: "business-context",
      data: JSON.stringify(records),
    }).status,
    "completed",
  );
  assert.equal(engine.store.query({ type: "employee" }).total, 1);
  assert.equal(engine.store.query({ type: "place" }).total, 1);
  const graph = engine.store.graph(100);
  assert.equal(
    graph.items.some((e) => e.relation === "professional_association"),
    true,
  );
  assert.equal(
    graph.items.some((e) => e.relation === "public_office"),
    true,
  );
  const place = engine.store.query({ type: "place" }).items[0];
  assert.equal(
    engine.store
      .evidence(place.id)
      .items[0].evidence.source_url.includes("token"),
    false,
  );
  assert.equal(
    engine.import({
      adapter: "business-context",
      data: JSON.stringify(
        business({
          kind: "place",
          person: undefined,
          value: "Private location",
        }),
      ),
    }).invalid,
    1,
  );
});
test("workflows retain candidates and source failures, enforce budget, and reuse cached collectors", async (t) => {
  let calls = 0;
  const engine = setup(
    t,
    settings({
      network: true,
      enabledAdapters: ["github-profile"],
      limits: { minIntervalMs: 0 },
    }),
    {
      fetcher: async (url) => {
        calls++;
        const login = decodeURIComponent(
          new URL(url).pathname.split("/").at(-1),
        );
        return new Response(
          JSON.stringify({ login, company: "Example", email: null }),
        );
      },
    },
  );
  const first = await engine.workflow({
    workflow: "personas",
    target: "Ana Pérez",
    execute: true,
    maxTargets: 2,
    maxCalls: 1,
  });
  assert.equal(first.calls, 1);
  assert.equal(
    first.steps.some((s) => s.status === "budget_exhausted"),
    true,
  );
  assert.equal(first.username_candidates.length > 2, true);
  assert.equal(engine.store.query({ type: "employee" }).total, 1);
  await engine.workflow({
    workflow: "personas",
    target: "Ana Pérez",
    execute: true,
    maxTargets: 1,
    maxCalls: 1,
  });
  assert.equal(calls, 1);
});
test("MX distinguishes null/no explicit MX without claiming mailbox validity or catch-all", async () => {
  for (const [records, status] of [
    [[{ priority: 0, exchange: "" }], "null_mx"],
    [[{ priority: 10, exchange: "mx.example.net" }], "mx_present"],
    [[], "no_explicit_mx"],
  ]) {
    const resolver = { resolveMx: async () => records, cancel: () => {} };
    const data = JSON.parse(
      await collectMX("example.com", settings(), { resolver }),
    );
    assert.equal(data.status, status);
    assert.equal(data.mailbox, "unknown");
    assert.equal(data.catch_all, "unknown");
  }
});
test("IANA bootstrap selects longest prefix and rejects arbitrary/private provider URLs", () => {
  const data = {
    services: [
      [["0.0.0.0/0"], ["https://127.0.0.1/rdap/"]],
      [["192.0.0.0/8"], ["https://rdap.arin.net/registry/"]],
      [["192.0.2.0/24"], ["https://rdap.db.ripe.net/"]],
    ],
  };
  assert.equal(rdapBase("192.0.2.1", data), "https://rdap.db.ripe.net/");
  assert.throws(() => rdapBase("203.0.113.1", data), /RDAP_PROVIDER_NOT_FOUND/);
  assert.equal(
    rdapBase("2001:db8::1", {
      services: [[["2001:db8::/32"], ["https://rdap.apnic.net/"]]],
    }),
    "https://rdap.apnic.net/",
  );
});
test("passive enrichment of a discovered IP never authorizes active scanning of that IP", async (t) => {
  const engine = setup(
    t,
    settings({
      network: true,
      enabledAdapters: ["rdap", "routing", "naabu"],
      active: true,
      limits: { minIntervalMs: 0 },
    }),
    {
      fetcher: async (url) => {
        if (url.includes("data.iana.org"))
          return new Response(
            '{"services":[[["192.0.2.0/24"],["https://rdap.arin.net/registry/"]]]}',
          );
        if (url.includes("stat.ripe.net"))
          return new Response(
            '{"status":"ok","data":{"prefix":"192.0.2.0/24","asns":[64496]}}',
          );
        return new Response(
          '{"startAddress":"192.0.2.0","endAddress":"192.0.2.255","country":"ZZ","handle":"DEMO"}',
        );
      },
    },
  );
  engine.import({
    adapter: "dnsx",
    data: '{"host":"api.example.com","a":["192.0.2.1"]}',
  });
  assert.equal(
    (await engine.run({ adapter: "rdap", target: "192.0.2.1" })).status,
    "completed",
  );
  assert.equal(
    (await engine.run({ adapter: "routing", target: "192.0.2.1" })).status,
    "completed",
  );
  assert.equal(engine.store.query({ type: "asn" }).total, 1);
  await assert.rejects(
    engine.run({ adapter: "naabu", target: "192.0.2.1" }),
    /OUT_OF_SCOPE/,
  );
  assert.equal(engine.store.query({ type: "place" }).total, 0);
});
test("all secret import routes discard raw values; breach summaries reject password fields", (t) => {
  const engine = setup(t);
  engine.import({
    adapter: "trufflehog",
    data: JSON.stringify({
      DetectorName: "API",
      Raw: "DO_NOT_STORE",
      Redacted: "DO_NOT_STORE",
      Verified: true,
      SourceMetadata: { Data: { Git: { file: "config.txt", line: 7 } } },
    }),
  });
  engine.import({
    adapter: "jsonl",
    data: JSON.stringify({
      type: "secret",
      value: "ALSO_DO_NOT_STORE",
      source: "test",
      confidence: 0.9,
      timestamp,
      evidence: { document: "config.txt", line: 8, rule: "password" },
    }),
  });
  for (const item of engine.store.query({ type: "secret" }).items) {
    assert.equal(item.value.includes("DO_NOT_STORE"), false);
    assert.equal(
      JSON.stringify(engine.store.evidence(item.id)).includes("DO_NOT_STORE"),
      false,
    );
  }
  const summary = {
    email: "contact@example.com",
    provider: "LeakCheck",
    breach: "Demo",
    date: "2020-01-01",
    timestamp,
  };
  assert.equal(
    engine.import({ adapter: "breach-summary", data: JSON.stringify(summary) })
      .inserted,
    1,
  );
  assert.equal(
    engine.import({
      adapter: "breach-summary",
      data: JSON.stringify({ ...summary, password: "NEVER" }),
    }).invalid,
    1,
  );
});
test("external file contracts use bounded argv and clean temporary outputs", async () => {
  let directory;
  const config = settings();
  const sherlock = await collectExtra("sherlock", "aperez", config, {
    runner: async (command, args) => {
      assert.equal(command, "sherlock");
      assert.equal(args.includes("--local"), true);
      directory = args[args.indexOf("--folderoutput") + 1];
      await writeFile(
        join(directory, "aperez.csv"),
        "username,url_user,exists\naperez,https://github.com/aperez,Claimed\n",
      );
      return "";
    },
  });
  assert.equal(sherlock.includes("aperez"), true);
  await assert.rejects(readFile(join(directory, "aperez.csv")));
  const harvester = await collectExtra("theharvester", "example.com", config, {
    runner: async (command, args) => {
      assert.equal(command, "theHarvester");
      await writeFile(
        args[args.indexOf("-f") + 1] + ".json",
        '{"emails":["contact@example.com"]}',
      );
      return "";
    },
  });
  assert.equal(JSON.parse(harvester).emails.length, 1);
});
test("WhatsMyName imports candidate matches and correlation separates company breach evidence", async (t) => {
  const engine = setup(t);
  engine.import({
    adapter: "whatsmyname",
    data: '{"username":"aperez","url":"https://github.com/aperez","status":"found"}',
  });
  assert.equal(
    engine.store.query({ type: "profile" }).items[0].confidence,
    0.4,
  );
  engine.import({
    adapter: "theharvester",
    data: '{"emails":["contact@example.com","other@other.invalid"]}',
  });
  engine.import({
    adapter: "breach-summary",
    data: JSON.stringify([
      {
        email: "contact@example.com",
        provider: "HIBP",
        breach: "A",
        timestamp,
      },
      {
        email: "other@other.invalid",
        provider: "HIBP",
        breach: "B",
        timestamp,
      },
    ]),
  });
  const result = await engine.workflow({
    workflow: "correlacion",
    target: "example.com",
  });
  assert.equal(result.correlation.counts.breach_associations, 1);
  assert.equal(
    result.correlation.conclusions.probable_entry_point,
    "not_established_by_osint",
  );
  assert.equal(result.correlation.professional_coverage.length, 1);
});
