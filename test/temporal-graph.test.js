import test from "node:test";
import assert from "node:assert/strict";
import { Engine } from "../src/engine.js";
import { Store } from "../src/store.js";
import { mirrorRun } from "../src/state.js";
import { temporalGraph } from "../src/temporal-graph.js";

const early = "2026-09-07T15:00:00.000Z";
const middle = "2026-09-17T15:00:00.000Z";
const late = "2026-10-03T15:00:00.000Z";
const host = "api.example.com";
const ip = "192.0.2.10";
const filters = {
  host,
  since: "2026-09-01T00:00:00Z",
  until: "2026-10-01T00:00:00Z",
  as_of: "2026-09-30T23:59:59Z",
};

function workspace(t) {
  const store = new Store();
  t.after(() => store.close());
  const { scope } = new Engine(
    {
      version: 1,
      scope: { domains: ["example.com"], excludeDomains: ["skip.example.com"] },
    },
    store,
  );
  return { store, scope };
}

function captureDns(
  store,
  {
    hostname = host,
    address = ip,
    observed = early,
    collected = observed,
    finished = collected,
    status = "completed",
    collector = "import:dnsx",
    cached = false,
  } = {},
) {
  const runId = store.start(collector, "fixture");
  store.ingest(
    [
      {
        type: "ip",
        value: address,
        source: "dnsx",
        timestamp: observed,
        confidence: 0.85,
        evidence: { host: hostname },
      },
    ],
    { runId, collector, target: hostname, collected_at: collected, cached },
  );
  if (status !== "running") {
    store.finish(runId, status, {});
    store.db
      .prepare("UPDATE runs SET finished=? WHERE id=?")
      .run(finished, runId);
  }
  return runId;
}

test("an as-of query uses original snapshots and excludes evidence learned later", (t) => {
  const { store, scope } = workspace(t);
  const first = captureDns(store, { finished: middle });
  const lateImport = captureDns(store, {
    address: "192.0.2.20",
    collected: late,
  });
  captureDns(store, { address: "192.0.2.30", observed: late });
  captureDns(store, { address: "192.0.2.40", status: "running" });
  captureDns(store, { address: "192.0.2.50", status: "failed" });
  captureDns(store, { address: "192.0.2.60", collector: "import:jsonl" });
  captureDns(store, { cached: true });
  const mirror = store.start("import:dnsx", "fixture");
  mirrorRun(store, first, mirror);
  store.finish(mirror, "completed", {});
  assert.deepEqual(
    temporalGraph(store, scope, { ...filters, as_of: early }).items,
    [],
  );
  const past = temporalGraph(store, scope, filters);
  assert.deepEqual(
    past.items.map((item) => item.run_id),
    [first],
  );
  assert.equal(past.items[0].observed_at, early);
  assert.equal(past.items[0].collected_at, early);
  assert.equal(past.items[0].known_at, middle);
  assert.deepEqual(
    temporalGraph(store, scope, { ...filters, as_of: late }).items.map(
      (item) => item.run_id,
    ),
    [first, lateImport],
  );
});

test("IP history filters workspace scope and paginates observations with the same timestamp", (t) => {
  const { store, scope } = workspace(t);
  captureDns(store);
  captureDns(store, { hostname: "cdn.example.com", status: "partial" });
  captureDns(store, { hostname: "foo.skip.example.com" });
  captureDns(store, { hostname: "notexample.com" });
  captureDns(store, { hostname: "example.com.invalid" });
  const reverse = { ...filters, host: undefined, ip, limit: 1 };
  const first = temporalGraph(store, scope, reverse);
  const second = temporalGraph(store, scope, {
    ...reverse,
    cursor: first.next_cursor,
  });
  assert.deepEqual(
    [...first.items, ...second.items].map((item) => item.from),
    [host, "cdn.example.com"],
  );
  assert.equal(second.next_cursor, null);
  assert.throws(
    () =>
      temporalGraph(store, scope, {
        ...reverse,
        ip: "192.0.2.99",
        cursor: first.next_cursor,
      }),
    /INVALID_TEMPORAL_CURSOR/,
  );
  assert.throws(
    () => temporalGraph(store, scope, { ...filters, host: "skip.example.com" }),
    /OUT_OF_SCOPE/,
  );
  assert.throws(
    () => temporalGraph(store, scope, { ...filters, until: filters.since }),
    /INVALID_TIME_RANGE/,
  );
});

test("observation windows include their start and exclude their end", (t) => {
  const { store, scope } = workspace(t);
  captureDns(store, { observed: early, address: "2001:db8::10" });
  captureDns(store, { observed: middle, address: "2001:db8::11" });
  const page = temporalGraph(store, scope, {
    ...filters,
    host: "API.EXAMPLE.COM.",
    since: "2026-09-07T10:00:00-05:00",
    until: middle,
    ip: "2001:0db8:0:0:0:0:0:10",
  });
  assert.equal(page.since, early);
  assert.deepEqual(
    page.items.map((item) => item.to),
    ["2001:db8::10"],
  );
  assert.equal(
    temporalGraph(store, scope, {
      ...filters,
      since: early,
      until: middle,
    }).items.length,
    1,
  );
});

test("archive and HTTP observations use distinct relationship labels", (t) => {
  const { store, scope } = workspace(t);
  const url = `https://${host}/`;
  for (const collector of ["import:wayback", "import:httpx"]) {
    const runId = store.start(collector, "fixture");
    store.ingest(
      [
        {
          type: "url",
          value: url,
          source: collector.split(":")[1],
          timestamp: early,
          confidence: 0.7,
          evidence: { host },
        },
      ],
      { runId, collector, target: host, collected_at: middle },
    );
    store.finish(runId, "completed", {});
    store.db
      .prepare("UPDATE runs SET finished=? WHERE id=?")
      .run(middle, runId);
  }
  const items = temporalGraph(store, scope, filters).items;
  assert.deepEqual(
    items.map((item) => item.relation),
    ["historically_served", "serves"],
  );
  assert.deepEqual(
    items.map((item) => item.source_family),
    ["web_archive", "direct_observation"],
  );
  assert.equal(temporalGraph(store, scope, { ...filters, ip }).items.length, 0);
});
