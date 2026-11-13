import assert from "node:assert/strict";
import test from "node:test";
import { Engine } from "../src/engine.js";
import { correlateOsintResults } from "../src/external-osint.js";
import { Store, hash } from "../src/store.js";

const observedAt = "2026-11-10T18:00:00-05:00";
const username = "example-researcher";
const profile = "https://github.com/" + username;
const reported = (site, url, handle = username, status = "Claimed") => ({
  url_user: url,
  status: {
    username: handle,
    site_name: site,
    url,
    status,
    ids: { private: "never-store-this" },
  },
  response_text: "untrusted HTML never-store-this",
});

function workspace(t) {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(
    {
      version: 1,
      scope: {
        domains: ["example.com"],
        usernames: [username],
        people: [{ name: "Alex Rivera", companyDomain: "example.com" }],
      },
      network: false,
      active: false,
    },
    store,
    {
      fetcher: () => assert.fail("Unexpected request"),
      runner: () => assert.fail("Unexpected subprocess"),
    },
  );
  const importReport = (report) =>
    engine.import({
      adapter: "maigret",
      data: JSON.stringify(report),
      observed_at: observedAt,
    });
  return { engine, store, importReport };
}

test("imports a reviewed Maigret v0.6.6 report and measures rejected false hits", (t) => {
  const { engine, store, importReport } = workspace(t);
  const unsupported = [
    ["GitLab", "https://gitlab.com/alex.rivera", "alex.rivera"],
    ["Codeberg", "https://codeberg.org/unapproved-user", "unapproved-user"],
    ["PrivateForum", `https://forum.example/${username}`],
    ["BarePage", "https://github.com/settings"],
    ["Lookalike", `https://github.com.evil.example/${username}`],
    ["Login", `https://user:password@github.com/${username}`],
    ["Unknown", `https://gitlab.com/${username}`, username, "Unknown"],
    ["CustomPort", `https://github.com:8080/${username}`],
    ["EncodedPath", "https://github.com/%65xample-researcher"],
  ];
  const row = reported("GitHub", profile + "?secret=never-store-this#private");
  const data = {
    GitHub: row,
    ...Object.fromEntries(
      unsupported.map((args) => [args[0], reported(...args)]),
    ),
  };
  const result = importReport(data);
  assert.equal(result.inserted, 2);
  assert.equal(result.coverage_complete, false);
  assert.equal(result.invalid + result.skipped, unsupported.length);
  assert.equal(importReport(data).inserted, 0);
  const rows = store.db
    .prepare("SELECT source,timestamp,evidence FROM observations")
    .all();
  assert.ok(rows.every((row) => row.timestamp === "2026-11-10T23:00:00.000Z"));
  assert.ok(
    rows.every((row) => JSON.parse(row.evidence).verification === "candidate"),
  );
  assert.equal(JSON.stringify(rows).includes("never-store-this"), false);
  assert.deepEqual(
    store.query({ type: "profile" }).items.map((item) => item.value),
    [profile],
  );
  assert.equal(
    store.graph().items.some((edge) => edge.relation === "username_match"),
    true,
  );
  assert.deepEqual(engine.providers.health().providers, []);
  assert.throws(
    () => engine.import({ adapter: "maigret", data: "{}" }),
    /OBSERVED_AT_REQUIRED/,
  );
  assert.equal(importReport([]).status, "failed");
});

test("compares exact entity overlap with bounded evidence references", (t) => {
  const { engine, store, importReport } = workspace(t);
  engine.import({
    adapter: "sherlock",
    data: `username,url_user,exists\n${username},${profile},Claimed`,
  });
  const { run_id } = importReport({ GitHub: reported("GitHub", profile) });
  const before = store.db
    .prepare("SELECT COUNT(*) AS n FROM observations")
    .get().n;
  const first = correlateOsintResults(store, { run_id, limit: 1 });
  const second = correlateOsintResults(store, {
    run_id,
    limit: 1,
    cursor: first.next_cursor,
  });
  assert.equal(second.next_cursor, null);
  assert.equal(first.comparison, "exact_entity_overlap");
  const items = [...first.items, ...second.items];
  assert.deepEqual(items.map((item) => item.type).sort(), [
    "profile",
    "username",
  ]);
  assert.ok(
    items.every(
      (item) =>
        item.other_observations.length === 1 &&
        item.other_observations[0].source === "sherlock",
    ),
  );
  assert.ok(
    items.every((item) => item.entity_id === hash([item.type, item.value])),
  );
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM observations").get().n,
    before,
  );
});
