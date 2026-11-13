import assert from "node:assert/strict";
import test from "node:test";
import { toolResponse } from "../src/contracts.js";
import { Engine } from "../src/engine.js";
import { Store } from "../src/store.js";

const names = [
  "a.example.com",
  "b.example.com",
  "c.example.com",
  "*.d.example.com",
  "e.example.com",
  "f.example.com",
  "g.example.com",
];
const irrelevant = [
  "Example Corp",
  "user@example.com",
  "https://example.com/",
  "192.0.2.1",
];
function fixture(t, rows, limit) {
  const store = new Store();
  t.after(() => store.close());
  return new Engine(
    {
      version: 1,
      scope: {
        domains: ["example.com"],
        excludeDomains: ["excluded.example.com"],
      },
      network: true,
      limits: { maxRecords: limit },
    },
    store,
    { fetcher: async () => new Response(JSON.stringify(rows)) },
  );
}

test("crt.sh keeps seven DNS names and ignores four expected non-DNS values", async (t) => {
  const engine = fixture(
    t,
    [
      {
        id: 11,
        name_value: [
          ...names,
          ...irrelevant,
          "excluded.example.com",
          "external.example.net",
        ].join("\r\n"),
      },
    ],
    7,
  );
  const run = await engine.run({ adapter: "crtsh", target: "example.com" });
  assert.equal(run.status, "completed");
  assert.equal(run.observations, 7);
  assert.equal(run.invalid, 0);
  assert.equal(run.skipped, 6);
  assert.equal(run.truncated, false);
  assert.deepEqual(run.crtsh_counts, {
    dns: 7,
    ignored_non_dns: 4,
    out_of_scope: 2,
  });
  assert.equal(
    toolResponse("collect", run).result.crtsh_counts.ignored_non_dns,
    4,
  );
});

test("crt.sh still reports malformed values and DNS records beyond the cap", async (t) => {
  const engine = fixture(
    t,
    [
      { id: 2 },
      { id: 3, name_value: 123 },
      { id: 4, name_value: " \n " },
      {
        id: 5,
        name_value: [
          names[0],
          "bad..example.com",
          "example.com/private",
          names[1],
        ].join("\n"),
      },
    ],
    1,
  );
  const run = await engine.run({ adapter: "crtsh", target: "example.com" });
  assert.equal(run.status, "partial");
  assert.equal(run.invalid, 5);
  assert.equal(run.observations, 1);
  assert.equal(run.truncated, true);
  assert.equal(run.crtsh_counts.dns, 2);
});
