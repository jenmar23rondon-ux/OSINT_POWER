import assert from "node:assert/strict";
import test from "node:test";
import { Engine } from "../src/engine.js";
import {
  correlateOsintResults,
  ExternalOsintImportInput,
} from "../src/external-osint.js";
import { sourceFamily } from "../src/state.js";
import { Store } from "../src/store.js";

test("imports SpiderFoot certificate-name events with scoped provenance and rejects labeled false hits", (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(
    {
      version: 1,
      scope: {
        domains: ["example.com", "example.org"],
        excludeDomains: ["excluded.example.com"],
      },
      network: false,
    },
    store,
    {
      runner: () => assert.fail("Unexpected process"),
      fetcher: () => assert.fail("Unexpected request"),
    },
  );
  const hit = {
    data: "api.example.com",
    event_type: "INTERNET_NAME_UNRESOLVED",
    module: "sfp_crt",
    false_positive: 0,
    last_seen: "2026-11-10 18:00:00",
    scan_target: "example.com",
    source_data: "discard-source-payload",
    scan_name: "discard-scan-name",
  };
  const negatives = [
    { false_positive: 1, data: "fp.example.com" },
    { data: "excluded.example.com" },
    { data: "foreign.example.org" },
    { scan_target: "sub.example.com" },
    { module: "sfp_dnsresolve" },
    { event_type: "EMAILADDR", data: "synthetic@example.com" },
    { data: "path.example.com/private" },
    { last_seen: "2026-02-30 12:00:00" },
  ];
  engine.import({ adapter: "subfinder", data: hit.data });
  const input = ExternalOsintImportInput.parse({
    adapter: "spiderfoot-json",
    source_utc_offset: "-05:00",
    data: JSON.stringify([
      hit,
      ...negatives.map((diff) => ({ ...hit, ...diff })),
    ]),
  });
  const result = engine.import(input);
  assert.equal(result.inserted, 1);
  assert.equal(result.invalid + result.skipped, negatives.length);
  assert.equal(result.coverage_complete, false);
  assert.equal(engine.import(input).inserted, 0);
  const row = store.db
    .prepare("SELECT * FROM observations WHERE source='spiderfoot'")
    .get();
  assert.equal(row.timestamp, "2026-11-10T23:00:00.000Z");
  const evidence = JSON.parse(row.evidence);
  assert.equal(evidence.verification, "certificate_name_only");
  assert.equal(
    sourceFamily("spiderfoot", evidence),
    "certificate_transparency",
  );
  assert.equal(row.evidence.includes("discard"), false);
  const match = correlateOsintResults(store, { run_id: result.run_id });
  assert.equal(match.items[0].value, hit.data);
  assert.equal(match.items[0].imported_observation_id, row.id);
  assert.deepEqual(
    match.items[0].other_observations.map((item) => item.source),
    ["subfinder"],
  );
  assert.throws(
    () => engine.import({ adapter: input.adapter, data: "[]" }),
    /SOURCE_UTC_OFFSET_REQUIRED/,
  );
  assert.equal(engine.import({ ...input, data: "{}" }).status, "failed");
});
