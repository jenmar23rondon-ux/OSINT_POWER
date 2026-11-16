import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Engine } from "../src/engine.js";
import { Store } from "../src/store.js";

const username = "example-researcher";

function workspace(t, extra = {}) {
  const store = new Store();
  t.after(() => store.close());
  return new Engine(
    {
      version: 1,
      scope: {
        domains: ["example.com"],
        emails: ["alex@example.com"],
        usernames: [username],
      },
      network: false,
      ...extra,
    },
    store,
  );
}

test("holehe CSV stores registered sites and keeps rate limits and errors as gaps", (t) => {
  const engine = workspace(t);
  const data = readFileSync(
    fileURLToPath(new URL("../examples/holehe.csv", import.meta.url)),
    "utf8",
  );
  const result = engine.import({ adapter: "holehe", data });
  assert.equal(result.status, "completed");
  assert.equal(result.inserted, 1);
  assert.equal(result.coverage_gaps.length, 2);
  assert.deepEqual(result.coverage_gaps.map((gap) => gap.reason).sort(), [
    "error",
    "rate_limited",
  ]);
  const profiles = engine.store.query({ type: "profile" }).items;
  assert.deepEqual(
    profiles.map((item) => item.value),
    ["https://twitter.com/"],
  );
  const evidence = engine.store.evidence(profiles[0].id).items[0].evidence;
  assert.equal(evidence.site_name, "twitter");
  assert.equal(evidence.status, "registered");
  assert.equal(evidence.account, "alex@example.com");
  const stored = JSON.stringify(engine.store.evidence(profiles[0].id));
  assert.equal(stored.includes("secret-phone"), false);
  assert.equal(stored.includes("secret-recovery"), false);
  assert.equal(stored.includes("secret-other"), false);
  assert.equal(
    engine.store
      .query({ type: "profile" })
      .items.some((item) => item.value.includes("github.com")),
    false,
  );
});

test("holehe uses --target when the CSV has no email column", (t) => {
  const engine = workspace(t);
  const result = engine.import({
    adapter: "holehe",
    target: "alex@example.com",
    data: "name,domain,rateLimit,exists,error\nsteam,steamcommunity.com,False,True,False\n",
  });
  assert.equal(result.status, "completed");
  assert.equal(
    engine.store.query({ type: "profile" }).items[0].value,
    "https://steamcommunity.com/",
  );
});

test("Social Analyzer JSON stores found profiles and gaps for unknown or failed checks", (t) => {
  const engine = workspace(t);
  const data = readFileSync(
    fileURLToPath(new URL("../examples/social-analyzer.json", import.meta.url)),
    "utf8",
  );
  const result = engine.import({ adapter: "social-analyzer", data });
  assert.equal(result.status, "completed");
  assert.equal(result.coverage_gaps.length, 2);
  assert.deepEqual(result.coverage_gaps.map((gap) => gap.reason).sort(), [
    "failed",
    "unknown",
  ]);
  const profiles = engine.store.query({ type: "profile" }).items;
  assert.deepEqual(
    profiles.map((item) => item.value),
    ["https://www.tiktok.com/@example-researcher"],
  );
  const stored = JSON.stringify(engine.store.evidence(profiles[0].id));
  assert.equal(stored.includes("ref=secret"), false);
  assert.equal(stored.includes("do not treat"), false);
  assert.equal(engine.store.query({ type: "username" }).total, 1);
});
