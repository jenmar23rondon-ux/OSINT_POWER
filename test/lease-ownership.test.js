import test from "node:test";
import assert from "node:assert/strict";
import { Engine } from "../src/engine.js";
import { Store } from "../src/store.js";

test("a worker losing ownership cannot overwrite its successor or seal a snapshot", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  let started;
  const ready = new Promise((resolve) => (started = resolve));
  const engine = new Engine(
    {
      version: 1,
      scope: { domains: ["example.com"] },
      network: true,
      enabledAdapters: ["crtsh"],
      limits: { minIntervalMs: 0 },
    },
    store,
    {
      fetcher: async (_url, options) =>
        new Promise((_resolve, reject) => {
          started();
          options.signal.addEventListener(
            "abort",
            () => reject(options.signal.reason),
            { once: true },
          );
        }),
    },
  );
  const job = engine.jobs.create({
    workflow: "company",
    target: "example.com",
  });
  const active = engine.resume({ id: job.id });
  await ready;
  store.db
    .prepare("UPDATE jobs SET owner='successor',lease_until=? WHERE id=?")
    .run(Date.now() + 15000, job.id);
  const result = await active;
  assert.equal(result.code, "JOB_LEASE_LOST");
  assert.equal(result.snapshot_id, undefined);
  assert.equal(
    store.db.prepare("SELECT owner FROM jobs WHERE id=?").get(job.id).owner,
    "successor",
  );
  assert.equal(
    store.db
      .prepare(
        "SELECT COUNT(*) AS n FROM run_sources WHERE run_id=? AND collector='crtsh'",
      )
      .get(job.id).n,
    0,
  );
});
