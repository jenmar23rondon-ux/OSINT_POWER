import test from "node:test";
import assert from "node:assert/strict";
import { Engine } from "../src/engine.js";
import { Store } from "../src/store.js";
import { assessEvidence } from "../src/quality.js";
import { planInvestigation } from "../src/planning.js";
import {
  completeEvidence,
  exportEvidence,
  verifyEvidence,
} from "../src/bundles.js";
import { RESULT_SCHEMAS, toolResponse } from "../src/contracts.js";
import { runBenchmark } from "../benchmarks/runner.js";

const setup = (t) => {
  const store = new Store();
  t.after(() => store.close());
  return new Engine({ version: 1, scope: { domains: ["example.com"] } }, store);
};
test("evidence packages are deterministic, paginated, self-contained and detect tampering", (t) => {
  const engine = setup(t);
  const result = engine.import({
    adapter: "subfinder",
    data: "api.example.com\nold.example.com",
  });
  const first = exportEvidence(engine.store, {
    run_id: result.run_id,
    limit: 1,
  });
  assert.deepEqual(
    first,
    exportEvidence(engine.store, { run_id: result.run_id, limit: 1 }),
  );
  assert.equal(first.page.complete, false);
  assert.equal(verifyEvidence(first).complete, false);
  const second = exportEvidence(engine.store, {
    run_id: result.run_id,
    limit: 1,
    cursor: first.page.next_cursor,
  });
  assert.equal(second.page.next_cursor, null);
  assert.equal(second.captures.length, 1);
  assert.notEqual(
    first.captures[0].observation_id,
    second.captures[0].observation_id,
  );
  const complete = completeEvidence(engine.store, result.run_id);
  assert.equal(
    RESULT_SCHEMAS.export_evidence.safeParse(complete).success,
    true,
  );
  assert.equal(verifyEvidence(complete).complete, true);
  assert.equal(complete.captures[0].provenance.configuration_digest.length, 64);
  assert.equal(
    complete.captures[0].provenance.collector_version,
    "external_version_unknown",
  );
  complete.captures[0].payload.value = "tampered.example.com";
  assert.equal(verifyEvidence(complete).code, "INTEGRITY_MISMATCH");
  assert.throws(
    () =>
      exportEvidence(engine.store, {
        run_id: result.run_id,
        cursor: "a".repeat(64) + ":" + "b".repeat(64),
      }),
    /INVALID_BUNDLE_CURSOR/,
  );
});
test("mutable and legacy runs cannot masquerade as immutable evidence packages", (t) => {
  const engine = setup(t);
  const job = engine.jobs.create({
    workflow: "correlation",
    target: "example.com",
  });
  assert.throws(
    () => completeEvidence(engine.store, job.id),
    /USE_IMMUTABLE_SNAPSHOT_ID/,
  );
  const run = engine.store.start("legacy", "example.com");
  assert.throws(() => completeEvidence(engine.store, run), /RUN_STILL_ACTIVE/);
  engine.store.finish(run, "completed", {});
  assert.throws(
    () => completeEvidence(engine.store, run),
    /SNAPSHOT_UNAVAILABLE/,
  );
});
test("MCP separates partial success and deferred collection from execution errors", () => {
  const base = {
    run_id: "fixture",
    status: "partial",
    observations: 1,
    inserted: 1,
    repeated: 0,
    invalid: 1,
    skipped: 0,
    truncated: false,
    next_actions: [],
  };
  const partial = toolResponse("import_findings", base);
  assert.equal(partial.ok, true);
  assert.equal(partial.execution_status, "succeeded");
  assert.equal(partial.collection_status, "partial");
  assert.equal(partial.coverage.complete, false);
  const deferred = toolResponse("collect", {
    run_id: "fixture",
    status: "deferred",
    code: "PROVIDER_COOLDOWN",
    retry_after_ms: 120000,
    next_actions: [],
  });
  assert.equal(deferred.ok, true);
  assert.equal(deferred.retry.retryable, true);
  assert.equal(deferred.retry.retry_after_ms, 120000);
  const invalid = toolResponse("query_findings", { items: "malformed" });
  assert.equal(invalid.ok, false);
  assert.equal(invalid.result.code, "INTERNAL_OUTPUT_VALIDATION");
  assert.equal(
    RESULT_SCHEMAS.query_findings.safeParse({ items: [] }).success,
    false,
  );
});
test("freshness, public-assertion conflicts and identity are separate assessments", () => {
  const asOf = Date.parse("2026-01-01T00:00:00.000Z");
  const observations = [
    {
      type: "profile",
      source: "a",
      timestamp: "2020-01-01T00:00:00.000Z",
      evidence: { public_company: "A" },
    },
    {
      type: "profile",
      source: "b",
      timestamp: "2025-12-31T00:00:00.000Z",
      evidence: { public_company: "B" },
    },
  ];
  const result = assessEvidence(observations, asOf);
  assert.equal(result.identity, "candidate_unverified");
  assert.equal(result.ownership, "not_established");
  assert.equal(result.conflicting_assertions.length, 2);
  assert.equal(result.freshness.stale, 1);
  assert.equal(
    assessEvidence(
      [
        {
          type: "url",
          source: "wayback",
          timestamp: "2001-01-01T00:00:00.000Z",
          evidence: { historical: true },
        },
      ],
      asOf,
    ).existence,
    "historical_record_only",
  );
});
test("planner exposes measured novelty and HTTP cost after real recorded collection samples", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  let i = 0;
  const engine = new Engine(
    {
      version: 1,
      scope: { domains: ["example.com"] },
      network: true,
      enabledAdapters: ["crtsh"],
      limits: { minIntervalMs: 0, cacheTtlSeconds: 0 },
    },
    store,
    {
      fetcher: async () =>
        new Response(
          JSON.stringify([{ id: ++i, name_value: `host${i}.example.com` }]),
        ),
    },
  );
  for (let n = 0; n < 3; n++)
    await engine.run({ adapter: "crtsh", target: "example.com" });
  const plan = await planInvestigation(engine, {
    workflow: "company",
    target: "example.com",
  });
  const source = plan.actions.find((a) => a.arguments.adapter === "crtsh");
  assert.equal(source.source_metrics.sample_runs, 3);
  assert.equal(source.source_metrics.mean_http_requests, 1);
  assert.equal(source.source_metrics.precision, "not_measured");
  assert.equal(
    source.reasons.some((r) => r.includes("workspace novelty")),
    true,
  );
});
test("labeled investigation benchmark meets entity, relationship and semantic regression gates", async () => {
  const report = await runBenchmark();
  assert.equal(report.status, "passed");
  assert.equal(report.cases.length, 35);
  assert.equal(report.metrics.attribution.baseline_v0_4.false_attributions, 0);
  assert.equal(
    report.metrics.attribution.evidence_intelligence.false_attributions,
    0,
  );
  assert.equal(report.metrics.attribution.baseline_v0_4.true_positives, 0);
  assert.equal(
    report.metrics.attribution.evidence_intelligence.recall >
      report.metrics.attribution.baseline_v0_4.recall,
    true,
  );
  assert.equal(report.metrics.entities.false_positives, 0);
  assert.equal(report.metrics.relations.false_positives, 0);
  assert.equal(report.metrics.semantic_failures, 0);
});
