import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
import { Engine } from "../src/engine.js";
import { Store, hash } from "../src/store.js";
import { explainEntity } from "../src/state.js";
import { blockedCandidate, generateLookalikes } from "../src/phishing.js";
import { diffAssets } from "../src/monitor.js";

export async function runBenchmark(
  fixtures = JSON.parse(
    readFileSync(new URL("./cases.json", import.meta.url), "utf8"),
  ),
) {
  const cases = [],
    sourceYield = new Map();
  const started = performance.now();
  for (const fixture of fixtures) {
    const store = new Store();
    let responseData,
      requests = 0;
    const engine = new Engine(
      {
        version: 1,
        scope: {
          domains: ["example.com"],
          excludeDomains: ["excluded.example.com"],
          usernames: ["alex"],
          emails: ["alex@example.com"],
          documents: ["config.txt"],
        },
        network: true,
        enabledAdapters: [
          "crtsh",
          "certspotter",
          "wayback",
          "github-profile",
          "hibp",
        ],
        limits: { minIntervalMs: 0, attempts: 1, cacheTtlSeconds: 0 },
      },
      store,
      {
        fetcher: async () => {
          requests++;
          return new Response(responseData);
        },
      },
    );
    // Use the real HIBP parser without credentials or external access. The fixture
    // collector's key is temporary, deterministic and never a real credential.
    const previousKey = process.env.HIBP_API_KEY;
    process.env.HIBP_API_KEY = "synthetic-benchmark-only";
    let checkFailures = 0;
    try {
      for (const step of fixture.steps) {
        const before = store.query().total,
          beforeRequests = requests;
        responseData =
          typeof step.data === "string" ? step.data : JSON.stringify(step.data);
        const result = step.collect
          ? await engine.run({
              adapter: step.adapter,
              target: step.target ?? "example.com",
            })
          : engine.import({ adapter: step.adapter, data: responseData });
        if (step.status && result.status !== step.status) checkFailures++;
        const metric = sourceYield.get(step.adapter) ?? {
          source: step.adapter,
          steps: 0,
          new_entities: 0,
          http_requests: 0,
        };
        metric.steps++;
        metric.new_entities += store.query().total - before;
        metric.http_requests += requests - beforeRequests;
        sourceYield.set(step.adapter, metric);
      }
      const actualEntities = store.db
        .prepare("SELECT type,value FROM entities")
        .all()
        .map((r) => JSON.stringify([r.type, r.value]));
      const actualRelations = store.db
        .prepare(
          "SELECT a.type AS at,a.value AS av,e.relation,b.type AS bt,b.value AS bv FROM edges e JOIN entities a ON a.id=e.from_id JOIN entities b ON b.id=e.to_id",
        )
        .all()
        .map((r) => JSON.stringify([r.at, r.av, r.relation, r.bt, r.bv]));
      const measure = (actual, gold) => {
        const a = new Set(actual),
          g = new Set(gold.map((v) => JSON.stringify(v)));
        return {
          true_positives: [...a].filter((v) => g.has(v)).length,
          false_positives: [...a].filter((v) => !g.has(v)).length,
          false_negatives: [...g].filter((v) => !a.has(v)).length,
        };
      };
      if (fixture.assessment) {
        const expected = fixture.assessment;
        const assessment = explainEntity(
          store,
          hash([expected.type, expected.value]),
        ).assessment;
        if (
          expected.stale !== undefined &&
          assessment.freshness.stale !== expected.stale
        )
          checkFailures++;
        if (
          expected.conflicting_assertions !== undefined &&
          assessment.conflicting_assertions.length !==
            expected.conflicting_assertions
        )
          checkFailures++;
        if (
          assessment.identity !== expected.identity ||
          assessment.ownership !== "not_established"
        )
          checkFailures++;
      }
      if (fixture.monitor) {
        const spec = fixture.monitor;
        const diff = diffAssets(
          spec.previous,
          spec.current,
          spec.thresholds ?? {},
          spec.coverage ?? {},
          spec.target,
        );
        const alertRules = diff.alerts.map((item) => item.rule).sort();
        const expectedRules = [...(spec.alert_rules ?? [])].sort();
        if (JSON.stringify(alertRules) !== JSON.stringify(expectedRules))
          checkFailures++;
        const actual = {};
        for (const change of diff.changes) {
          actual[change.change] ??= [];
          actual[change.change].push(change.asset_key);
        }
        for (const [kind, keys] of Object.entries(spec.changes ?? {})) {
          const got = [...(actual[kind] ?? [])].sort();
          const want = [...keys].sort();
          if (JSON.stringify(got) !== JSON.stringify(want)) checkFailures++;
          delete actual[kind];
        }
        if (Object.values(actual).some((keys) => keys.length)) checkFailures++;
      }
      if (fixture.lookalike) {
        const spec = fixture.lookalike;
        const options = {
          maxCandidates: spec.maxCandidates ?? 40,
          reject: (name) => blockedCandidate(engine.scope, name),
        };
        const produced = generateLookalikes(spec.protected, options);
        const again = generateLookalikes(spec.protected, options);
        if (JSON.stringify(produced) !== JSON.stringify(again)) checkFailures++;
        const byDomain = new Map(
          produced.candidates.map((candidate) => [candidate.domain, candidate]),
        );
        for (const domain of spec.includes ?? [])
          if (!byDomain.has(domain)) checkFailures++;
        for (const domain of spec.excludes ?? [])
          if (byDomain.has(domain)) checkFailures++;
        for (const [domain, score] of Object.entries(spec.scores ?? {}))
          if (byDomain.get(domain)?.similarity !== score) checkFailures++;
        if (
          produced.candidates.some(
            (candidate) =>
              candidate.similarity <= 0 || candidate.similarity > 0.95,
          )
        )
          checkFailures++;
        if (
          spec.homoglyph &&
          !produced.candidates.some(
            (candidate) =>
              candidate.technique === "homoglyph" &&
              candidate.domain.startsWith("xn--"),
          )
        )
          checkFailures++;
        if (
          produced.candidates.some(
            (candidate) => candidate.domain === spec.protected,
          )
        )
          checkFailures++;
      }
      const entities = measure(actualEntities, fixture.entities),
        relations = measure(actualRelations, fixture.relations);
      cases.push({
        id: fixture.id,
        tags: fixture.tags,
        entities,
        relations,
        semantic_failures: checkFailures,
        http_requests: requests,
        passed:
          !entities.false_positives &&
          !entities.false_negatives &&
          !relations.false_positives &&
          !relations.false_negatives &&
          !checkFailures,
      });
    } finally {
      if (previousKey === undefined) delete process.env.HIBP_API_KEY;
      else process.env.HIBP_API_KEY = previousKey;
      store.close();
    }
  }
  const aggregate = (kind) => {
    const n = cases.reduce(
      (all, c) => ({
        true_positives: all.true_positives + c[kind].true_positives,
        false_positives: all.false_positives + c[kind].false_positives,
        false_negatives: all.false_negatives + c[kind].false_negatives,
      }),
      { true_positives: 0, false_positives: 0, false_negatives: 0 },
    );
    return {
      ...n,
      precision:
        n.true_positives / Math.max(1, n.true_positives + n.false_positives),
      recall:
        n.true_positives / Math.max(1, n.true_positives + n.false_negatives),
    };
  };
  return {
    benchmark: "osint-power-synthetic-v1",
    status: cases.every((c) => c.passed) ? "passed" : "failed",
    cases,
    metrics: {
      entities: aggregate("entities"),
      relations: aggregate("relations"),
      semantic_failures: cases.reduce((n, c) => n + c.semantic_failures, 0),
      http_requests: cases.reduce((n, c) => n + c.http_requests, 0),
      elapsed_ms: Math.round(performance.now() - started),
    },
    source_yield: [...sourceYield.values()].sort((a, b) =>
      a.source.localeCompare(b.source),
    ),
    limitations: [
      "Synthetic fixtures are regression controls, not real-world accuracy estimates.",
      "Source yield is order-dependent. Mock HTTP counts exclude native tools' internal requests.",
      "No external network, real people, credentials or model calls are used.",
    ],
  };
}
if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  const { values } = parseArgs({ options: { output: { type: "string" } } });
  const result = await runBenchmark();
  const content = JSON.stringify(result, null, 2) + "\n";
  if (values.output) writeFileSync(values.output, content, { flag: "wx" });
  process.stdout.write(content);
  if (result.status !== "passed") process.exitCode = 1;
}
