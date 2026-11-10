import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
import { Engine } from "../src/engine.js";
import { Store, hash } from "../src/store.js";
import { explainEntity } from "../src/state.js";
import { assessAssets } from "../src/evidence-intelligence.js";
import { blockedCandidate, generateLookalikes } from "../src/phishing.js";
import { diffAssets } from "../src/monitor.js";
import { createHypothesis, evaluateHypothesis } from "../src/cases.js";
import { recordDecision } from "../src/review.js";
import { exportStix } from "../src/stix.js";
import { investigationGraph } from "../src/graph-export.js";

const CATEGORIES = {
  "deduplicated-domains": "duplicates",
  "scope-boundaries": "out-of-scope",
  "idn-normalization": "normalization",
  "overlapping-ct-sources": "duplicate-sources",
  "wildcard-certificates": "scope",
  "historical-url": "historical",
  "live-url": "direct-observation",
  "shared-infrastructure": "shared-infrastructure",
  "username-collision": "name-collision",
  "unknown-account": "identity",
  "profile-mismatch": "identity",
  "public-profile": "identity",
  "breach-is-not-password-validity": "secret-leak",
  "secret-reference-only": "secret-leak",
  "invalid-calendar-date": "invalid-input",
  "stale-evidence": "stale-conflict",
  "conflicting-profile-assertions": "conflict",
  "lookalike-generation": "lookalike",
  "monitor-diff-significance": "monitor",
  "independent-org-attribution": "attribution",
  "independent-technology-attribution": "attribution",
  "same-run-sources-count-once": "duplicate-sources",
  "duplicate-upstream-counts-once": "duplicate-sources",
  "mirrored-source-counts-once": "mirrored-sources",
  "shared-ip-not-ownership": "shared-infrastructure",
  "cdn-not-ownership": "shared-cdn",
  "hosting-asn-not-ownership": "shared-asn",
  "certificate-not-ownership": "attribution",
  "historical-archive-not-active": "historical",
  "historical-conflicts-with-recent": "stale-conflict",
  "recent-dns-contradiction": "stale-conflict",
  "foreign-org-contradiction": "conflict",
  "shared-handle-stays-candidate": "name-collision",
  "inferred-technology-not-verified": "attribution",
  "public-company-text-not-ownership": "hypothesis-trap",
  "hypothesis-out-of-scope-entity": "out-of-scope",
};

export async function runBenchmark(
  fixtures = JSON.parse(
    readFileSync(new URL("./cases.json", import.meta.url), "utf8"),
  ),
) {
  const cases = [],
    sourceYield = new Map();
  const hypothesisScore = {
    labeled: 0,
    true_positives: 0,
    false_positives: 0,
    false_negatives: 0,
    false_confirmations: 0,
    weakened_expected: 0,
    weakened_matches: 0,
    adversarial: 0,
    adversarial_passed: 0,
    scope_rejections: 0,
  };
  const attribution = {
    baseline_v0_4: {
      labeled: 0,
      true_positives: 0,
      false_positives: 0,
      false_negatives: 0,
      false_attributions: 0,
    },
    evidence_intelligence: {
      labeled: 0,
      true_positives: 0,
      false_positives: 0,
      false_negatives: 0,
      false_attributions: 0,
    },
  };
  const scopeScore = { attempts: 0, blocked: 0 };
  const exportScore = {
    compared: 0,
    mismatches: 0,
    secret_traps: 0,
    secret_leaks: 0,
  };
  const categories = new Map();
  const blank = () => ({
    true_positives: 0,
    false_positives: 0,
    false_negatives: 0,
  });
  const categoryBucket = (name) => {
    if (!categories.has(name))
      categories.set(name, {
        cases: 0,
        entities: blank(),
        relations: blank(),
        false_attributions: 0,
        scope_attempts: 0,
        scope_blocked: 0,
      });
    return categories.get(name);
  };
  const started = performance.now();
  for (const fixture of fixtures) {
    const categoryName = fixture.category ?? CATEGORIES[fixture.id] ?? "other";
    const categoryScore = categoryBucket(categoryName);
    categoryScore.cases++;
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
      if (fixture.intelligence) {
        const spec = fixture.intelligence;
        const page = assessAssets(
          store,
          engine.scope,
          {
            network: engine.config.network,
            active: engine.config.active,
            enabledAdapters: engine.config.enabledAdapters,
          },
          { limit: 100 },
          { asOf: spec.as_of },
        );
        const labeled = spec.assets ?? [];
        const verifiedGold = new Set(
          labeled
            .filter((asset) => asset.ownership === "verified")
            .map((asset) => `${asset.type}:${asset.value}`),
        );
        for (const item of page.items) {
          if (item.next_action.executes !== false) checkFailures++;
          if (
            item.ownership.status === "verified" &&
            !verifiedGold.has(`${item.type}:${item.value}`)
          )
            checkFailures++;
        }
        if (
          spec.confirmed_links !== undefined &&
          page.identity_resolution.confirmed_count !== spec.confirmed_links
        )
          checkFailures++;
        if (
          spec.candidate_links_min !== undefined &&
          page.identity_resolution.candidate_count < spec.candidate_links_min
        )
          checkFailures++;
        const expectAsset = (actual, wanted) => {
          if (!actual) return false;
          if (wanted.ownership && actual.ownership.status !== wanted.ownership)
            return false;
          if (wanted.basis && actual.ownership.basis !== wanted.basis)
            return false;
          if (
            wanted.independent_sources !== undefined &&
            actual.ownership.independent_sources !== wanted.independent_sources
          )
            return false;
          if (
            wanted.historical &&
            actual.historical_existence.status !== wanted.historical
          )
            return false;
          if (
            wanted.activity &&
            actual.current_activity.status !== wanted.activity
          )
            return false;
          if (
            wanted.independent_groups !== undefined &&
            actual.source_independence.independent_groups !==
              wanted.independent_groups
          )
            return false;
          if (
            wanted.conflicts_min !== undefined &&
            actual.conflicts.length < wanted.conflicts_min
          )
            return false;
          if (
            wanted.next_action &&
            actual.next_action.action !== wanted.next_action
          )
            return false;
          return true;
        };
        const score = (bucket, predicted, goldVerified, recordCategory) => {
          bucket.labeled++;
          if (predicted && goldVerified) bucket.true_positives++;
          else if (predicted && !goldVerified) {
            bucket.false_positives++;
            bucket.false_attributions++;
            if (recordCategory) categoryScore.false_attributions++;
          } else if (!predicted && goldVerified) bucket.false_negatives++;
        };
        for (const wanted of labeled) {
          const actual = page.items.find(
            (item) => item.type === wanted.type && item.value === wanted.value,
          );
          if (!expectAsset(actual, wanted)) checkFailures++;
          const goldVerified = wanted.ownership === "verified";
          score(
            attribution.evidence_intelligence,
            actual?.ownership.status === "verified",
            goldVerified,
            true,
          );
          let legacyVerified = false;
          try {
            legacyVerified =
              explainEntity(store, hash([wanted.type, wanted.value])).assessment
                .ownership === "verified";
          } catch {
            legacyVerified = false;
          }
          score(attribution.baseline_v0_4, legacyVerified, goldVerified);
        }
      }
      const hypothesisSpecs = [
        ...(fixture.hypothesis ? [fixture.hypothesis] : []),
        ...(fixture.hypotheses ?? []),
      ];
      for (const spec of hypothesisSpecs) {
        const before = checkFailures;
        if (spec.adversarial) hypothesisScore.adversarial++;
        if (spec.inject) store.ingest(spec.inject);
        const entityIds = (spec.entities ?? []).map(([type, value]) =>
          hash([type, value]),
        );
        let created = null;
        try {
          created = createHypothesis(store, engine.scope, {
            statement: spec.statement,
            claim: spec.claim,
            entity_ids: entityIds,
          });
        } catch (error) {
          if (spec.error && error.message === spec.error) {
            if (spec.error === "OUT_OF_SCOPE") {
              hypothesisScore.scope_rejections++;
              scopeScore.attempts++;
              scopeScore.blocked++;
              categoryScore.scope_attempts++;
              categoryScore.scope_blocked++;
            }
          } else checkFailures++;
          created = null;
        }
        if (spec.error && created) checkFailures++;
        if (created && !spec.error) {
          if (spec.record_accept)
            recordDecision(store, {
              subject_kind: "entity",
              subject_id: entityIds[0],
              decision: "accept",
              reason:
                "Benchmark analyst accept does not confirm the hypothesis.",
              analyst_id: "analyst-1",
            });
          const evaluation = evaluateHypothesis(
            store,
            engine.scope,
            {
              network: engine.config.network,
              active: engine.config.active,
              enabledAdapters: engine.config.enabledAdapters,
            },
            { id: created.hypothesis.id },
            { asOf: spec.as_of },
          );
          if (evaluation.finding !== false) checkFailures++;
          if (
            evaluation.executes !== false ||
            evaluation.network !== false ||
            evaluation.collection !== false
          )
            checkFailures++;
          if (evaluation.next_steps.some((item) => item.executes !== false))
            checkFailures++;
          if (
            evaluation.next_steps.some(
              (item) => item.requires_gate && item.within_gates !== false,
            )
          )
            checkFailures++;
          if (
            spec.assessed_status &&
            evaluation.assessed_status !== spec.assessed_status
          )
            checkFailures++;
          if (
            spec.confirmed !== undefined &&
            evaluation.confirmed !== spec.confirmed
          )
            checkFailures++;
          if (evaluation.confirmed && !spec.confirmed)
            hypothesisScore.false_confirmations++;
          if (
            spec.supporting_min !== undefined &&
            evaluation.supporting.length < spec.supporting_min
          )
            checkFailures++;
          if (
            spec.contradicting_min !== undefined &&
            evaluation.contradicting.length < spec.contradicting_min
          )
            checkFailures++;
          if (
            spec.missing_min !== undefined &&
            evaluation.missing.length < spec.missing_min
          )
            checkFailures++;
          if (
            spec.requires_gate &&
            !evaluation.next_steps.some(
              (item) =>
                item.requires_gate === spec.requires_gate &&
                item.within_gates === false &&
                item.executes === false,
            )
          )
            checkFailures++;
          if (evaluation.stored_status === "analyst-confirmed") checkFailures++;
          const predicted =
            evaluation.assessed_status === "supported-pending-review";
          const gold = spec.support === true;
          hypothesisScore.labeled++;
          if (predicted && gold) hypothesisScore.true_positives++;
          else if (predicted && !gold) {
            hypothesisScore.false_positives++;
          } else if (!predicted && gold) hypothesisScore.false_negatives++;
          if (spec.assessed_status === "weakened") {
            hypothesisScore.weakened_expected++;
            if (evaluation.assessed_status === "weakened")
              hypothesisScore.weakened_matches++;
          }
        }
        if (spec.adversarial && checkFailures === before)
          hypothesisScore.adversarial_passed++;
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
      const entities = measure(actualEntities, fixture.entities),
        relations = measure(actualRelations, fixture.relations);
      for (const [target, score] of [
        [categoryScore.entities, entities],
        [categoryScore.relations, relations],
      ]) {
        target.true_positives += score.true_positives;
        target.false_positives += score.false_positives;
        target.false_negatives += score.false_negatives;
      }
      const present = new Set(actualEntities);
      for (const item of fixture.scope_bait ?? []) {
        scopeScore.attempts++;
        categoryScore.scope_attempts++;
        if (!present.has(JSON.stringify(item))) {
          scopeScore.blocked++;
          categoryScore.scope_blocked++;
        } else checkFailures++;
      }
      const mismatchesBefore = exportScore.mismatches;
      const leaksBefore = exportScore.secret_leaks;
      const exportBlobs = [];
      try {
        const stixA = JSON.stringify(exportStix(store, engine.scope, {}));
        const stixB = JSON.stringify(exportStix(store, engine.scope, {}));
        exportScore.compared++;
        if (stixA !== stixB) exportScore.mismatches++;
        exportBlobs.push(stixA);
        const gates = {
          network: engine.config.network === true,
          active: engine.config.active === true,
          enabledAdapters: engine.config.enabledAdapters ?? [],
        };
        for (const run of store.db
          .prepare("SELECT id FROM runs ORDER BY id")
          .all()) {
          const first = investigationGraph(store, engine.scope, gates, {
            investigation: run.id,
            format: "html",
          });
          const second = investigationGraph(store, engine.scope, gates, {
            investigation: run.id,
            format: "html",
          });
          exportScore.compared += 2;
          if (JSON.stringify(first.graph) !== JSON.stringify(second.graph))
            exportScore.mismatches++;
          if (first.html !== second.html) exportScore.mismatches++;
          if (
            first.graph.edges.some(
              (edge) =>
                edge.kind === "candidate-link" &&
                (edge.confirmed || edge.status !== "candidate"),
            ) ||
            first.graph.nodes.some(
              (node) => node.status === "candidate" && node.confirmed,
            )
          )
            exportScore.mismatches++;
          exportBlobs.push(JSON.stringify(first.graph), first.html ?? "");
        }
      } catch {
        exportScore.mismatches++;
      }
      for (const secret of fixture.secrets ?? []) {
        exportScore.secret_traps++;
        if (exportBlobs.some((blob) => blob.includes(secret)))
          exportScore.secret_leaks++;
      }
      if (
        exportScore.mismatches !== mismatchesBefore ||
        exportScore.secret_leaks !== leaksBefore
      )
        checkFailures++;
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
  const rate = (score) => ({
    ...score,
    precision:
      score.true_positives /
      Math.max(1, score.true_positives + score.false_positives),
    recall:
      score.true_positives /
      Math.max(1, score.true_positives + score.false_negatives),
  });
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
  const labeledRate = (score) => {
    const labeled =
      score.true_positives + score.false_positives + score.false_negatives;
    return {
      ...score,
      precision: labeled
        ? score.true_positives /
          Math.max(1, score.true_positives + score.false_positives)
        : null,
      recall: labeled
        ? score.true_positives /
          Math.max(1, score.true_positives + score.false_negatives)
        : null,
    };
  };
  const scope = {
    attempts: scopeScore.attempts,
    blocked: scopeScore.blocked,
    rate:
      scopeScore.attempts === 0 ? 1 : scopeScore.blocked / scopeScore.attempts,
  };
  const exports = {
    compared: exportScore.compared,
    mismatches: exportScore.mismatches,
    reproducible: exportScore.mismatches === 0 && exportScore.compared > 0,
    secret_traps: exportScore.secret_traps,
    secret_leaks: exportScore.secret_leaks,
  };
  const categoryReport = Object.fromEntries(
    [...categories.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([name, score]) => [
        name,
        {
          cases: score.cases,
          entities: labeledRate(score.entities),
          relations: labeledRate(score.relations),
          false_attributions: score.false_attributions,
          scope_attempts: score.scope_attempts,
          scope_blocked: score.scope_blocked,
        },
      ]),
  );
  return {
    benchmark: "osint-power-synthetic-v1",
    status:
      cases.every((c) => c.passed) &&
      scope.rate === 1 &&
      exports.reproducible &&
      exports.secret_leaks === 0
        ? "passed"
        : "failed",
    cases,
    metrics: {
      entities: aggregate("entities"),
      relations: aggregate("relations"),
      semantic_failures: cases.reduce((n, c) => n + c.semantic_failures, 0),
      http_requests: cases.reduce((n, c) => n + c.http_requests, 0),
      elapsed_ms: Math.round(performance.now() - started),
      attribution: {
        baseline_v0_4: rate(attribution.baseline_v0_4),
        evidence_intelligence: rate(attribution.evidence_intelligence),
      },
      hypothesis: rate(hypothesisScore),
      categories: categoryReport,
      scope,
      exports,
    },
    source_yield: [...sourceYield.values()].sort((a, b) =>
      a.source.localeCompare(b.source),
    ),
    limitations: [
      "Synthetic fixtures are regression controls, not real-world accuracy estimates.",
      "Attribution scores compare verified organization-domain claims. v0.4 explain_entity never verifies ownership. Shared infrastructure and candidate identity links are not true positives.",
      "Hypothesis scores compare assessed support with the fixture label. supported-pending-review is not analyst-confirmed. A false confirmation is an evaluation that reports confirmed without that label. Adversarial cases include shared infrastructure, shared handles, contradictions, and an out-of-scope attachment.",
      "Per-category precision and recall use the same entity and relationship labels, grouped by category. A category with no positive or negative labels has null precision and recall.",
      "Scope-block rate is blocked out-of-scope import bait plus rejected out-of-scope hypothesis attachments, divided by those attempts. It is a gate on this fixture, not a field measurement.",
      "Export reproducibility is byte-identical repeated STIX and investigation-graph exports of the same stored rows. Secret-leak count is planted discarded secret strings that reappear in those exports.",
      "This corpus is synthetic and has not been independently reviewed by humans. A perfect score is not a real-world accuracy estimate.",
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
