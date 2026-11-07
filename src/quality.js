import { sourceFamily } from "./state.js";

// These dimensions deliberately do not inherit an entity's maximum source score.
export function assessEvidence(
  observations,
  asOf = Date.now(),
  maxAgeMs = 30 * 86400000,
) {
  const current = observations.filter((o) => {
    const age = asOf - Date.parse(o.timestamp);
    return age >= 0 && age <= maxAgeMs;
  });
  const direct = current.some((o) =>
    ["dnsx", "httpx", "naabu", "mx"].includes(o.source),
  );
  const historical =
    observations.length > 0 &&
    observations.every((o) => o.evidence.historical === true);
  const identityRelevant = observations.some((o) =>
    ["profile", "username", "employee"].includes(o.type),
  );
  const assertions = new Map();
  for (const o of observations) {
    const value = o.evidence.public_company;
    if (typeof value === "string" && value.trim()) {
      const assertion = assertions.get(value) ?? {
        predicate: "public_company_claim",
        value,
        supporting_sources: new Set(),
        observed_at: [],
      };
      assertion.supporting_sources.add(o.source);
      assertion.observed_at.push(o.timestamp);
      assertions.set(value, assertion);
    }
  }
  return {
    existence: direct
      ? "recent_direct_tool_record"
      : historical
        ? "historical_record_only"
        : observations.length
          ? "source_asserted"
          : "unknown",
    ownership: "not_established",
    identity: identityRelevant ? "candidate_unverified" : "not_applicable",
    review_status: "unreviewed",
    freshness: {
      window_days: maxAgeMs / 86400000,
      current: current.length,
      stale: observations.filter(
        (o) => asOf - Date.parse(o.timestamp) > maxAgeMs,
      ).length,
      future_dated: observations.filter((o) => Date.parse(o.timestamp) > asOf)
        .length,
    },
    source_families: [
      ...new Set(observations.map((o) => sourceFamily(o.source, o.evidence))),
    ].sort(),
    conflicting_assertions:
      assertions.size > 1
        ? [...assertions.values()].map((a) => ({
            ...a,
            supporting_sources: [...a.supporting_sources].sort(),
            observed_at: a.observed_at.sort(),
            interpretation:
              "Different public company assertions may reflect time changes or ambiguity; review evidence before attribution",
          }))
        : [],
    calibration: "heuristic_not_probability",
  };
}

export function sourceMetrics(store, adapter, target) {
  const runs = store.db
    .prepare(
      `SELECT id,started,finished,summary FROM runs
    WHERE adapter=? AND target=? AND status='completed' AND json_extract(summary,'$.cached')=0
      AND json_extract(summary,'$.entities_inserted') IS NOT NULL
    ORDER BY started DESC,id LIMIT 20`,
    )
    .all(adapter, target);
  if (!runs.length) return { sample_runs: 0, precision: "not_measured" };
  let novel = 0,
    unique = 0,
    requests = 0,
    elapsed = 0;
  for (const run of runs) {
    const summary = JSON.parse(run.summary);
    const rows = store.db
      .prepare("SELECT DISTINCT entity_id FROM run_observations WHERE run_id=?")
      .all(run.id);
    unique += rows.length;
    novel += summary.entities_inserted;
    requests += summary.http_requests ?? 0;
    elapsed += Math.max(0, Date.parse(run.finished) - Date.parse(run.started));
  }
  return {
    sample_runs: runs.length,
    mean_new_entities: novel / runs.length,
    mean_unique_entities: unique / runs.length,
    mean_http_requests: requests / runs.length,
    mean_duration_ms: elapsed / runs.length,
    precision: "not_measured",
    interpretation:
      "Workspace novelty/cost sample; source overlap, order and scope affect yield. Native internal requests are unknown.",
  };
}
