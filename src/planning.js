import { WorkflowInput } from "./schema.js";
import { runWorkflow } from "./workflows.js";
import { ADAPTERS } from "./adapters.js";
import { hash } from "./store.js";
import { sourceMetrics } from "./quality.js";
import { z } from "zod";

export const ReviewBudget = z.number().int().min(1).max(20);
const reviewAction = z.enum([
  "compare-conflicting-evidence",
  "inspect-evidence-gap",
  "check-supporting-evidence",
  "reassess-after-review",
  "request-analyst-disposition",
]);
const reviewStep = z
  .object({
    id: z.string(),
    hypothesis_id: z.uuid(),
    action: reviewAction,
    reason: z.string(),
    evidence_ids: z.array(z.string().regex(/^[a-f0-9]{64}$/)).max(40),
    depends_on: z.string().nullable(),
  })
  .strict();
export const CaseReviewPlan = z
  .object({
    budget: ReviewBudget,
    steps: z.array(reviewStep).max(20),
    deferred_steps: z.number().int().nonnegative(),
  })
  .strict();

function reviewSteps(evaluation) {
  const id = evaluation.hypothesis_id;
  const step = (action, reason, evidence = [], dependsOn = null) => ({
    id: `${id}/${action}`,
    hypothesis_id: id,
    action,
    reason,
    evidence_ids: [
      ...new Set(evidence.map((item) => item.evidence_id).filter(Boolean)),
    ]
      .sort()
      .slice(0, 40),
    depends_on: dependsOn,
  });
  if (evaluation.contradicting.length) {
    const compare = step(
      "compare-conflicting-evidence",
      "Compare the conflicting records and their dates before reviewing the claim.",
      [
        ...evaluation.contradicting.slice(0, 20),
        ...evaluation.supporting.slice(0, 20),
      ],
    );
    return [
      compare,
      step(
        "reassess-after-review",
        "Refresh the assessment after the analyst reviews the disagreement.",
        [],
        compare.id,
      ),
    ];
  }
  if (evaluation.assessed_status === "supported-pending-review") {
    const support = step(
      "check-supporting-evidence",
      "Review whether the cited records support the claim and whether their sources overlap.",
      evaluation.supporting,
    );
    return [
      support,
      step(
        "request-analyst-disposition",
        "Ask the analyst to decide whether to close the hypothesis or request more evidence.",
        [],
        support.id,
      ),
    ];
  }
  const gap = step(
    "inspect-evidence-gap",
    evaluation.missing[0]?.reason ??
      "Check the case records for evidence that directly supports the claim.",
    evaluation.supporting,
  );
  return [
    gap,
    step(
      "reassess-after-review",
      "Refresh the assessment after reviewing the gap or adding reviewed evidence.",
      [],
      gap.id,
    ),
  ];
}

export function planCaseReview(evaluations, budget) {
  const open = evaluations.filter(
    ({ hypothesis }) =>
      hypothesis.status !== "rejected" &&
      hypothesis.status !== "analyst-confirmed",
  );
  const priority = { weakened: 0, open: 1, "supported-pending-review": 2 };
  open.sort(
    (left, right) =>
      priority[left.assessed_status] - priority[right.assessed_status] ||
      left.hypothesis_id.localeCompare(right.hypothesis_id),
  );
  const paths = open.map(reviewSteps);
  const steps = [
    ...paths.map(([first]) => first),
    ...paths.map(([, second]) => second),
  ];
  return {
    budget,
    steps: steps.slice(0, budget),
    deferred_steps: Math.max(0, steps.length - budget),
  };
}

const PROVIDERS = {
  crtsh: "crt.sh",
  certspotter: "api.certspotter.com",
  wayback: "web.archive.org",
  subfinder: "binary:subfinder",
  amass: "binary:amass",
  theharvester: "binary:theharvester",
  sherlock: "binary:sherlock",
  dnsx: "binary:dnsx",
  httpx: "binary:httpx",
  naabu: "binary:naabu",
  mx: "dns:system",
  hibp: "haveibeenpwned.com",
  "github-profile": "api.github.com",
  routing: "stat.ripe.net",
  rdap: "data.iana.org",
};
export async function planInvestigation(engine, input) {
  const request = WorkflowInput.parse({ ...input, execute: false });
  const plan = await runWorkflow(engine, request);
  const health = new Map(
    engine.providers.health().providers.map((p) => [p.provider, p]),
  );
  const candidates = [];
  for (const step of plan.steps.filter((s) => s.adapter)) {
    const provider = health.get(PROVIDERS[step.adapter]);
    let eligibility = step.status;
    try {
      if (!(
        ["rdap", "routing"].includes(step.adapter) &&
        engine.store.ipHost(step.target, engine.scope)
      ))
        engine.scope.target(step.adapter, step.target);
    } catch {
      eligibility = "out_of_scope_or_requires_discovered_context";
    }
    if (provider && ["cooldown", "quota_exhausted"].includes(provider.status))
      eligibility = provider.status;
    const cached = engine.store.cached(
      hash(["v0.4", step.adapter, step.target, engine.config]),
    );
    const prior = engine.store.db
      .prepare(
        "SELECT status,finished FROM runs WHERE adapter=? AND target=? ORDER BY started DESC LIMIT 1",
      )
      .get(step.adapter, step.target);
    const passive = ADAPTERS[step.adapter].mode === "passive";
    const metrics = sourceMetrics(engine.store, step.adapter, step.target);
    const reasons = [];
    let score = passive ? 30 : 10;
    reasons.push(
      passive
        ? "passive source preference"
        : "confirmation requires active mode",
    );
    if (!prior) {
      score += 30;
      reasons.push("no previous collection for this source/target");
    } else if (prior.status === "failed") {
      score -= 20;
      reasons.push("previous failure reduces immediate value");
    }
    if (
      prior?.finished &&
      Date.now() - Date.parse(prior.finished) >
        Math.max(3600000, engine.config.limits.cacheTtlSeconds * 1000)
    ) {
      score += 20;
      reasons.push("previous collection is stale");
    }
    if (cached) {
      score -= 25;
      reasons.push("cached evidence already available");
    }
    if (step.stage === "passive_domains" && !plan.correlation.counts.domains) {
      score += 25;
      reasons.push("domain inventory is missing");
    }
    if (step.stage === "dns" && !plan.correlation.counts.ips) {
      score += 20;
      reasons.push("address context is missing");
    }
    if (metrics.sample_runs >= 3) {
      score += Math.min(
        15,
        metrics.mean_new_entities / Math.max(1, metrics.mean_http_requests),
      );
      reasons.push(
        "observed workspace novelty per HTTP request (at least 3 completed samples)",
      );
    }
    if (
      step.adapter === "wayback" &&
      engine.store.db
        .prepare(
          "SELECT exhausted FROM discovery_state WHERE adapter=? AND target=?",
        )
        .get(step.adapter, step.target)?.exhausted
    )
      eligibility = "discovery_exhausted_restart_required";
    if (eligibility !== "ready") score = -1;
    candidates.push({
      tool: "collect",
      arguments: { adapter: step.adapter, target: step.target },
      eligibility,
      score,
      reasons,
      cached: Boolean(cached),
      estimated_logical_calls: 1,
      provider: PROVIDERS[step.adapter] ?? null,
      retry_at: provider?.status === "cooldown" ? provider.retry_at : null,
      source_metrics: metrics,
    });
  }
  candidates.sort(
    (a, b) =>
      b.score - a.score ||
      a.arguments.adapter.localeCompare(b.arguments.adapter) ||
      a.arguments.target.localeCompare(b.arguments.target),
  );
  return {
    workflow: plan.workflow,
    target: plan.target,
    status: "planned",
    actions: candidates.slice(0, 30),
    next_actions: candidates
      .filter((c) => c.score >= 0)
      .slice(0, Math.min(3, request.maxCalls))
      .map((c, i) => ({ rank: i + 1, ...c })),
    pending_dependencies: plan.steps.filter(
      (s) => !s.adapter && !["planned", "context_available"].includes(s.status),
    ),
    budget: { maxCalls: request.maxCalls, maxTargets: request.maxTargets },
    scoring:
      "Transparent prioritization heuristic, not a probability, vulnerability verdict or identity score.",
    mutation: false,
    network: false,
  };
}
