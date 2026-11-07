import { WorkflowInput } from "./schema.js";
import { runWorkflow } from "./workflows.js";
import { ADAPTERS } from "./adapters.js";
import { hash } from "./store.js";

const PROVIDERS = {
  crtsh: "crt.sh",
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
      hash(["v0.3", step.adapter, step.target, engine.config]),
    );
    const prior = engine.store.db
      .prepare(
        "SELECT status,finished FROM runs WHERE adapter=? AND target=? ORDER BY started DESC LIMIT 1",
      )
      .get(step.adapter, step.target);
    const passive = ADAPTERS[step.adapter].mode === "passive";
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
