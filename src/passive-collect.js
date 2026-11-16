import { isIP } from "node:net";
import { ADAPTERS } from "./adapters.js";
import { gapReason, PASSIVE_ADAPTERS } from "./adapter-kinds.js";

export function targetKind(target, scope) {
  if (isIP(target)) return "ip";
  if (String(target).includes("@")) return "email";
  if (!String(target).includes(".") && scope.username(target))
    return "username";
  return "domain";
}

export function passiveAdaptersFor(target, scope) {
  return (PASSIVE_ADAPTERS[targetKind(target, scope)] ?? []).filter(
    (name) => ADAPTERS[name]?.mode === "passive",
  );
}

export async function collectPassiveSources(engine, target) {
  const adapters = passiveAdaptersFor(target, engine.scope).filter((name) =>
    engine.config.enabledAdapters.includes(name),
  );
  const results = [];
  const coverage_gaps = [];
  for (const adapter of adapters) {
    let result;
    try {
      result = await engine.run({ adapter, target });
    } catch (error) {
      result = {
        adapter,
        target,
        status: "failed",
        code: /^[A-Z][A-Z_0-9]+$/.test(error.message)
          ? error.message
          : "ADAPTER_ERROR",
      };
    }
    results.push(result);
    if (Array.isArray(result.coverage_gaps))
      coverage_gaps.push(...result.coverage_gaps);
    if (["failed", "deferred"].includes(result.status) && result.code)
      coverage_gaps.push({
        source: adapter,
        target: result.target ?? target,
        site: "",
        reason: gapReason(result.code),
      });
  }
  const sources = [
    ...new Set(
      results
        .filter(
          (result) =>
            (result.inserted ?? 0) > 0 || (result.observations ?? 0) > 0,
        )
        .map((result) => result.adapter),
    ),
  ];
  return {
    status:
      results.length &&
      results.every((result) => result.status === "completed") &&
      coverage_gaps.length === 0
        ? "completed"
        : "partial",
    target,
    results,
    coverage_gaps: coverage_gaps.slice(0, 200),
    correlation: {
      target,
      findings: engine.store.findings(target, 50).items.length,
      sources,
    },
    next_actions: engine.next(),
  };
}
