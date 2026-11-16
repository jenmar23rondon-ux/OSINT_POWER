import { gapReason } from "./adapter-kinds.js";

const GAP_REASONS = new Set([
  "rate_limited",
  "error",
  "missing_key",
  "unknown",
  "failed",
]);

function httpServices(engine) {
  const services = [];
  for (const item of engine.store.query({ type: "url", limit: 50 }).items) {
    const hit = engine.store
      .evidence(item.id, 20)
      .items.find((row) => row.source === "httpx");
    if (!hit) continue;
    const evidence = hit.evidence ?? {};
    services.push({
      url: item.value,
      status: Number.isInteger(evidence.status) ? evidence.status : null,
      title: String(evidence.title ?? ""),
      webserver: String(evidence.webserver ?? ""),
      technology: Array.isArray(evidence.technology)
        ? evidence.technology.map(String)
        : [],
      ip: String(evidence.ip ?? ""),
      cdn: String(evidence.cdn ?? ""),
      source: hit.source,
    });
  }
  return services;
}

function registrations(engine) {
  const rows = [];
  for (const type of ["profile", "email"]) {
    for (const item of engine.store.query({ type, limit: 50 }).items) {
      for (const observation of engine.store.evidence(item.id, 10).items) {
        const evidence = observation.evidence ?? {};
        const sites = [
          evidence.site_name,
          ...(Array.isArray(evidence.profiles) ? evidence.profiles : []),
        ].filter((site) => typeof site === "string" && site);
        if (!sites.length && type !== "profile") continue;
        for (const site of sites.length ? sites : [""]) {
          rows.push({
            account: String(evidence.account ?? evidence.username ?? ""),
            site: String(site),
            url: type === "profile" ? item.value : "",
            status: String(evidence.status ?? ""),
            source: observation.source,
          });
          if (rows.length === 50) return rows;
        }
      }
    }
  }
  return rows;
}

function byTarget(engine) {
  const targets = [
    ...engine.scope.domains,
    ...engine.scope.ips,
    ...engine.scope.emails,
    ...engine.config.scope.usernames,
  ];
  return targets.map((target) => {
    const items = engine.store.findings(target, 50).items;
    return {
      target,
      findings: new Set(items.map((item) => item.id)).size,
      sources: [...new Set(items.map((item) => item.source))].sort(),
    };
  });
}

function coverageGaps(runs) {
  const gaps = [];
  for (const run of runs) {
    const summary = run.summary ?? {};
    if (Array.isArray(summary.coverage_gaps)) {
      for (const gap of summary.coverage_gaps) {
        if (!gap || typeof gap.source !== "string") continue;
        gaps.push({
          source: gap.source,
          target: String(gap.target ?? run.target ?? ""),
          site: String(gap.site ?? ""),
          reason: gap.reason,
        });
      }
    } else if (["failed", "deferred"].includes(run.status) && summary.code) {
      gaps.push({
        source: String(run.adapter).replace(/^import:/, ""),
        target: String(run.target ?? ""),
        site: "",
        reason: gapReason(summary.code),
      });
    }
  }
  return gaps.filter((gap) => GAP_REASONS.has(gap.reason)).slice(0, 50);
}

export function report(engine) {
  const findings = engine.store.query({ limit: 50 });
  const runs = engine.store.runs(20);
  return {
    project: "OSINT_POWER",
    version: "0.4.0",
    generated_at: new Date().toISOString(),
    findings,
    graph: engine.store.graph(50),
    runs,
    jobs: engine.jobs.list({ limit: 20 }),
    source_health: engine.providers.health(),
    next_actions: engine.next(),
    limitations: [
      "Source assessments are not verified ownership or identity.",
      "This report contains at most 50 entities, 50 relations and 20 runs; use pagination for more.",
      "No vulnerability or credential validity is established by a recon observation.",
      "A coverage gap means a source was not fully checked. It is not a negative result.",
      "HTTP service rows come from an explicit ProjectDiscovery httpx probe or import.",
    ],
    by_target: byTarget(engine),
    http_services: httpServices(engine),
    coverage_gaps: coverageGaps(runs),
    registrations: registrations(engine),
  };
}
