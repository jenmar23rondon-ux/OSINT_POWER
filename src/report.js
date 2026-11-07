export function report(engine) {
  const findings = engine.store.query({ limit: 50 });
  return {
    project: "OSINT_POWER",
    version: "0.1.0",
    generated_at: new Date().toISOString(),
    findings,
    graph: engine.store.graph(50),
    runs: engine.store.runs(20),
    next_actions: engine.next(),
    limitations: [
      "Source assessments are not verified ownership or identity.",
      "This report contains at most 50 entities, 50 relations and 20 runs; use pagination for more.",
      "No vulnerability or credential validity is established by a recon observation.",
    ],
  };
}
