import { WorkflowInput, WORKFLOW_NAMES, WORKFLOW_ALIASES } from "./schema.js";
import { usernameVariants, employeeValue } from "./identity.js";
import { ADAPTERS } from "./adapters.js";
import { domain } from "./scope.js";
import { recordSource } from "./state.js";

export const WORKFLOWS = WORKFLOW_NAMES;
const obs = (type, value, evidence, confidence = 0.25) => ({
  type,
  value,
  evidence,
  confidence,
  source: "workflow",
  timestamp: new Date().toISOString(),
});
export function correlate(engine, target) {
  const d = domain(target);
  if (!engine.scope.host(d)) throw new Error("OUT_OF_SCOPE");
  const emails = engine.store.domainEntities("email", d, 100);
  const domains = engine.store.domainEntities("domain", d, 100);
  const ips = engine.store.domainIPs(d, 100);
  const breachRows = engine.store.db
    .prepare(
      "SELECT e.id,e.value,o.evidence FROM entities e JOIN observations o ON o.entity_id=e.id WHERE e.type='breach' AND (json_extract(o.evidence,'$.account') LIKE ? OR json_extract(o.evidence,'$.account') LIKE ?) ORDER BY e.id LIMIT 1000",
    )
    .all("%@" + d, "%@%." + d);
  const scopedEmails = new Set(emails.map((e) => e.value));
  const breachMap = new Map();
  for (const row of breachRows) {
    const ev = JSON.parse(row.evidence);
    if (scopedEmails.has(ev.account))
      breachMap.set(row.id, {
        entity_id: row.id,
        type: "breach",
        reason:
          "Review breach association and account protections; password validity unknown",
      });
  }
  const serviceRows = engine.store.db
    .prepare(
      "SELECT e.id,e.value,o.evidence FROM entities e JOIN observations o ON o.entity_id=e.id WHERE e.type='service' AND (json_extract(o.evidence,'$.host')=? OR json_extract(o.evidence,'$.host') LIKE ?) ORDER BY e.id LIMIT 1000",
    )
    .all(d, "%." + d)
    .filter((r) => {
      const host = JSON.parse(r.evidence).host;
      return host === d || host?.endsWith("." + d);
    });
  const services = [
    ...new Map(serviceRows.map((row) => [row.id, row])).values(),
  ];
  const professionalCoverage = engine.scope.people
    .filter((p) => p.companyDomain === d)
    .map((p) => ({
      name: p.name,
      employee: employeeValue(p),
      observations: engine.store.db
        .prepare(
          "SELECT COUNT(*) AS n FROM observations WHERE json_extract(evidence,'$.person')=? AND json_extract(evidence,'$.company')=?",
        )
        .get(p.name, d).n,
      identity_verified: false,
    }));
  const total = (type) =>
    engine.store.db
      .prepare(
        "SELECT COUNT(*) AS n FROM entities WHERE type=? AND (value=? OR value LIKE ? OR value LIKE ?)",
      )
      .get(type, d, "%." + d, "%@" + d).n;
  const totalIPs = engine.store.db
    .prepare(
      "SELECT COUNT(DISTINCT ip.id) AS n FROM entities ip JOIN edges edge ON edge.to_id=ip.id AND edge.relation='resolves_to' JOIN entities host ON host.id=edge.from_id WHERE ip.type='ip' AND (host.value=? OR host.value LIKE ?)",
    )
    .get(d, "%." + d).n;
  const totalBreaches = engine.store.db
    .prepare(
      "SELECT COUNT(DISTINCT e.id) AS n FROM entities e JOIN observations o ON o.entity_id=e.id WHERE e.type='breach' AND (json_extract(o.evidence,'$.account') LIKE ? OR json_extract(o.evidence,'$.account') LIKE ?)",
    )
    .get("%@" + d, "%@%." + d).n;
  const totalServices = engine.store.db
    .prepare(
      "SELECT COUNT(DISTINCT e.id) AS n FROM entities e JOIN observations o ON o.entity_id=e.id WHERE e.type='service' AND (json_extract(o.evidence,'$.host')=? OR json_extract(o.evidence,'$.host') LIKE ?)",
    )
    .get(d, "%." + d).n;
  return {
    company: d,
    counts: {
      domains: total("domain"),
      ips: totalIPs,
      emails: total("email"),
      breach_associations: totalBreaches,
      observed_services: totalServices,
    },
    samples: {
      domains: domains.length,
      ips: ips.length,
      emails: emails.length,
      breach_associations: breachMap.size,
      observed_services: services.length,
    },
    truncated:
      total("domain") > domains.length ||
      totalIPs > ips.length ||
      total("email") > emails.length ||
      totalBreaches > breachMap.size ||
      totalServices > services.length,
    bounded: true,
    summary_limits: { entities_per_type: 100, observations_per_review: 1000 },
    professional_coverage: professionalCoverage,
    defensive_review: [
      ...breachMap.values(),
      ...services.slice(0, 10).map((r) => ({
        entity_id: r.id,
        type: "service",
        reason:
          "Review necessity, ownership and access restrictions of the observed service",
      })),
    ].slice(0, 10),
    conclusions: {
      probable_entry_point: "not_established_by_osint",
      employee_risk_ranking: "not_computed",
      physical_location_from_ip: "not_established",
    },
    next_actions: [
      {
        rank: 1,
        action: breachMap.size
          ? "Review affected account protections and remediate known exposure"
          : "Confirm ownership and provenance of observed assets",
        reason: "Prioritize evidence-backed remediation; no credential testing",
        cost: "local_review",
      },
      {
        rank: 2,
        action:
          "Resolve conflicting identities, shared infrastructure and inferred technology claims",
        reason: "Reduce false attribution before drawing conclusions",
        cost: "local_review",
      },
      {
        rank: 3,
        action:
          "Collect one missing independent source within configured quotas",
        reason:
          "Use cached state and a bounded query instead of broad repeated collection",
        cost: "one_scoped_call",
      },
    ],
  };
}
export function searchQueries(person, company) {
  const quoted = (value) => '"' + value.replace(/["\\]/g, "") + '"';
  const name = quoted(person);
  const org = quoted(company);
  return [
    { source: "LinkedIn", query: `site:linkedin.com/in ${name} ${org}` },
    { source: "GitHub", query: `site:github.com ${name} ${org}` },
    { source: "X", query: `site:x.com ${name} ${org}` },
  ];
}
export async function runWorkflow(engine, input, job) {
  const request = WorkflowInput.parse(input);
  const { execute, maxTargets } = request;
  const maxCalls = job?.maxCalls ?? request.maxCalls;
  const workflow = WORKFLOW_ALIASES[request.workflow] ?? request.workflow;
  const person =
    workflow === "people" ? engine.scope.person(request.target) : null;
  if (workflow === "people" && !person) throw new Error("PERSON_OUT_OF_SCOPE");
  const target = person ? person.companyDomain : domain(request.target);
  if (!engine.scope.host(target)) throw new Error("OUT_OF_SCOPE");
  const runId =
    job?.id ??
    (execute
      ? engine.store.start(`workflow:${workflow}`, person?.name ?? target)
      : null);
  const steps = [];
  let usernameCandidates = [];
  let calls = 0;
  const offline = (name, observations) => {
    job?.check();
    const operation = () => {
      const result = engine.store.ingest(observations, {
        runId,
        collector: "workflow",
        target,
      });
      recordSource(engine.store, runId, "workflow", target, {
        status: "completed",
      });
      return result;
    };
    const result = execute
      ? job
        ? job.local(name, observations, operation)
        : operation()
      : { observations: observations.length };
    steps.push({
      stage: name,
      status: execute ? "completed" : "planned",
      ...result,
    });
  };
  const invoke = async (stage, adapter, value) => {
    job?.check();
    if (job) {
      const saved = job.before(stage, adapter, value);
      if (saved) {
        steps.push({ stage, ...saved });
        return;
      }
    }
    let status = !engine.config.enabledAdapters.includes(adapter)
      ? "adapter_disabled"
      : !engine.config.network
        ? "network_disabled"
        : ADAPTERS[adapter].mode === "active" && !engine.config.active
          ? "active_disabled"
          : "ready";
    if (!execute || status !== "ready") {
      steps.push({ stage, adapter, target: value, status });
      if (job) {
        job.complete(stage, adapter, value, {
          stage,
          adapter,
          target: value,
          status,
        });
        recordSource(engine.store, runId, adapter, value, { status });
      }
      return;
    }
    if (calls >= maxCalls) {
      steps.push({ stage, adapter, target: value, status: "budget_exhausted" });
      if (job)
        job.complete(stage, adapter, value, {
          stage,
          adapter,
          target: value,
          status: "budget_exhausted",
        });
      return;
    }
    calls++;
    job?.start(stage, adapter, value);
    try {
      const result = await engine.run(
        { adapter, target: value },
        {
          parentRunId: runId,
          signal: job?.signal,
          isOwner: job?.isOwner,
          onStarted: (id) => job?.child(stage, adapter, value, id),
        },
      );
      job?.check();
      job?.complete(stage, adapter, value, result);
      steps.push({ stage, ...result });
    } catch (error) {
      job?.check();
      const result = {
        stage,
        adapter,
        target: value,
        status: "failed",
        code: /^[A-Z_0-9]+$/.test(error.message)
          ? error.message
          : "INVALID_INPUT",
      };
      job?.complete(stage, adapter, value, result);
      if (runId) recordSource(engine.store, runId, adapter, value, result);
      steps.push({
        stage,
        adapter,
        target: value,
        status: "failed",
        code: /^[A-Z_0-9]+$/.test(error.message)
          ? error.message
          : "INVALID_INPUT",
      });
    }
  };
  const context = (stage, type) => {
    const found = engine.store.contextEntities(type, target, maxTargets);
    steps.push({
      stage,
      status: found.length ? "context_available" : "needs_import",
      type,
      entities: found.map((r) => r.id),
      reason:
        "Import a sourced business-context record; external searches are not fabricated",
    });
  };
  const freeze = (name, compute) =>
    job ? job.freeze(name, compute) : compute();
  const names = () =>
    freeze("hosts", () =>
      engine.store
        .domainEntities("domain", target, maxTargets)
        .map((r) => r.value),
    );
  const accounts = () =>
    freeze("accounts", () =>
      [
        ...new Set([
          ...engine.store
            .domainEntities("email", target, maxTargets)
            .map((r) => r.value),
          ...engine.config.scope.emails.filter((e) => e.endsWith("@" + target)),
        ]),
      ].slice(0, maxTargets),
    );
  try {
    if (workflow !== "correlation")
      offline("company_context", [
        obs(
          "company",
          target,
          { host: target, verification: "configured_scope" },
          0.5,
        ),
      ]);
    if (workflow === "people") {
      const variants = usernameVariants(
        person.name,
        person.aliases,
        engine.config.collectors.usernameSuffixes,
      );
      usernameCandidates = variants.map((value) => ({
        type: "username",
        value,
        source: "name_variants",
        confidence: 0.25,
        inferred: true,
      }));
      offline("candidate_aliases", [
        obs(
          "employee",
          employeeValue(person),
          {
            company: target,
            person: person.name,
            verification: "configured_professional_subject",
          },
          0.5,
        ),
        ...variants.map((value) =>
          obs("username", value, {
            company: target,
            person: person.name,
            inferred: true,
            reason: "Name-derived candidate; identity unverified",
          }),
        ),
      ]);
      for (const value of variants.slice(0, maxTargets)) {
        await invoke("username_lookup", "sherlock", value);
        await invoke("public_profile", "github-profile", value);
      }
      context("professional_roles", "role");
      context("professional_technology", "technology");
      steps.push({
        stage: "external_search",
        status: "needs_host_search",
        queries: searchQueries(person.name, target),
        reason:
          "Host search or sourced import for LinkedIn, GitHub and X; no automatic identity attribution",
      });
    }
    if (["company", "emails", "users"].includes(workflow)) {
      if (workflow === "company")
        for (const adapter of ["crtsh", "subfinder", "amass"])
          await invoke("passive_domains", adapter, target);
      await invoke("public_email_collection", "theharvester", target);
    }
    if (workflow === "company") {
      const hosts = names();
      if (!hosts.length)
        steps.push({
          stage: "host_validation",
          status: execute ? "needs_input" : "deferred",
          reason: "Depends on passive domain findings",
        });
      for (const host of hosts) {
        await invoke("dns", "dnsx", host);
        await invoke("http_fingerprint", "httpx", host);
      }
      for (const ip of freeze("ips", () =>
        engine.store.domainIPs(target, maxTargets),
      ))
        for (const adapter of ["rdap", "routing"])
          await invoke("ip_context", adapter, ip.value);
      context("hiring_technology", "job");
    }
    if (["company", "emails", "exposures"].includes(workflow)) {
      const emails = accounts();
      if (execute)
        offline(
          "configured_accounts",
          emails
            .filter((e) => engine.config.scope.emails.includes(e))
            .map((e) =>
              obs(
                "email",
                e,
                { verification: "configured_account_mailbox_unknown" },
                0.5,
              ),
            ),
        );
      if (workflow !== "exposures")
        for (const emailDomain of [
          ...new Set(emails.map((e) => e.split("@")[1])),
        ])
          await invoke("mail_dns", "mx", emailDomain);
      for (const email of emails) {
        if (engine.scope.emails.includes(email))
          await invoke("breach_metadata", "hibp", email);
        else
          steps.push({
            stage: "breach_metadata",
            target: email,
            status: "exact_account_required",
            reason:
              "HIBP accepts only exact configured accounts; MX is not mailbox verification",
          });
      }
      if (!emails.length)
        steps.push({
          stage: "email_context",
          status: "needs_input",
          reason:
            "Import public corporate emails or configure exact test accounts",
        });
    }
    if (workflow === "users") {
      const emails = accounts();
      offline(
        "configured_accounts",
        emails
          .filter((e) => engine.config.scope.emails.includes(e))
          .map((e) =>
            obs(
              "email",
              e,
              { verification: "configured_account_mailbox_unknown" },
              0.5,
            ),
          ),
      );
      offline(
        "email_alias_candidates",
        emails.map((email) =>
          obs("username", email.split("@")[0], {
            account: email,
            inferred: true,
            reason: "Email local part; identity unverified",
          }),
        ),
      );
      for (const email of emails) {
        const alias = email.split("@")[0];
        if (engine.scope.username(alias)) {
          await invoke("username_lookup", "sherlock", alias);
          await invoke("public_profile", "github-profile", alias);
        } else
          steps.push({
            stage: "username_lookup",
            target: alias,
            status: "candidate_only",
            reason:
              "Candidate retained; configure the intended alias before cross-platform collection",
          });
      }
    }
    if (workflow === "places") {
      context("public_office_locations", "place");
      steps.push({
        stage: "infrastructure_location",
        status: "not_inferred",
        reason:
          "ASN, registration country, CDN or IP geolocation do not establish a corporate office",
      });
    }
    if (workflow === "exposures") {
      const secrets = engine.store.query({ type: "secret", limit: maxTargets });
      steps.push({
        stage: "secret_references",
        status: secrets.total ? "context_available" : "needs_import",
        entities: secrets.items.map((r) => r.id),
        company_attribution: "unassigned_workspace_references",
        reason:
          "Import Gitleaks/TruffleHog reports; keep file/rule/line only, never raw values or prefixes",
      });
      steps.push({
        stage: "additional_breaches",
        status: "import_only",
        adapters: ["breach-summary"],
        reason:
          "Strict DeHashed/LeakCheck summaries only; no password search or credential validation",
      });
    }
    job?.check();
    const correlation = correlate(engine, target);
    const pending = steps.filter(
      (s) =>
        ![
          "completed",
          "context_available",
          "not_inferred",
          "import_only",
        ].includes(s.status),
    );
    const result = {
      workflow,
      target,
      person: person?.name ?? null,
      mode: execute ? "execute" : "plan",
      status: execute ? (pending.length ? "partial" : "completed") : "planned",
      run_id: runId,
      calls,
      maxCalls,
      maxTargets,
      steps,
      correlation,
      username_candidates: usernameCandidates,
      findings: engine.store.findings(target, 25),
      next_actions: correlation.next_actions,
    };
    if (runId)
      engine.store.finish(runId, result.status, {
        workflow,
        calls,
        steps: steps.map((s) => ({ stage: s.stage, status: s.status })),
        pending: pending.length,
      });
    return result;
  } catch (error) {
    if (runId && !job)
      engine.store.finish(runId, "failed", { code: "WORKFLOW_ERROR" });
    throw error;
  }
}
