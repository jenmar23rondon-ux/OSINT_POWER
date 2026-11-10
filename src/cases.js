import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { z } from "zod";
import { ADAPTERS } from "./adapters.js";
import { explainAsset } from "./evidence-intelligence.js";
import { SCHEMA_VERSION, inspectResolution, loadDecisions } from "./review.js";
import { WORKFLOW_ALIASES, WORKFLOW_NAMES } from "./schema.js";
import { domain, normalized } from "./scope.js";
import { STIX_LIMITATIONS, exportStix, stixId, stixTime } from "./stix.js";
import { validateStixBundle } from "./stix-validate.js";

// Local investigation hypotheses and cases. Nothing here collects, scans, or
// contacts a network. A hypothesis is never a finding. analyst-confirmed is
// stored only when an analyst closes it explicitly.
export const HYPOTHESIS_STATUSES = [
  "open",
  "supported-pending-review",
  "weakened",
  "rejected",
  "analyst-confirmed",
];
export const DERIVED_STATUSES = [
  "open",
  "supported-pending-review",
  "weakened",
];
export const CLAIMS = [
  "current-activity",
  "historical-existence",
  "organization-attribution",
  "entity-association",
];
const ANALYST_CLOSURES = ["rejected", "analyst-confirmed"];
const INVESTIGATIONS = new Set([...WORKFLOW_NAMES, "phishing", "collectors"]);
const MAX_LIST = 40;
const hashId = z.string().regex(/^[a-f0-9]{64}$/);
const text = z.string();

export const HYPOTHESIS_RULES = [
  "A hypothesis is not a finding and is not confirmed by this tool.",
  "evaluate_hypothesis never sets analyst-confirmed.",
  "analyst-confirmed is stored only by close_hypothesis with an analyst id and a reason.",
  "An analyst accept on an entity or finding does not confirm the hypothesis.",
  "Contradicting evidence sets the assessed status to weakened.",
  "Support that meets the claim stays supported-pending-review until an analyst closes it.",
  "A shared name, handle, IP, CDN, or hosting ASN is not support for attribution or identity.",
  "A suggested step is not executed. If it needs network, active mode, or an adapter, requires_gate is set and within_gates is false.",
];
export const HYPOTHESIS_LIMITATIONS = [
  "Evaluation is a heuristic over stored rows and the evidence-intelligence assessment. It is not a probability or proof.",
  "Historical certificates and archives do not establish current activity.",
  "Duplicate, mirrored, same-upstream, and same-run sources are not independent support.",
  "These tools do not collect, scan, change scope, or record an entity review decision.",
  "Out-of-scope entities and evidence cannot be attached.",
];
export const CASE_LIMITATIONS = [
  "This report reads stored rows. It does not collect, scan, or contact a source.",
  "Confirmed analyst decisions are decisions a person recorded. They are not findings produced by this tool.",
  "Candidates are unresolved links. A shared name or handle is not a confirmed identity.",
  "Hypotheses are not findings. supported-pending-review and weakened are assessments.",
  "analyst-confirmed is an explicit analyst close. It is still not proof of identity, ownership, or phishing.",
  "Resolver-confirmed identity links are omitted from the confirmed section because they are not analyst decisions.",
  "STIX export reuses the evidence exporter. A hypothesis is a note, not an indicator or a finding.",
  "A suggestion that needs network, active mode, or an adapter is labeled and is not executed.",
];
const CASE_STIX_NOTES = [
  "Case export calls the existing STIX exporter once per investigation and target on the case, then keeps one copy of each object id.",
  "Hypothesis statements are notes. They are not indicators, and a supported or analyst-confirmed hypothesis is not rewritten as a finding.",
  "With no investigation and no target, the bundle is the in-scope workspace rather than a proof that the case contains only those objects.",
];

const analystId = z.string().regex(/^[A-Za-z0-9_.@-]{1,80}$/);
export const CreateHypothesisInput = z
  .object({
    statement: z.string().min(1).max(500),
    claim: z.enum(CLAIMS),
    entity_ids: z.array(hashId).min(1).max(20),
    evidence_ids: z.array(hashId).max(40).default([]),
    case_id: z.uuid().optional(),
    note: z.string().max(2000).default(""),
  })
  .strict();
export const UpdateHypothesisInput = z
  .object({
    id: z.uuid(),
    statement: z.string().min(1).max(500).optional(),
    claim: z.enum(CLAIMS).optional(),
    entity_ids: z.array(hashId).min(1).max(20).optional(),
    evidence_ids: z.array(hashId).max(40).optional(),
    case_id: z.uuid().nullable().optional(),
    note: z.string().max(2000).optional(),
  })
  .strict();
export const CloseHypothesisInput = z
  .object({
    id: z.uuid(),
    status: z.enum(ANALYST_CLOSURES),
    reason: z.string().min(1).max(2000),
    analyst_id: analystId,
  })
  .strict();
export const ListHypothesesInput = z
  .object({
    case_id: z.uuid().optional(),
    status: z.enum(HYPOTHESIS_STATUSES).optional(),
    limit: z.number().int().min(1).max(100).default(25),
    cursor: z.uuid().optional(),
  })
  .strict();
export const EvaluateHypothesisInput = z.object({ id: z.uuid() }).strict();
export const CreateCaseInput = z
  .object({
    title: z.string().min(1).max(120),
    summary: z.string().min(1).max(2000),
    investigations: z.array(z.string().min(1).max(80)).max(20).default([]),
    targets: z.array(z.string().min(1).max(253)).max(20).default([]),
    hypothesis_ids: z.array(z.uuid()).max(40).default([]),
    decision_ids: z.array(z.uuid()).max(40).default([]),
    notes: z.array(z.string().min(1).max(2000)).max(20).default([]),
  })
  .strict();
export const ListCasesInput = z
  .object({
    limit: z.number().int().min(1).max(100).default(25),
    cursor: z.uuid().optional(),
  })
  .strict();
export const CaseIdInput = z.object({ case_id: z.uuid() }).strict();
export const CaseReportInput = z
  .object({
    case_id: z.uuid(),
    format: z.enum(["json", "markdown"]).default("json"),
  })
  .strict();

const gatesShape = z
  .object({
    executes: z.literal(false),
    network: z.literal(false),
    collection: z.literal(false),
  })
  .strict();
const hypothesisShape = {
  id: z.uuid(),
  statement: text,
  claim: z.enum(CLAIMS),
  status: z.enum(HYPOTHESIS_STATUSES),
  confirmed: z.boolean(),
  finding: z.literal(false),
  case_id: z.uuid().nullable(),
  note: text,
  entity_ids: z.array(hashId),
  evidence_ids: z.array(hashId),
  analyst_id: text.nullable(),
  analyst_reason: text.nullable(),
  closed_at: text.nullable(),
  created_at: text,
  updated_at: text,
};
export const Hypothesis = z.object(hypothesisShape).strict();
const hypothesisPayload = {
  hypothesis: Hypothesis,
  ...gatesShape.shape,
  rules: z.array(text),
};
export const HypothesisResult = z.object(hypothesisPayload).strict();
export const HypothesisListResult = z
  .object({
    items: z.array(Hypothesis),
    returned: z.number().int().nonnegative(),
    limit: z.number().int().nonnegative(),
    next_cursor: z.uuid().nullable(),
    total: z.number().int().nonnegative(),
    ...gatesShape.shape,
    rules: z.array(text),
  })
  .strict();
const hit = z
  .object({
    evidence_id: hashId.nullable(),
    entity_id: hashId.nullable(),
    reason: text,
  })
  .strict();
const gap = z
  .object({
    entity_id: hashId.nullable(),
    kind: text,
    reason: text,
  })
  .strict();
const nextStep = z
  .object({
    action: text,
    reason: text,
    executes: z.literal(false),
    within_gates: z.boolean(),
    requires_gate: z.enum(["network", "active", "adapter"]).nullable(),
    adapter: text.nullable(),
    target: text.nullable(),
  })
  .strict();
export const EvaluateHypothesisResult = z
  .object({
    hypothesis_id: z.uuid(),
    statement: text,
    claim: z.enum(CLAIMS),
    stored_status: z.enum(HYPOTHESIS_STATUSES),
    assessed_status: z.enum(DERIVED_STATUSES),
    confirmed: z.boolean(),
    finding: z.literal(false),
    analyst_id: text.nullable(),
    analyst_reason: text.nullable(),
    supporting: z.array(hit).max(MAX_LIST),
    supporting_truncated: z.boolean(),
    contradicting: z.array(hit).max(MAX_LIST),
    contradicting_truncated: z.boolean(),
    missing: z.array(gap).max(MAX_LIST),
    missing_truncated: z.boolean(),
    next_steps: z.array(nextStep).min(1).max(5),
    status_updated: z.boolean(),
    ...gatesShape.shape,
    rules: z.array(text),
    limitations: z.array(text),
  })
  .strict();
const caseCounts = z
  .object({
    investigations: z.number().int().nonnegative(),
    targets: z.number().int().nonnegative(),
    hypotheses: z.number().int().nonnegative(),
    decisions: z.number().int().nonnegative(),
    notes: z.number().int().nonnegative(),
    candidates: z.number().int().nonnegative(),
  })
  .strict();
export const CaseSummaryResult = z
  .object({
    id: z.uuid(),
    title: text,
    summary: text,
    investigations: z.array(text),
    targets: z.array(text),
    notes: z.array(text),
    decision_ids: z.array(z.uuid()),
    hypotheses: z.array(Hypothesis),
    counts: caseCounts,
    ...gatesShape.shape,
    limitations: z.array(text),
  })
  .strict();
export const CaseListResult = z
  .object({
    items: z.array(
      z
        .object({
          id: z.uuid(),
          title: text,
          summary: text,
          hypothesis_count: z.number().int().nonnegative(),
          created_at: text,
          updated_at: text,
        })
        .strict(),
    ),
    returned: z.number().int().nonnegative(),
    limit: z.number().int().nonnegative(),
    next_cursor: z.uuid().nullable(),
    total: z.number().int().nonnegative(),
    ...gatesShape.shape,
  })
  .strict();
const reviewItem = z
  .object({
    kind: z.literal("review-decision"),
    id: z.uuid(),
    subject_kind: z.enum(["entity", "finding"]),
    subject_id: hashId,
    decision: z.literal("accept"),
    reason: text,
    analyst_id: text,
    recorded_at: text,
    finding: z.literal(false),
  })
  .strict();
const closureItem = z
  .object({
    kind: z.literal("hypothesis-closure"),
    hypothesis_id: z.uuid(),
    statement: text,
    analyst_id: text,
    reason: text,
    closed_at: text,
    finding: z.literal(false),
  })
  .strict();
const candidateItem = z
  .object({
    kind: z.literal("candidate-link"),
    id: hashId,
    left_id: hashId,
    right_id: hashId,
    basis: text,
    status: z.literal("candidate"),
    finding: z.literal(false),
    note: text,
  })
  .strict();
const hypothesisReportItem = z
  .object({
    kind: z.literal("hypothesis"),
    ...hypothesisShape,
    assessed_status: z.enum(DERIVED_STATUSES),
  })
  .strict();
export const CaseReportResult = z
  .object({
    case_id: z.uuid(),
    title: text,
    format: z.enum(["json", "markdown"]),
    sections: z
      .object({
        confirmed_analyst_decisions: z.array(
          z.union([reviewItem, closureItem]),
        ),
        candidates: z.array(candidateItem),
        hypotheses: z.array(hypothesisReportItem),
        limitations: z.array(text),
      })
      .strict(),
    markdown: text,
    ...gatesShape.shape,
  })
  .strict();

function parseInput(schema, input) {
  const result = schema.safeParse(input ?? {});
  if (!result.success) throw new Error("INVALID_INPUT");
  return result.data;
}
function unique(values) {
  return [...new Set(values)];
}
function trimText(value) {
  return typeof value === "string" ? value.trim() : value;
}
function gatesOf(gates = {}) {
  return {
    network: gates.network === true,
    active: gates.active === true,
    enabledAdapters: Array.isArray(gates.enabledAdapters)
      ? gates.enabledAdapters
      : [],
  };
}
function readJson(value, fallback) {
  try {
    const parsed = JSON.parse(value);
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
}
function presentHypothesis(row) {
  return {
    id: row.id,
    statement: row.statement,
    claim: row.claim,
    status: row.status,
    confirmed: row.status === "analyst-confirmed",
    finding: false,
    case_id: row.case_id,
    note: row.note,
    entity_ids: readJson(row.entity_ids, []),
    evidence_ids: readJson(row.evidence_ids, []),
    analyst_id: row.analyst_id,
    analyst_reason: row.analyst_reason,
    closed_at: row.closed_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}
function localFlags() {
  return { executes: false, network: false, collection: false };
}
function hypothesisResult(row) {
  return {
    hypothesis: presentHypothesis(row),
    ...localFlags(),
    rules: HYPOTHESIS_RULES,
  };
}
function loadHypothesis(store, id) {
  const row = store.db.prepare("SELECT * FROM hypotheses WHERE id=?").get(id);
  if (!row) throw new Error("HYPOTHESIS_NOT_FOUND");
  return row;
}
function loadCaseRow(store, id) {
  const row = store.db.prepare("SELECT * FROM cases WHERE id=?").get(id);
  if (!row) throw new Error("CASE_NOT_FOUND");
  return row;
}
function closedStatus(status) {
  return status === "rejected" || status === "analyst-confirmed";
}
function entityRow(store, id) {
  return (
    store.db
      .prepare("SELECT id, type, value FROM entities WHERE id=?")
      .get(id) ?? null
  );
}
function observationRows(store, entityId) {
  return store.db
    .prepare(
      "SELECT id, entity_id, evidence FROM observations WHERE entity_id=?",
    )
    .all(entityId)
    .map((row) => ({ ...row, evidence: readJson(row.evidence, {}) }));
}
function observationById(store, id) {
  const row = store.db
    .prepare("SELECT id, entity_id, evidence FROM observations WHERE id=?")
    .get(id);
  if (!row) return null;
  return { ...row, evidence: readJson(row.evidence, {}) };
}
function entityInScope(scope, entity, observations) {
  if (
    observations.some((obs) =>
      scope.allows(entity.type, entity.value, obs.evidence ?? {}),
    )
  )
    return true;
  try {
    if (["domain", "company", "mail_domain"].includes(entity.type))
      return scope.host(entity.value);
    if (entity.type === "url")
      return scope.host(new URL(entity.value).hostname.replace(/^\[|\]$/g, ""));
    if (entity.type === "email") return scope.allows("email", entity.value);
    if (entity.type === "username") return scope.username(entity.value);
    if (entity.type === "ip") return scope.allows("ip", entity.value, {});
  } catch {
    return false;
  }
  return false;
}
function requireEntity(store, scope, id) {
  const entity = entityRow(store, id);
  if (!entity) throw new Error("ENTITY_NOT_FOUND");
  if (!entityInScope(scope, entity, observationRows(store, id)))
    throw new Error("OUT_OF_SCOPE");
  return entity;
}
function requireEvidence(store, scope, id) {
  const obs = observationById(store, id);
  if (!obs) throw new Error("EVIDENCE_NOT_FOUND");
  requireEntity(store, scope, obs.entity_id);
  return obs;
}
function requireCase(store, id) {
  if (id) loadCaseRow(store, id);
}
function assertInvestigation(store, value) {
  const label = value.trim();
  if (z.uuid().safeParse(label).success) {
    const found =
      store.db.prepare("SELECT 1 FROM monitors WHERE id=?").get(label) ||
      store.db.prepare("SELECT 1 FROM runs WHERE id=?").get(label) ||
      store.db.prepare("SELECT 1 FROM jobs WHERE id=?").get(label);
    if (!found) throw new Error("INVESTIGATION_NOT_FOUND");
    return label;
  }
  const name = WORKFLOW_ALIASES[label] ?? label;
  if (!INVESTIGATIONS.has(name)) throw new Error("INVALID_INPUT");
  return name;
}
function assertTarget(scope, value) {
  const raw = value.trim();
  try {
    if (raw.includes("@")) {
      const email = normalized("email", raw);
      if (!scope.allows("email", email)) throw new Error("OUT_OF_SCOPE");
      return email;
    }
    if (isIP(raw)) {
      const ip = normalized("ip", raw);
      if (!scope.allows("ip", ip, {})) throw new Error("OUT_OF_SCOPE");
      return ip;
    }
    const name = domain(raw);
    if (!scope.host(name)) throw new Error("OUT_OF_SCOPE");
    return name;
  } catch (error) {
    if (error.message === "OUT_OF_SCOPE") throw error;
    throw new Error("INVALID_INPUT");
  }
}
function requireDecision(store, scope, id) {
  const row = store.db
    .prepare(
      "SELECT id, subject_kind, subject_id FROM review_decisions WHERE id=?",
    )
    .get(id);
  if (!row) throw new Error("DECISION_NOT_FOUND");
  if (row.subject_kind === "entity")
    requireEntity(store, scope, row.subject_id);
  else {
    const obs = observationById(store, row.subject_id);
    if (!obs) throw new Error("EVIDENCE_NOT_FOUND");
    requireEntity(store, scope, obs.entity_id);
  }
  return row;
}
function linksFor(ids, resolution) {
  const wanted = new Set(ids);
  return resolution.links.filter(
    (link) => wanted.has(link.left_id) || wanted.has(link.right_id),
  );
}
function pack(items, limit = MAX_LIST) {
  return { items: items.slice(0, limit), truncated: items.length > limit };
}
function dedupeHits(items) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = `${item.evidence_id}|${item.entity_id}|${item.reason}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}
function pushIds(bucket, ids, entityId, reason) {
  const list = ids.length ? ids : [null];
  for (const evidenceId of list)
    bucket.push({
      evidence_id: evidenceId,
      entity_id: entityId,
      reason,
    });
}
function assessStored(store, scope, gates, entity) {
  try {
    return explainAsset(store, scope, gates, { entity_id: entity.id });
  } catch (error) {
    if (
      error.message === "ASSET_NOT_IN_SCOPE" ||
      error.message === "ENTITY_NOT_FOUND"
    )
      return null;
    throw error;
  }
}
function claimView(claim, entity, assessment, links, decisions) {
  const supporting = [];
  const contradicting = [];
  const missing = [];
  let met = false;
  const history = decisions.get(`entity:${entity.id}`) ?? [];
  const current = history.at(-1) ?? null;
  if (current?.decision === "reject") {
    contradicting.push({
      evidence_id: null,
      entity_id: entity.id,
      reason:
        "An analyst rejected this entity. That weakens the hypothesis and does not confirm it.",
    });
  }
  if (claim === "current-activity") {
    if (!assessment)
      missing.push({
        entity_id: entity.id,
        kind: "current-activity",
        reason:
          "Current activity is assessed for in-scope domains, IPs, ASNs, URLs and technologies.",
      });
    else if (assessment.current_activity.status === "confirmed") {
      met = true;
      pushIds(
        supporting,
        assessment.current_activity.evidence_ids,
        entity.id,
        "A recent direct observation confirms activity. This does not confirm the hypothesis.",
      );
    } else if (assessment.current_activity.status === "contradicted") {
      pushIds(
        contradicting,
        assessment.current_activity.evidence_ids,
        entity.id,
        "Recent observations disagree on current activity.",
      );
    } else
      missing.push({
        entity_id: entity.id,
        kind: "current-activity",
        reason:
          "No recent DNS, HTTP, MX, or port observation confirms activity. Historical records do not fill this gap.",
      });
  } else if (claim === "historical-existence") {
    if (!assessment)
      missing.push({
        entity_id: entity.id,
        kind: "historical-existence",
        reason:
          "Historical existence is assessed for in-scope domains, IPs, ASNs, URLs and technologies.",
      });
    else if (assessment.historical_existence.status === "documented") {
      met = true;
      pushIds(
        supporting,
        assessment.historical_existence.evidence_ids,
        entity.id,
        "A stored certificate or archive record documents the name. This does not confirm the hypothesis.",
      );
    } else
      missing.push({
        entity_id: entity.id,
        kind: "historical-existence",
        reason: "No stored certificate or archive record documents this asset.",
      });
  } else if (claim === "organization-attribution") {
    if (!assessment)
      missing.push({
        entity_id: entity.id,
        kind: "organization-attribution",
        reason:
          "Organization attribution is assessed for in-scope domains, IPs, ASNs, URLs and technologies.",
      });
    else if (assessment.ownership.status === "verified") {
      met = true;
      pushIds(
        supporting,
        assessment.ownership.evidence_ids,
        entity.id,
        "Two independent in-scope organization-domain assertions are stored. This is not an analyst confirmation.",
      );
    } else if (assessment.ownership.status === "contradicted") {
      pushIds(
        contradicting,
        assessment.ownership.evidence_ids,
        entity.id,
        `Stored organization claims conflict (${assessment.ownership.basis}).`,
      );
    } else
      missing.push({
        entity_id: entity.id,
        kind: "organization-attribution",
        reason: `Attribution is unverified (${assessment.ownership.basis}). A shared IP, CDN, hosting ASN, name, or single source is not support.`,
      });
  } else {
    const related = links.filter(
      (link) => link.left_id === entity.id || link.right_id === entity.id,
    );
    const confirmed = related.filter((link) => link.status === "confirmed");
    const identifiers = confirmed.flatMap((link) =>
      (link.evidence ?? [])
        .filter((item) => item.role === "corroborating_identifier")
        .map((item) => item.observation_id),
    );
    if (confirmed.length) {
      met = true;
      pushIds(
        supporting,
        identifiers,
        entity.id,
        "A non-name identifier has independent corroboration. The hypothesis is still not analyst-confirmed.",
      );
    } else if (related.length)
      missing.push({
        entity_id: entity.id,
        kind: "entity-association",
        reason:
          "A shared name or handle is not support. The link stays a candidate.",
      });
    else
      missing.push({
        entity_id: entity.id,
        kind: "entity-association",
        reason:
          "No stored non-name identifier links these entities. A hypothesis cannot create that link.",
      });
    for (const item of assessment?.conflicts ?? [])
      pushIds(
        contradicting,
        item.evidence_ids,
        entity.id,
        "Stored attributes disagree.",
      );
  }
  const contradictions = [];
  return {
    supporting,
    contradicting: contradicting.concat(contradictions),
    missing,
    met,
  };
}
function hostOf(entity) {
  if (["domain", "company", "mail_domain"].includes(entity.type))
    return entity.value;
  if (entity.type === "url") {
    try {
      return new URL(entity.value).hostname.replace(/^\[|\]$/g, "");
    } catch {
      return null;
    }
  }
  return null;
}
function scopedHost(scope, entity) {
  const host = hostOf(entity);
  if (!host) return null;
  try {
    return scope.host(host) ? host : null;
  } catch {
    return null;
  }
}
function step(action, reason, within, requires, adapter = null, target = null) {
  return {
    action,
    reason,
    executes: false,
    within_gates: within,
    requires_gate: requires,
    adapter,
    target,
  };
}
function localStep(action, reason) {
  return step(action, reason, true, null);
}
function gatedStep(action, reason, adapter, target, gates) {
  if (!target)
    return localStep(
      "request human review before attribution",
      "No in-scope host is available for that suggestion. Nothing is executed.",
    );
  const mode = ADAPTERS[adapter]?.mode;
  if (!gates.network)
    return step(
      action,
      `${reason} Network is disabled, so this step is not executed.`,
      false,
      "network",
      adapter,
      target,
    );
  if (mode === "active" && !gates.active)
    return step(
      action,
      `${reason} Active mode is disabled, so this step is not executed.`,
      false,
      "active",
      adapter,
      target,
    );
  if (!gates.enabledAdapters.includes(adapter))
    return step(
      action,
      `${reason} The ${adapter} adapter is not enabled, so this step is not executed.`,
      false,
      "adapter",
      adapter,
      target,
    );
  return step(
    action,
    `${reason} The current gates allow this target, but this step is not executed.`,
    true,
    null,
    adapter,
    target,
  );
}
function nextSteps(claim, entities, assessments, assessed, gates, scope) {
  const steps = [];
  const push = (item) => {
    const key = `${item.action}|${item.requires_gate}|${item.target}`;
    if (
      steps.some(
        (existing) =>
          `${existing.action}|${existing.requires_gate}|${existing.target}` ===
          key,
      )
    )
      return;
    if (steps.length < 5) steps.push(item);
  };
  if (assessed === "weakened")
    push(
      localStep(
        "request human review before attribution",
        "Contradicting evidence weakened this hypothesis. This suggestion does not collect or record a decision.",
      ),
    );
  if (assessed === "supported-pending-review")
    push(
      localStep(
        "record an analyst decision before treating this hypothesis as confirmed",
        "Supporting evidence is pending review. supported-pending-review is not analyst-confirmed and is not a finding.",
      ),
    );
  if (claim === "current-activity" && assessed === "open") {
    for (const entity of entities) {
      const assessment = assessments.get(entity.id);
      if (assessment?.current_activity.status !== "not_confirmed") continue;
      push(
        gatedStep(
          "collect recent in-scope DNS evidence",
          "No recent direct observation confirms activity.",
          "dnsx",
          scopedHost(scope, entity),
          gates,
        ),
      );
    }
  }
  if (claim === "historical-existence" && assessed === "open") {
    for (const entity of entities) {
      const assessment = assessments.get(entity.id);
      if (assessment?.historical_existence.status !== "not_documented")
        continue;
      push(
        gatedStep(
          "collect historical certificate or archive evidence",
          "No stored certificate or archive record documents this name.",
          "crtsh",
          scopedHost(scope, entity),
          gates,
        ),
      );
    }
  }
  if (claim === "organization-attribution" && assessed === "open")
    push(
      localStep(
        "request human review before attribution",
        "Ownership is not verified. A shared IP, CDN, hosting ASN, name, or single source is not support. This suggestion does not collect.",
      ),
    );
  if (claim === "entity-association" && assessed === "open")
    push(
      localStep(
        "request human review before attribution",
        "A shared name or handle is not an identity match. This suggestion does not collect or confirm the hypothesis.",
      ),
    );
  if (!steps.length)
    push(
      localStep(
        "no collection suggested",
        "No further local suggestion. This does not run a collector.",
      ),
    );
  return steps;
}
function evaluateStored(store, scope, gates, row, options = {}) {
  const hypothesis = presentHypothesis(row);
  const entities = hypothesis.entity_ids.map((id) =>
    requireEntity(store, scope, id),
  );
  for (const id of hypothesis.evidence_ids) requireEvidence(store, scope, id);
  const resolution = inspectResolution(store);
  const decisions = loadDecisions(store);
  const links = linksFor(hypothesis.entity_ids, resolution);
  const gate = gatesOf(gates);
  const asOf = options.asOf;
  const assessments = new Map();
  const supporting = [];
  const contradicting = [];
  const missing = [];
  let allMet = entities.length > 0;
  for (const entity of entities) {
    let assessment = null;
    if (asOf === undefined)
      assessment = assessStored(store, scope, gate, entity);
    else {
      try {
        assessment = explainAsset(
          store,
          scope,
          gate,
          { entity_id: entity.id },
          { asOf },
        );
      } catch (error) {
        if (
          error.message !== "ASSET_NOT_IN_SCOPE" &&
          error.message !== "ENTITY_NOT_FOUND"
        )
          throw error;
      }
    }
    assessments.set(entity.id, assessment);
    const view = claimView(
      hypothesis.claim,
      entity,
      assessment,
      links,
      decisions,
    );
    supporting.push(...view.supporting);
    contradicting.push(...view.contradicting);
    missing.push(...view.missing);
    if (!view.met) allMet = false;
  }
  const cleanSupporting = dedupeHits(supporting);
  const cleanContradicting = dedupeHits(contradicting);
  let assessed = "open";
  if (cleanContradicting.length) assessed = "weakened";
  else if (allMet) assessed = "supported-pending-review";
  if (!DERIVED_STATUSES.includes(assessed))
    throw new Error("HYPOTHESIS_CONFIRMATION_FORBIDDEN");
  const supportPack = pack(cleanSupporting);
  const contradictPack = pack(cleanContradicting);
  const missingPack = pack(missing);
  return {
    hypothesis_id: hypothesis.id,
    statement: hypothesis.statement,
    claim: hypothesis.claim,
    assessed_status: assessed,
    analyst_id: hypothesis.analyst_id,
    analyst_reason: hypothesis.analyst_reason,
    supporting: supportPack.items,
    supporting_truncated: supportPack.truncated,
    contradicting: contradictPack.items,
    contradicting_truncated: contradictPack.truncated,
    missing: missingPack.items,
    missing_truncated: missingPack.truncated,
    next_steps: nextSteps(
      hypothesis.claim,
      entities,
      assessments,
      assessed,
      gate,
      scope,
    ),
    ...localFlags(),
    rules: HYPOTHESIS_RULES,
    limitations: HYPOTHESIS_LIMITATIONS,
    hypothesis,
  };
}
export function initializeCases(db) {
  const version = db.prepare("PRAGMA user_version").get().user_version;
  if (version > SCHEMA_VERSION) throw new Error("DATABASE_VERSION_TOO_NEW");
  db.exec(`
    CREATE TABLE IF NOT EXISTS hypotheses(
      id TEXT PRIMARY KEY,
      statement TEXT NOT NULL,
      claim TEXT NOT NULL,
      status TEXT NOT NULL,
      case_id TEXT,
      note TEXT NOT NULL,
      entity_ids TEXT NOT NULL,
      evidence_ids TEXT NOT NULL,
      closed_at TEXT,
      analyst_id TEXT,
      analyst_reason TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      CHECK(claim IN ('current-activity','historical-existence','organization-attribution','entity-association')),
      CHECK(status IN ('open','supported-pending-review','weakened','rejected','analyst-confirmed')),
      CHECK(
        (status IN ('open','supported-pending-review','weakened')
          AND closed_at IS NULL AND analyst_id IS NULL AND analyst_reason IS NULL)
        OR (status IN ('rejected','analyst-confirmed')
          AND closed_at IS NOT NULL AND analyst_id IS NOT NULL AND analyst_reason IS NOT NULL)));
    CREATE INDEX IF NOT EXISTS hypotheses_case ON hypotheses(case_id, id);
    CREATE TABLE IF NOT EXISTS cases(
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS case_members(
      id TEXT PRIMARY KEY,
      case_id TEXT NOT NULL REFERENCES cases(id),
      kind TEXT NOT NULL,
      ref TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL,
      CHECK(kind IN ('investigation','target','hypothesis','decision','note')));
    CREATE INDEX IF NOT EXISTS case_members_case ON case_members(case_id, kind);`);
}
function members(store, caseId) {
  return store.db
    .prepare(
      "SELECT id, kind, ref, body, created_at FROM case_members WHERE case_id=? ORDER BY created_at, id",
    )
    .all(caseId);
}
function caseEntityIds(store, hypothesisRows, targets) {
  const ids = new Set(
    hypothesisRows.flatMap((row) => presentHypothesis(row).entity_ids),
  );
  for (const target of targets)
    for (const row of store.db
      .prepare("SELECT id FROM entities WHERE value=?")
      .all(target))
      ids.add(row.id);
  return ids;
}
function summarizeCase(store, _scope, row) {
  const linked = members(store, row.id);
  const investigations = linked
    .filter((item) => item.kind === "investigation")
    .map((item) => item.ref);
  const targets = linked
    .filter((item) => item.kind === "target")
    .map((item) => item.ref);
  const notes = linked
    .filter((item) => item.kind === "note")
    .map((item) => item.body);
  const decisionIds = linked
    .filter((item) => item.kind === "decision")
    .map((item) => item.ref);
  const hypotheses = store.db
    .prepare("SELECT * FROM hypotheses WHERE case_id=? ORDER BY id")
    .all(row.id)
    .map(presentHypothesis);
  const entityIds = caseEntityIds(
    store,
    store.db.prepare("SELECT * FROM hypotheses WHERE case_id=?").all(row.id),
    targets,
  );
  const resolution = inspectResolution(store);
  const candidates = linksFor([...entityIds], resolution).filter(
    (link) => link.status === "candidate",
  );
  return {
    id: row.id,
    title: row.title,
    summary: row.summary,
    investigations,
    targets,
    notes,
    decision_ids: decisionIds,
    hypotheses,
    counts: {
      investigations: investigations.length,
      targets: targets.length,
      hypotheses: hypotheses.length,
      decisions: decisionIds.length,
      notes: notes.length,
      candidates: candidates.length,
    },
    ...localFlags(),
    limitations: CASE_LIMITATIONS,
    entityIds,
    resolution,
  };
}
export function createHypothesis(store, scope, input) {
  const source = input && typeof input === "object" ? { ...input } : input;
  if (source && typeof source === "object") {
    source.statement = trimText(source.statement);
    source.note = trimText(source.note);
    if (Array.isArray(source.entity_ids))
      source.entity_ids = unique(source.entity_ids);
    if (Array.isArray(source.evidence_ids))
      source.evidence_ids = unique(source.evidence_ids);
  }
  const data = parseInput(CreateHypothesisInput, source);
  if (!scope?.host) throw new Error("INVALID_INPUT");
  requireCase(store, data.case_id);
  for (const id of data.entity_ids) requireEntity(store, scope, id);
  for (const id of data.evidence_ids) requireEvidence(store, scope, id);
  const now = new Date().toISOString();
  const row = {
    id: randomUUID(),
    statement: data.statement,
    claim: data.claim,
    status: "open",
    case_id: data.case_id ?? null,
    note: data.note,
    entity_ids: JSON.stringify(data.entity_ids),
    evidence_ids: JSON.stringify(data.evidence_ids),
    closed_at: null,
    analyst_id: null,
    analyst_reason: null,
    created_at: now,
    updated_at: now,
  };
  store.db
    .prepare(`INSERT INTO hypotheses VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      row.id,
      row.statement,
      row.claim,
      row.status,
      row.case_id,
      row.note,
      row.entity_ids,
      row.evidence_ids,
      row.closed_at,
      row.analyst_id,
      row.analyst_reason,
      row.created_at,
      row.updated_at,
    );
  if (row.case_id)
    store.db
      .prepare("INSERT INTO case_members VALUES(?,?,?,?,?,?)")
      .run(randomUUID(), row.case_id, "hypothesis", row.id, "", now);
  return hypothesisResult(row);
}
export function updateHypothesis(store, scope, input) {
  const source = input && typeof input === "object" ? { ...input } : input;
  if (source && typeof source === "object") {
    source.statement = trimText(source.statement);
    source.note = trimText(source.note);
    if (Array.isArray(source.entity_ids))
      source.entity_ids = unique(source.entity_ids);
    if (Array.isArray(source.evidence_ids))
      source.evidence_ids = unique(source.evidence_ids);
  }
  const data = parseInput(UpdateHypothesisInput, source);
  const current = loadHypothesis(store, data.id);
  if (closedStatus(current.status)) throw new Error("HYPOTHESIS_CLOSED");
  const next = presentHypothesis(current);
  if (data.statement !== undefined) next.statement = data.statement;
  if (data.claim !== undefined) next.claim = data.claim;
  if (data.note !== undefined) next.note = data.note;
  if (data.entity_ids !== undefined) next.entity_ids = data.entity_ids;
  if (data.evidence_ids !== undefined) next.evidence_ids = data.evidence_ids;
  if (data.case_id !== undefined) next.case_id = data.case_id;
  requireCase(store, next.case_id);
  for (const id of next.entity_ids) requireEntity(store, scope, id);
  for (const id of next.evidence_ids) requireEvidence(store, scope, id);
  const now = new Date().toISOString();
  store.db
    .prepare(
      `UPDATE hypotheses SET statement=?, claim=?, case_id=?, note=?, entity_ids=?, evidence_ids=?, updated_at=? WHERE id=?`,
    )
    .run(
      next.statement,
      next.claim,
      next.case_id,
      next.note,
      JSON.stringify(next.entity_ids),
      JSON.stringify(next.evidence_ids),
      now,
      next.id,
    );
  if (data.case_id && data.case_id !== current.case_id) {
    store.db
      .prepare("DELETE FROM case_members WHERE kind='hypothesis' AND ref=?")
      .run(next.id);
    store.db
      .prepare("INSERT INTO case_members VALUES(?,?,?,?,?,?)")
      .run(randomUUID(), data.case_id, "hypothesis", next.id, "", now);
  }
  if (data.case_id === null)
    store.db
      .prepare("DELETE FROM case_members WHERE kind='hypothesis' AND ref=?")
      .run(next.id);
  return hypothesisResult(loadHypothesis(store, next.id));
}
export function closeHypothesis(store, input) {
  const source = input && typeof input === "object" ? { ...input } : input;
  if (source && typeof source === "object") {
    source.reason = trimText(source.reason);
    source.analyst_id = trimText(source.analyst_id);
  }
  const data = parseInput(CloseHypothesisInput, source);
  const current = loadHypothesis(store, data.id);
  if (closedStatus(current.status)) throw new Error("HYPOTHESIS_CLOSED");
  const now = new Date().toISOString();
  store.db
    .prepare(
      `UPDATE hypotheses SET status=?, closed_at=?, analyst_id=?, analyst_reason=?, updated_at=? WHERE id=?`,
    )
    .run(data.status, now, data.analyst_id, data.reason, now, data.id);
  const saved = loadHypothesis(store, data.id);
  if (saved.status !== data.status || saved.analyst_id !== data.analyst_id)
    throw new Error("HYPOTHESIS_CONFIRMATION_FORBIDDEN");
  return hypothesisResult(saved);
}
export function listHypotheses(store, input = {}) {
  const data = parseInput(ListHypothesesInput, input);
  let rows = store.db
    .prepare("SELECT * FROM hypotheses ORDER BY id")
    .all()
    .map(presentHypothesis);
  if (data.case_id) rows = rows.filter((row) => row.case_id === data.case_id);
  if (data.status) rows = rows.filter((row) => row.status === data.status);
  const pageStart = data.cursor
    ? rows.filter((row) => row.id > data.cursor)
    : rows;
  const page = pageStart.slice(0, data.limit);
  return {
    items: page,
    returned: page.length,
    limit: data.limit,
    next_cursor: pageStart.length > data.limit ? page.at(-1).id : null,
    total: rows.length,
    ...localFlags(),
    rules: HYPOTHESIS_RULES,
  };
}
export function readHypothesisAssessment(
  store,
  scope,
  gates = {},
  id,
  options = {},
) {
  const row = loadHypothesis(store, id);
  const before = row.status;
  const evaluation = evaluateStored(store, scope, gates, row, options);
  const after = store.db
    .prepare("SELECT status FROM hypotheses WHERE id=?")
    .get(id).status;
  if (after !== before) throw new Error("HYPOTHESIS_CONFIRMATION_FORBIDDEN");
  return evaluation;
}
export function evaluateHypothesis(
  store,
  scope,
  gates = {},
  input = {},
  options = {},
) {
  const data = parseInput(EvaluateHypothesisInput, input);
  const row = loadHypothesis(store, data.id);
  const evaluation = evaluateStored(store, scope, gates, row, options);
  const closed = closedStatus(row.status);
  let statusUpdated = false;
  let stored = row.status;
  if (!closed && row.status !== evaluation.assessed_status) {
    const now = new Date().toISOString();
    store.db
      .prepare("UPDATE hypotheses SET status=?, updated_at=? WHERE id=?")
      .run(evaluation.assessed_status, now, row.id);
    stored = evaluation.assessed_status;
    statusUpdated = true;
  }
  if (stored === "analyst-confirmed" && !row.analyst_id)
    throw new Error("HYPOTHESIS_CONFIRMATION_FORBIDDEN");
  if (!closed && ANALYST_CLOSURES.includes(stored))
    throw new Error("HYPOTHESIS_CONFIRMATION_FORBIDDEN");
  return {
    hypothesis_id: evaluation.hypothesis_id,
    statement: evaluation.statement,
    claim: evaluation.claim,
    stored_status: stored,
    assessed_status: evaluation.assessed_status,
    confirmed: stored === "analyst-confirmed",
    finding: false,
    analyst_id: evaluation.analyst_id,
    analyst_reason: evaluation.analyst_reason,
    supporting: evaluation.supporting,
    supporting_truncated: evaluation.supporting_truncated,
    contradicting: evaluation.contradicting,
    contradicting_truncated: evaluation.contradicting_truncated,
    missing: evaluation.missing,
    missing_truncated: evaluation.missing_truncated,
    next_steps: evaluation.next_steps,
    status_updated: statusUpdated,
    ...localFlags(),
    rules: evaluation.rules,
    limitations: evaluation.limitations,
  };
}
function insertMember(store, caseId, kind, ref, body, at) {
  store.db
    .prepare("INSERT INTO case_members VALUES(?,?,?,?,?,?)")
    .run(randomUUID(), caseId, kind, ref, body, at);
}
export function createCase(store, scope, input) {
  const source = input && typeof input === "object" ? { ...input } : input;
  if (source && typeof source === "object") {
    source.title = trimText(source.title);
    source.summary = trimText(source.summary);
    if (Array.isArray(source.notes))
      source.notes = source.notes.map((item) => trimText(item));
  }
  const data = parseInput(CreateCaseInput, source);
  if (!scope?.host) throw new Error("INVALID_INPUT");
  const investigations = unique(
    data.investigations.map((item) => assertInvestigation(store, item)),
  );
  const targets = unique(data.targets.map((item) => assertTarget(scope, item)));
  const hypothesisIds = unique(data.hypothesis_ids);
  const decisionIds = unique(data.decision_ids);
  for (const id of hypothesisIds) {
    const row = loadHypothesis(store, id);
    if (row.case_id) throw new Error("HYPOTHESIS_CASE_CONFLICT");
  }
  for (const id of decisionIds) requireDecision(store, scope, id);
  const now = new Date().toISOString();
  const id = randomUUID();
  store.db.exec("BEGIN IMMEDIATE");
  try {
    store.db
      .prepare("INSERT INTO cases VALUES(?,?,?,?,?)")
      .run(id, data.title, data.summary, now, now);
    for (const ref of investigations)
      insertMember(store, id, "investigation", ref, "", now);
    for (const ref of targets) insertMember(store, id, "target", ref, "", now);
    for (const ref of hypothesisIds) {
      insertMember(store, id, "hypothesis", ref, "", now);
      store.db
        .prepare("UPDATE hypotheses SET case_id=?, updated_at=? WHERE id=?")
        .run(id, now, ref);
    }
    for (const ref of decisionIds)
      insertMember(store, id, "decision", ref, "", now);
    for (const note of data.notes)
      insertMember(store, id, "note", randomUUID(), note, now);
    store.db.exec("COMMIT");
  } catch (error) {
    store.db.exec("ROLLBACK");
    throw error;
  }
  return caseSummary(store, scope, { case_id: id });
}
export function listCases(store, input = {}) {
  const data = parseInput(ListCasesInput, input);
  const rows = store.db.prepare("SELECT * FROM cases ORDER BY id").all();
  const pageStart = data.cursor
    ? rows.filter((row) => row.id > data.cursor)
    : rows;
  const page = pageStart.slice(0, data.limit).map((row) => ({
    id: row.id,
    title: row.title,
    summary: row.summary,
    hypothesis_count: store.db
      .prepare("SELECT COUNT(*) AS n FROM hypotheses WHERE case_id=?")
      .get(row.id).n,
    created_at: row.created_at,
    updated_at: row.updated_at,
  }));
  return {
    items: page,
    returned: page.length,
    limit: data.limit,
    next_cursor: pageStart.length > data.limit ? page.at(-1).id : null,
    total: rows.length,
    ...localFlags(),
  };
}
export function caseSummary(store, scope, input = {}) {
  const data = parseInput(CaseIdInput, input);
  const summary = summarizeCase(store, scope, loadCaseRow(store, data.case_id));
  return {
    id: summary.id,
    title: summary.title,
    summary: summary.summary,
    investigations: summary.investigations,
    targets: summary.targets,
    notes: summary.notes,
    decision_ids: summary.decision_ids,
    hypotheses: summary.hypotheses,
    counts: summary.counts,
    ...localFlags(),
    limitations: summary.limitations,
  };
}
function markdownList(lines) {
  return lines.length ? lines.map((line) => `- ${line}`).join("\n") : "- None.";
}
function reportSections(store, scope, gates, row) {
  const summary = summarizeCase(store, scope, row);
  const explicitDecisions = new Set(summary.decision_ids);
  const subjectIds = summary.entityIds;
  const accepted = [];
  for (const decision of store.db
    .prepare(
      `SELECT id, subject_kind, subject_id, decision, reason, analyst_id, recorded_at
       FROM review_decisions ORDER BY recorded_at, id`,
    )
    .all()) {
    if (decision.decision !== "accept") continue;
    const tied =
      explicitDecisions.has(decision.id) || subjectIds.has(decision.subject_id);
    if (!tied) continue;
    accepted.push({
      kind: "review-decision",
      id: decision.id,
      subject_kind: decision.subject_kind,
      subject_id: decision.subject_id,
      decision: "accept",
      reason: decision.reason,
      analyst_id: decision.analyst_id,
      recorded_at: decision.recorded_at,
      finding: false,
    });
  }
  const closures = summary.hypotheses
    .filter((item) => item.status === "analyst-confirmed")
    .map((item) => ({
      kind: "hypothesis-closure",
      hypothesis_id: item.id,
      statement: item.statement,
      analyst_id: item.analyst_id,
      reason: item.analyst_reason,
      closed_at: item.closed_at,
      finding: false,
    }));
  const candidates = linksFor([...summary.entityIds], summary.resolution)
    .filter((link) => link.status === "candidate")
    .slice(0, MAX_LIST)
    .map((link) => ({
      kind: "candidate-link",
      id: link.id,
      left_id: link.left_id,
      right_id: link.right_id,
      basis: link.basis,
      status: "candidate",
      finding: false,
      note: "A shared name or handle is not a confirmed identity.",
    }));
  const hypotheses = summary.hypotheses.map((item) => {
    const stored = store.db
      .prepare("SELECT * FROM hypotheses WHERE id=?")
      .get(item.id);
    const evaluation = evaluateStored(store, scope, gates, stored);
    return {
      kind: "hypothesis",
      ...item,
      assessed_status: evaluation.assessed_status,
    };
  });
  const limitations = [...CASE_LIMITATIONS];
  const resolverConfirmed = linksFor(
    [...summary.entityIds],
    summary.resolution,
  ).filter((link) => link.status === "confirmed").length;
  if (resolverConfirmed)
    limitations.push(
      `${resolverConfirmed} resolver-confirmed identity link(s) are omitted from the confirmed section because they are not analyst decisions.`,
    );
  return {
    summary,
    sections: {
      confirmed_analyst_decisions: [...accepted, ...closures],
      candidates,
      hypotheses,
      limitations,
    },
  };
}
export function caseReport(store, scope, gates = {}, input = {}) {
  const data = parseInput(CaseReportInput, input);
  const built = reportSections(
    store,
    scope,
    gates,
    loadCaseRow(store, data.case_id),
  );
  const sections = built.sections;
  const confirmedLines = sections.confirmed_analyst_decisions.map((item) =>
    item.kind === "review-decision"
      ? `Review accept ${item.id} on ${item.subject_kind} ${item.subject_id} by ${item.analyst_id}: ${item.reason}`
      : `Analyst closed hypothesis ${item.hypothesis_id} as analyst-confirmed. Reason: ${item.reason}`,
  );
  const candidateLines = sections.candidates.map(
    (item) => `Candidate ${item.id} (${item.basis}). ${item.note}`,
  );
  const hypothesisLines = sections.hypotheses.map(
    (item) =>
      `${item.statement} — stored ${item.status}, assessed ${item.assessed_status}. Not a finding.`,
  );
  const markdown = [
    `# Case: ${built.summary.title}`,
    "",
    built.summary.summary,
    "",
    "## Confirmed analyst decisions",
    "",
    "These are stored analyst decisions. An accept is not proof of identity, ownership, or phishing, and it is not a finding produced by this tool.",
    "",
    markdownList(confirmedLines),
    "",
    "## Candidates",
    "",
    "Candidate links only. A shared name or handle is not a confirmed identity.",
    "",
    markdownList(candidateLines),
    "",
    "## Hypotheses",
    "",
    "A hypothesis is not a finding. analyst-confirmed is an explicit analyst decision and is still not a tool-confirmed finding.",
    "",
    markdownList(hypothesisLines),
    "",
    "## Limitations",
    "",
    markdownList(sections.limitations),
    "",
  ].join("\n");
  return {
    case_id: built.summary.id,
    title: built.summary.title,
    format: data.format,
    sections,
    markdown,
    ...localFlags(),
  };
}
const STIX_TYPE_ORDER = [
  "identity",
  "domain-name",
  "ipv4-addr",
  "ipv6-addr",
  "email-addr",
  "url",
  "x509-certificate",
  "indicator",
  "observed-data",
  "relationship",
  "opinion",
  "note",
];
function sameExceptTime(left, right) {
  const rest = (object) => {
    const copy = { ...object };
    delete copy.created;
    delete copy.modified;
    return copy;
  };
  return JSON.stringify(rest(left)) === JSON.stringify(rest(right));
}
function mergeBundles(exported) {
  const byId = new Map();
  let truncated = false;
  for (const item of exported) {
    truncated = truncated || item.truncated;
    for (const object of item.bundle.objects) {
      const previous = byId.get(object.id);
      if (!previous) {
        byId.set(object.id, object);
        continue;
      }
      if (JSON.stringify(previous) === JSON.stringify(object)) continue;
      if (!sameExceptTime(previous, object))
        throw new Error("CASE_STIX_CONFLICT");
      const created = [previous.created, object.created].sort()[0];
      const modified = [previous.modified, object.modified].sort().at(-1);
      byId.set(object.id, {
        ...previous,
        created,
        modified: modified < created ? created : modified,
      });
    }
  }
  return { objects: [...byId.values()], truncated };
}
export function exportCaseStix(store, scope, input = {}) {
  const data = parseInput(CaseIdInput, input);
  const summary = caseSummary(store, scope, data);
  const investigations = summary.investigations.length
    ? summary.investigations
    : [undefined];
  const targets = summary.targets.length ? summary.targets : [undefined];
  const exported = [];
  for (const investigation of investigations)
    for (const target of targets)
      exported.push(
        exportStix(store, scope, {
          ...(investigation ? { investigation } : {}),
          ...(target ? { target } : {}),
        }),
      );
  const merged = mergeBundles(exported);
  const tool = merged.objects.find(
    (object) =>
      object.type === "identity" && object.identity_class === "system",
  );
  if (!tool) throw new Error("STIX_EXPORT_INVALID");
  const hypotheses = store.db
    .prepare("SELECT * FROM hypotheses WHERE case_id=? ORDER BY id")
    .all(data.case_id)
    .map(presentHypothesis);
  for (const hypothesis of hypotheses) {
    const created =
      stixTime(hypothesis.created_at) ?? stixTime(hypothesis.updated_at);
    const modifiedRaw = stixTime(hypothesis.updated_at) ?? created;
    if (!created || !modifiedRaw) throw new Error("STIX_EXPORT_INVALID");
    const modified = modifiedRaw < created ? created : modifiedRaw;
    merged.objects.push({
      type: "note",
      spec_version: "2.1",
      id: stixId("note", `hypothesis|${hypothesis.id}`),
      created,
      modified,
      created_by_ref: tool.id,
      labels: ["hypothesis"],
      abstract: `Hypothesis (${hypothesis.status}); not a finding`,
      content: [
        `Hypothesis: ${hypothesis.statement}`,
        `Claim: ${hypothesis.claim}.`,
        `Stored status: ${hypothesis.status}.`,
        "This note is not an indicator and not a finding.",
        hypothesis.status === "analyst-confirmed"
          ? "An analyst recorded analyst-confirmed. That is an analyst decision, not a confirmation produced by this exporter."
          : "This hypothesis is not analyst-confirmed.",
      ].join(" "),
      authors: ["OSINT POWER"],
      object_refs: [tool.id],
    });
  }
  merged.objects.sort(
    (left, right) =>
      STIX_TYPE_ORDER.indexOf(left.type) -
        STIX_TYPE_ORDER.indexOf(right.type) || left.id.localeCompare(right.id),
  );
  const bundle = {
    type: "bundle",
    id: stixId(
      "bundle",
      `case|${data.case_id}|${merged.objects
        .map((object) => object.id)
        .sort()
        .join("|")}`,
    ),
    objects: merged.objects,
  };
  const errors = validateStixBundle(bundle);
  if (errors.length) throw new Error("STIX_EXPORT_INVALID");
  const tally = (type) =>
    bundle.objects.filter((object) => object.type === type).length;
  const indicators = bundle.objects.filter(
    (object) => object.type === "indicator",
  );
  if (
    indicators.some(
      (object) =>
        object.labels?.includes("hypothesis") ||
        hypotheses.some((item) => object.description?.includes(item.statement)),
    )
  )
    throw new Error("STIX_EXPORT_INVALID");
  const investigationLabel =
    summary.investigations.length === 0
      ? null
      : summary.investigations.length === 1
        ? summary.investigations[0]
        : summary.investigations.join(", ");
  const targetLabel =
    summary.targets.length === 0
      ? null
      : summary.targets.length === 1
        ? summary.targets[0]
        : summary.targets.join(", ");
  return {
    format: "application/stix+json;version=2.1",
    read_only: true,
    bundle,
    validation: { valid: true, error_count: 0 },
    filters: {
      investigation: investigationLabel,
      target: targetLabel,
      review_status: "any",
      since: null,
      until: null,
    },
    counts: {
      objects: bundle.objects.length,
      identities: tally("identity"),
      scos: bundle.objects.filter((object) =>
        [
          "domain-name",
          "ipv4-addr",
          "ipv6-addr",
          "email-addr",
          "url",
          "x509-certificate",
        ].includes(object.type),
      ).length,
      indicators: indicators.length,
      observed_data: tally("observed-data"),
      relationships: tally("relationship"),
      notes: tally("note"),
      opinions: tally("opinion"),
      entities_included: exported.reduce(
        (sum, item) => sum + item.counts.entities_included,
        0,
      ),
      entities_omitted_out_of_scope: exported.reduce(
        (sum, item) => sum + item.counts.entities_omitted_out_of_scope,
        0,
      ),
      suspected_indicators: indicators.filter((object) =>
        object.labels?.includes("suspected"),
      ).length,
    },
    truncated: merged.truncated,
    limitations: [...STIX_LIMITATIONS, ...CASE_STIX_NOTES],
  };
}
