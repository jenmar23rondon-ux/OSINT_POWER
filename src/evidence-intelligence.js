import { z } from "zod";
import { ADAPTERS } from "./adapters.js";
import {
  INDEPENDENCE_NOTE,
  independentGroups,
  inspectResolution,
  loadDecisions,
} from "./review.js";
import { domain } from "./scope.js";
import { sourceFamily } from "./state.js";

const WINDOW_MS = 30 * 86400000;
const MAX_EVIDENCE = 40;
const MAX_CONFLICTS = 20;
const ACTIVITY_SOURCES = new Set(["dnsx", "httpx", "naabu", "mx"]);
const CDN_MARKERS = new Set([
  "cloudflare",
  "akamai",
  "fastly",
  "cloudfront",
  "incapsula",
  "sucuri",
  "edgecast",
]);
const NEGATIVE_STATUS = new Set([
  "0",
  "nxdomain",
  "failed",
  "refused",
  "unreachable",
]);

export const ASSET_TYPES = ["domain", "ip", "asn", "url", "technology"];
export const ASSESSMENT_RULES = [
  "Historical certificate and archive records can document a name. They do not confirm current activity.",
  "Current activity requires a recent DNS, HTTP, MX, or port observation. Disagreeing recent observations are contradicted.",
  "Ownership is verified only by two independent in-scope organization-domain assertions that are not infrastructure.",
  "A shared IP, a CDN, or a hosting or registry ASN never verifies ownership.",
  "Duplicate, mirrored, same-upstream, and same-run sources count once. A shared name or handle is never an identity match.",
  "Analyst decisions are reported as stored. An accept does not verify ownership or identity.",
  "The next action is a suggestion inside the current scope, network, active-mode, and adapter gates. It executes nothing.",
];
export const ASSESSMENT_LIMITATIONS = [
  "Assessments are heuristics over stored rows. They are not probabilities, calibrated confidence, or proof of control.",
  "A verified organization-domain assertion is not proof of legal ownership, and it never comes from a shared address, CDN, or hosting ASN.",
  "Historical records document past names and captures. They do not show that a service is active now.",
  "Candidate identity links stay candidates. A hypothesis is not a confirmed finding.",
  "Suggestions do not collect, scan, record an analyst decision, or change scope.",
  "Returned evidence identifiers are capped. The status itself is computed from the full stored set.",
];

const hashId = z.string().regex(/^[a-f0-9]{64}$/);
const text = z.string();
const count = z.number().int().nonnegative();
const evidenceRef = z
  .object({
    evidence_ids: z.array(hashId),
    evidence_truncated: z.boolean(),
  })
  .strict();
const decision = z
  .object({
    id: text,
    subject_kind: z.enum(["entity", "finding"]),
    subject_id: hashId,
    decision: z.enum(["accept", "reject", "needs-more-evidence"]),
    reason: text,
    analyst_id: text,
    recorded_at: text,
  })
  .strict();
const assetIdentity = z
  .object({
    status: z.enum(["candidate", "confirmed", "not_applicable"]),
    candidate_links: count,
    confirmed_links: count,
    note: text,
  })
  .strict();
const linkSummary = z
  .object({
    id: hashId,
    status: z.enum(["candidate", "confirmed"]),
    basis: text,
    blocked_reason: text.nullable(),
    shared_names: z.array(text),
    shared_handles: z.array(text),
    shared_identifiers: z.array(text),
    independent_corroboration: count,
  })
  .strict();
const nextAction = z
  .object({
    action: text,
    reason: text,
    executes: z.literal(false),
    within_gates: z.literal(true),
    adapter: text.nullable(),
    target: text.nullable(),
  })
  .strict();
export const AssetAssessment = z
  .object({
    entity_id: hashId,
    type: z.enum(ASSET_TYPES),
    value: text,
    historical_existence: evidenceRef.extend({
      status: z.enum(["documented", "not_documented"]),
    }),
    current_activity: evidenceRef.extend({
      status: z.enum(["confirmed", "not_confirmed", "contradicted"]),
    }),
    ownership: evidenceRef.extend({
      status: z.enum(["verified", "unverified", "contradicted"]),
      independent_sources: count,
      basis: text,
    }),
    conflicts: z.array(
      z
        .object({
          kind: z.enum(["historical_versus_recent", "attribute_disagreement"]),
          attribute: text,
          summary: text,
          evidence_ids: z.array(hashId),
          evidence_truncated: z.boolean(),
          independent_disagreement: z.boolean(),
        })
        .strict(),
    ),
    source_independence: z
      .object({
        observations: count,
        independent_groups: count,
        note: text,
      })
      .strict(),
    review: z
      .object({
        status: z.enum([
          "unreviewed",
          "accept",
          "reject",
          "needs-more-evidence",
        ]),
        current_decision: decision.nullable(),
        history_count: count,
      })
      .strict(),
    identity: assetIdentity,
    next_action: nextAction,
  })
  .strict();
const identityResolution = z
  .object({
    candidates: z.array(linkSummary),
    confirmed: z.array(linkSummary),
    candidate_count: count,
    confirmed_count: count,
    returned_candidates: count,
    returned_confirmed: count,
    note: text,
  })
  .strict();
const pageFields = {
  window_days: z.literal(30),
  executes: z.literal(false),
  mutation: z.literal(false),
  network: z.literal(false),
  calibration: z.literal("heuristic_not_probability"),
  sampling: z.literal("complete_for_stored_rows"),
  rules: z.array(text),
  limitations: z.array(text),
  identity_resolution: identityResolution,
};
export const AssessResult = z
  .object({
    items: z.array(AssetAssessment),
    returned: count,
    limit: count,
    next_cursor: hashId.nullable(),
    total: count,
    ...pageFields,
  })
  .strict();
const challengePoint = evidenceRef.extend({
  kind: z.enum([
    "conflicting-activity",
    "negative-activity",
    "host-context",
    "historical",
    "stale",
    "future-dated",
    "http-error-response",
    "conflicting-attribution",
    "shared-infrastructure",
    "insufficient-attribution",
  ]),
  explanation: text,
});
const challengeDimension = z
  .object({
    disposition: z.enum(["supported-pending-review", "unresolved", "disputed"]),
    supporting: evidenceRef,
    counterpoints: z.array(challengePoint),
  })
  .strict();
export const ExplainAssetResult = AssetAssessment.extend({
  ...pageFields,
  challenge: z
    .object({
      activity: challengeDimension,
      attribution: challengeDimension,
    })
    .strict()
    .optional(),
});
export const AssessInput = z
  .object({
    type: z.enum(ASSET_TYPES).optional(),
    limit: z.number().int().min(1).max(100).default(25),
    cursor: hashId.optional(),
  })
  .strict();
export const ExplainAssetInput = z
  .object({
    entity_id: hashId,
    challenge: z.boolean().default(false),
  })
  .strict();

function parseInput(schema, input) {
  const result = schema.safeParse(input ?? {});
  if (!result.success) throw new Error("INVALID_INPUT");
  return result.data;
}
function unique(values) {
  return [...new Set(values)].sort();
}
function pack(ids) {
  const all = unique(ids);
  return {
    evidence_ids: all.slice(0, MAX_EVIDENCE),
    evidence_truncated: all.length > MAX_EVIDENCE,
  };
}
function tokens(value) {
  return String(value ?? "")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}
function cdnToken(value) {
  return tokens(value).some((token) => CDN_MARKERS.has(token));
}
function hostnameOf(value) {
  try {
    return new URL(value).hostname.replace(/^\[|\]$/g, "").toLowerCase();
  } catch {
    return "";
  }
}
function inScopeHost(scope, value) {
  try {
    return scope.host(value);
  } catch {
    return false;
  }
}
function orgDomain(value, scope) {
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    const name = domain(value);
    return { org: name, foreign: !scope.host(name) };
  } catch {
    return null;
  }
}
function readAsOf(options) {
  const value = options.asOf ?? Date.now();
  const parsed = typeof value === "number" ? value : Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error("INVALID_INPUT");
  return parsed;
}
function readGates(gates = {}) {
  return {
    network: gates.network === true,
    active: gates.active === true,
    enabledAdapters: Array.isArray(gates.enabledAdapters)
      ? gates.enabledAdapters
      : [],
  };
}
function isHistorical(obs) {
  if (obs.evidence?.historical === true) return true;
  const family = sourceFamily(obs.source, obs.evidence);
  return family === "certificate_transparency" || family === "web_archive";
}
function isRecent(obs, asOf) {
  const at = Date.parse(obs.timestamp);
  if (!Number.isFinite(at)) return false;
  const age = asOf - at;
  return age >= 0 && age <= WINDOW_MS;
}
function statusToken(obs) {
  const value = obs.evidence?.status;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "string" && value.trim())
    return value.trim().toLowerCase();
  return null;
}
function activityPolarity(obs) {
  if (!ACTIVITY_SOURCES.has(obs.source) || isHistorical(obs)) return null;
  const token = statusToken(obs);
  if (obs.source === "dnsx" || obs.source === "mx") {
    if (
      token &&
      (NEGATIVE_STATUS.has(token) || token === "none" || token === "nodata")
    )
      return "negative";
    if (obs.evidence?.resolved === false) return "negative";
    if (obs.source === "mx" && Array.isArray(obs.evidence?.mx))
      return obs.evidence.mx.length ? "positive" : "negative";
    if (
      obs.type === "domain" ||
      obs.type === "ip" ||
      obs.type === "mail_domain"
    )
      return "positive";
    return null;
  }
  if (obs.source === "httpx") {
    if (obs.evidence?.failed === true) return "negative";
    if (!token || NEGATIVE_STATUS.has(token)) return "negative";
    const code = Number(token);
    if (code >= 100 && code <= 599) return "positive";
    return "negative";
  }
  if (obs.source === "naabu") {
    if (obs.evidence?.open === false || token === "closed") return "negative";
    return "positive";
  }
  return null;
}
function observationIsCdn(obs) {
  if (obs.evidence?.verification === "cdn") return true;
  const tech = Array.isArray(obs.evidence?.technology)
    ? obs.evidence.technology
    : [];
  return (
    tech.some((item) => cdnToken(item)) || cdnToken(obs.evidence?.provider)
  );
}
function sharedAddresses(observations) {
  const hosts = new Map();
  for (const obs of observations) {
    if (obs.type !== "ip") continue;
    let host = "";
    try {
      host = obs.evidence?.host ? domain(obs.evidence.host) : "";
    } catch {
      host = String(obs.evidence?.host ?? "")
        .trim()
        .toLowerCase();
    }
    if (!host) continue;
    const set = hosts.get(obs.value) ?? new Set();
    set.add(host);
    hosts.set(obs.value, set);
  }
  const shared = new Set();
  for (const [ip, names] of hosts) if (names.size > 1) shared.add(ip);
  return shared;
}
function decorate(store, resolution) {
  const times = new Map(
    store.db
      .prepare("SELECT id, timestamp FROM observations")
      .all()
      .map((row) => [row.id, row.timestamp]),
  );
  return resolution.observations.map((obs) => {
    const entity = resolution.entitiesById.get(obs.entity_id);
    return {
      ...obs,
      timestamp: times.get(obs.id) ?? "",
      type: entity?.type,
      value: entity?.value,
    };
  });
}
function entityInScope(scope, entity, observations) {
  const mine = observations.filter((obs) => obs.entity_id === entity.id);
  if (entity.type === "domain") return inScopeHost(scope, entity.value);
  if (entity.type === "url")
    return inScopeHost(scope, hostnameOf(entity.value));
  if (entity.type === "ip") {
    if (inScopeHost(scope, entity.value)) return true;
    return mine.some(
      (obs) => obs.evidence?.host && inScopeHost(scope, obs.evidence.host),
    );
  }
  if (entity.type === "asn") {
    return mine.some(
      (obs) =>
        (obs.evidence?.host && inScopeHost(scope, obs.evidence.host)) ||
        (typeof obs.evidence?.ip === "string" &&
          inScopeHost(scope, obs.evidence.ip)),
    );
  }
  if (entity.type === "technology") {
    return mine.some(
      (obs) =>
        obs.evidence?.company && inScopeHost(scope, obs.evidence.company),
    );
  }
  return false;
}
function relatedObservations(entity, observations) {
  if (entity.type === "domain") {
    return observations.filter((obs) => {
      if (obs.entity_id === entity.id) return true;
      if (obs.evidence?.host === entity.value) return true;
      return obs.type === "url" && hostnameOf(obs.value) === entity.value;
    });
  }
  if (entity.type === "ip") {
    return observations.filter(
      (obs) => obs.entity_id === entity.id || obs.evidence?.ip === entity.value,
    );
  }
  if (entity.type === "url") {
    const host = hostnameOf(entity.value);
    return observations.filter(
      (obs) =>
        obs.entity_id === entity.id ||
        (obs.type === "domain" && obs.value === host),
    );
  }
  if (entity.type === "asn")
    return observations.filter((obs) => obs.entity_id === entity.id);
  if (entity.type === "technology") {
    const name = entity.value.toLowerCase();
    return observations.filter((obs) => {
      if (obs.entity_id === entity.id) return true;
      const tech = obs.evidence?.technology;
      return (
        Array.isArray(tech) &&
        tech.some((item) => String(item).toLowerCase() === name)
      );
    });
  }
  return [];
}
function spansHistoryAndRecent(ids, byId, asOf) {
  let historical = false;
  let recent = false;
  for (const id of ids) {
    const obs = byId.get(id);
    if (!obs) continue;
    if (isHistorical(obs)) historical = true;
    else if (isRecent(obs, asOf)) recent = true;
  }
  return historical && recent;
}
function conflictsFor(entity, related, contradictions, byId, asOf) {
  const found = [];
  for (const item of contradictions.get(entity.id) ?? []) {
    const ids = item.values.flatMap((value) => value.observation_ids);
    const historical = spansHistoryAndRecent(ids, byId, asOf);
    const packed = pack(ids);
    found.push({
      kind: historical ? "historical_versus_recent" : "attribute_disagreement",
      attribute: item.attribute,
      summary: historical
        ? "Historical and recent observations disagree on this attribute."
        : "Stored observations disagree on this attribute.",
      evidence_ids: packed.evidence_ids,
      evidence_truncated: packed.evidence_truncated,
      independent_disagreement: item.independent_disagreement,
    });
  }
  const historical = related.filter(isHistorical);
  const recent = related.filter(
    (obs) => !isHistorical(obs) && isRecent(obs, asOf),
  );
  const historicalStatuses = new Set(
    historical.map(statusToken).filter(Boolean),
  );
  const recentStatuses = new Set(recent.map(statusToken).filter(Boolean));
  const overlap = [...historicalStatuses].some((status) =>
    recentStatuses.has(status),
  );
  if (historicalStatuses.size && recentStatuses.size && !overlap) {
    const used = [...historical, ...recent].filter((obs) => statusToken(obs));
    const packed = pack(used.map((obs) => obs.id));
    found.push({
      kind: "historical_versus_recent",
      attribute: "status",
      summary: "Historical and recent observations disagree on status.",
      evidence_ids: packed.evidence_ids,
      evidence_truncated: packed.evidence_truncated,
      independent_disagreement: independentGroups(used) >= 2,
    });
  } else if (
    historical.length &&
    recent.some((obs) => activityPolarity(obs) === "negative")
  ) {
    const negative = recent.filter(
      (obs) => activityPolarity(obs) === "negative",
    );
    const used = [...historical, ...negative];
    const packed = pack(used.map((obs) => obs.id));
    found.push({
      kind: "historical_versus_recent",
      attribute: "activity",
      summary:
        "Historical records exist and a recent direct observation does not confirm activity.",
      evidence_ids: packed.evidence_ids,
      evidence_truncated: packed.evidence_truncated,
      independent_disagreement: independentGroups(used) >= 2,
    });
  }
  found.sort((a, b) =>
    `${a.kind}:${a.attribute}:${a.summary}`.localeCompare(
      `${b.kind}:${b.attribute}:${b.summary}`,
    ),
  );
  return found.slice(0, MAX_CONFLICTS);
}
function claimBlocked(obs) {
  return (
    observationIsCdn(obs) ||
    obs.evidence?.verification === "shared_infrastructure" ||
    obs.evidence?.verification === "hosting_asn" ||
    sourceFamily(obs.source, obs.evidence) === "registry_or_routing"
  );
}
function ownershipFor(asset, related, contradictions, scope, sharedIps) {
  // Attribution has to be stated on the asset itself. A related address,
  // certificate, or archive row cannot supply the organization claim.
  const claims = [];
  for (const obs of related) {
    if (obs.entity_id !== asset.id) continue;
    const claim = orgDomain(obs.evidence?.company, scope);
    if (claim) claims.push({ obs, ...claim });
  }
  const foreign = claims.filter((claim) => claim.foreign);
  const stated = claims.filter((claim) => !claim.foreign);
  const local = stated.filter((claim) => claim.obs.evidence?.inferred !== true);
  const independentSources = independentGroups(
    stated.map((claim) => claim.obs),
  );
  const orgConflict = (contradictions.get(asset.id) ?? []).some(
    (item) =>
      ["company", "public_company"].includes(item.attribute) &&
      item.independent_disagreement,
  );
  const sharedBlocked = asset.type === "ip" && sharedIps.has(asset.value);
  const cdnBlocked =
    (["ip", "asn", "technology"].includes(asset.type) &&
      cdnToken(asset.value)) ||
    (asset.type === "ip" && related.some(observationIsCdn)) ||
    (local.length > 0 && local.every((claim) => observationIsCdn(claim.obs)));
  const eligible = local.filter(
    (claim) =>
      asset.type !== "asn" &&
      !sharedBlocked &&
      !cdnBlocked &&
      !claimBlocked(claim.obs),
  );
  const eligibleGroups = independentGroups(eligible.map((claim) => claim.obs));
  let status = "unverified";
  let basis = "no_org_domain_claim";
  if (foreign.length || orgConflict) {
    status = "contradicted";
    basis = foreign.length ? "foreign_org_domain" : "attribute_contradiction";
  } else if (sharedBlocked) basis = "shared_ip";
  else if (cdnBlocked && (stated.length || related.some(observationIsCdn)))
    basis = "cdn";
  else if (asset.type === "asn") basis = "hosting_or_registry";
  else if (
    stated.length &&
    stated.every(
      (claim) =>
        sourceFamily(claim.obs.source, claim.obs.evidence) ===
          "registry_or_routing" ||
        claim.obs.evidence?.verification === "hosting_asn",
    )
  )
    basis = "hosting_or_registry";
  else if (eligibleGroups >= 2) {
    status = "verified";
    basis = "independent_in_scope_org_domain";
  } else if (local.length) basis = "duplicate_or_single_source";
  else if (stated.some((claim) => claim.obs.evidence?.inferred === true))
    basis = "inferred_or_ineligible";
  const evidence = pack(
    (status === "verified" ? eligible : claims).map((claim) => claim.obs.id),
  );
  return {
    status,
    ...evidence,
    independent_sources: independentSources,
    basis,
  };
}
function directEvidence(asset, related) {
  return asset.type === "url"
    ? related.filter((obs) => obs.entity_id === asset.id)
    : related;
}
function activityFor(direct, asOf) {
  const recent = direct.filter(
    (obs) => isRecent(obs, asOf) && activityPolarity(obs),
  );
  const positive = recent.filter((obs) => activityPolarity(obs) === "positive");
  const negative = recent.filter((obs) => activityPolarity(obs) === "negative");
  const status =
    positive.length && negative.length
      ? "contradicted"
      : positive.length
        ? "confirmed"
        : "not_confirmed";
  const used =
    status === "contradicted" ? recent : status === "confirmed" ? positive : [];
  return { status, ...pack(used.map((obs) => obs.id)) };
}

function challengeAsset(asset, assessment, related, asOf) {
  const activityPoints = [];
  function add(kind, explanation, observations) {
    if (observations.length)
      activityPoints.push({
        kind,
        explanation,
        ...pack(observations.map((obs) => obs.id)),
      });
  }
  const direct = directEvidence(asset, related);
  const recent = direct.filter((obs) => isRecent(obs, asOf));
  const positive = recent.filter((obs) => activityPolarity(obs) === "positive");
  const negative = recent.filter((obs) => activityPolarity(obs) === "negative");
  add(
    positive.length ? "conflicting-activity" : "negative-activity",
    positive.length
      ? "Recent observations report different activity outcomes."
      : "Recent observations failed to establish activity for this asset.",
    negative,
  );
  add(
    "host-context",
    "Hostname evidence provides context for this URL. A response at this path requires an observation of the URL itself.",
    asset.type === "url"
      ? related.filter(
          (obs) => obs.entity_id !== asset.id && activityPolarity(obs),
        )
      : [],
  );
  add(
    "historical",
    "Certificate or archive evidence applies to a past observation.",
    direct.filter(isHistorical),
  );
  add(
    "stale",
    "Activity evidence falls before the current observation window.",
    direct.filter(
      (obs) =>
        activityPolarity(obs) && Date.parse(obs.timestamp) < asOf - WINDOW_MS,
    ),
  );
  add(
    "future-dated",
    "Activity evidence is dated after the assessment time.",
    direct.filter(
      (obs) => activityPolarity(obs) && Date.parse(obs.timestamp) > asOf,
    ),
  );
  add(
    "http-error-response",
    "An HTTP error response documents a server reply. Endpoint availability requires further evidence.",
    positive.filter(
      (obs) => obs.source === "httpx" && Number(statusToken(obs)) >= 400,
    ),
  );

  const ownership = assessment.ownership;
  const disputed = ownership.status === "contradicted";
  const supported = ownership.status === "verified";
  const shared = ["shared_ip", "cdn", "hosting_or_registry"].includes(
    ownership.basis,
  );
  const attributionPoints = supported
    ? []
    : [
        {
          kind: disputed
            ? "conflicting-attribution"
            : shared
              ? "shared-infrastructure"
              : "insufficient-attribution",
          explanation: disputed
            ? "Stored organization claims disagree. Review their provenance before attribution."
            : shared
              ? "Shared address space, CDN, or registry evidence can identify an infrastructure provider. An organization-domain claim requires independent corroboration."
              : "Attribution requires corroborating organization-domain assertions from independent sources.",
          evidence_ids: ownership.evidence_ids,
          evidence_truncated: ownership.evidence_truncated,
        },
      ];
  return {
    activity: {
      disposition:
        positive.length && negative.length
          ? "disputed"
          : positive.length
            ? "supported-pending-review"
            : "unresolved",
      supporting: pack(positive.map((obs) => obs.id)),
      counterpoints: activityPoints,
    },
    attribution: {
      disposition: disputed
        ? "disputed"
        : supported
          ? "supported-pending-review"
          : "unresolved",
      supporting: supported
        ? {
            evidence_ids: ownership.evidence_ids,
            evidence_truncated: ownership.evidence_truncated,
          }
        : pack([]),
      counterpoints: attributionPoints,
    },
  };
}
function historyFor(related) {
  const used = related.filter(isHistorical);
  return {
    status: used.length ? "documented" : "not_documented",
    ...pack(used.map((obs) => obs.id)),
  };
}
function reviewFor(decisions, entityId) {
  const history = decisions.get(`entity:${entityId}`) ?? [];
  const current = history.at(-1) ?? null;
  return {
    status: current?.decision ?? "unreviewed",
    current_decision: current,
    history_count: history.length,
  };
}
function identityFor(entityId, links) {
  const related = links.filter(
    (link) => link.left_id === entityId || link.right_id === entityId,
  );
  const confirmed = related.filter(
    (link) => link.status === "confirmed",
  ).length;
  const candidates = related.filter(
    (link) => link.status === "candidate",
  ).length;
  return {
    status: confirmed
      ? "confirmed"
      : candidates
        ? "candidate"
        : "not_applicable",
    candidate_links: candidates,
    confirmed_links: confirmed,
    note: "A shared name or handle is never an identity match. A candidate is not a confirmed finding.",
  };
}
function suggestion(action, reason, adapter = null, target = null) {
  return {
    action,
    reason,
    executes: false,
    within_gates: true,
    adapter,
    target,
  };
}
function nextActionFor(asset, assessment, scope, gates) {
  if (
    assessment.review.status === "reject" ||
    assessment.conflicts.length ||
    assessment.ownership.status === "contradicted" ||
    assessment.current_activity.status === "contradicted"
  ) {
    return suggestion(
      "request human review before attribution",
      "Stored records disagree, current activity is contradicted, or an analyst rejected the subject. This suggestion does not collect evidence or record a decision.",
    );
  }
  const host =
    asset.type === "domain"
      ? asset.value
      : asset.type === "url"
        ? hostnameOf(asset.value)
        : "";
  const dnsReady =
    host &&
    inScopeHost(scope, host) &&
    gates.network === true &&
    gates.active === true &&
    gates.enabledAdapters.includes("dnsx") &&
    ADAPTERS.dnsx?.mode === "active";
  if (
    assessment.historical_existence.status === "documented" &&
    assessment.current_activity.status === "not_confirmed" &&
    dnsReady
  ) {
    return suggestion(
      "collect recent in-scope DNS evidence",
      "Historical evidence is stored and no recent direct observation confirms activity. dnsx is already enabled for this in-scope name. This suggestion does not run a collector or establish ownership.",
      "dnsx",
      host,
    );
  }
  if (
    assessment.ownership.status !== "verified" ||
    assessment.review.status !== "accept"
  ) {
    return suggestion(
      "request human review before attribution",
      "Attribution is not an accepted verified finding. Shared infrastructure, a name or handle, and one source do not establish ownership. This suggestion does not record a decision.",
    );
  }
  return suggestion(
    "no collection suggested",
    "Stored evidence is already assessed inside the current gates. This suggestion does not run a collector.",
  );
}
function summarizeLink(link) {
  return {
    id: link.id,
    status: link.status,
    basis: link.basis,
    blocked_reason: link.blocked_reason,
    shared_names: link.shared_names,
    shared_handles: link.shared_handles,
    shared_identifiers: link.shared_identifiers,
    independent_corroboration: link.independent_corroboration,
  };
}
function identityResolutionFor(links) {
  const candidates = links
    .filter((link) => link.status === "candidate")
    .map(summarizeLink);
  const confirmed = links
    .filter((link) => link.status === "confirmed")
    .map(summarizeLink);
  return {
    candidates: candidates.slice(0, 20),
    confirmed: confirmed.slice(0, 20),
    candidate_count: candidates.length,
    confirmed_count: confirmed.length,
    returned_candidates: Math.min(20, candidates.length),
    returned_confirmed: Math.min(20, confirmed.length),
    note: "A shared name or handle is never an identity match. Candidates are not confirmed findings.",
  };
}
function frame(extra) {
  return {
    window_days: 30,
    executes: false,
    mutation: false,
    network: false,
    calibration: "heuristic_not_probability",
    sampling: "complete_for_stored_rows",
    rules: ASSESSMENT_RULES,
    limitations: ASSESSMENT_LIMITATIONS,
    ...extra,
  };
}
function assessOne(
  asset,
  context,
  related = relatedObservations(asset, context.observations),
) {
  const direct = directEvidence(asset, related);
  const historical = historyFor(direct);
  const current = activityFor(direct, context.asOf);
  const ownership = ownershipFor(
    asset,
    related,
    context.resolution.contradictions,
    context.scope,
    context.sharedIps,
  );
  const conflicts = conflictsFor(
    asset,
    related,
    context.resolution.contradictions,
    context.byId,
    context.asOf,
  );
  const assessment = {
    entity_id: asset.id,
    type: asset.type,
    value: asset.value,
    historical_existence: historical,
    current_activity: current,
    ownership,
    conflicts,
    source_independence: {
      observations: related.length,
      independent_groups: independentGroups(related),
      note: INDEPENDENCE_NOTE,
    },
    review: reviewFor(context.decisions, asset.id),
    identity: identityFor(asset.id, context.resolution.links),
  };
  assessment.next_action = nextActionFor(
    asset,
    assessment,
    context.scope,
    context.gates,
  );
  return assessment;
}
function contextFor(store, scope, gates, options) {
  if (!scope?.host) throw new Error("INVALID_INPUT");
  const resolution = inspectResolution(store);
  const observations = decorate(store, resolution);
  return {
    scope,
    gates: readGates(gates),
    asOf: readAsOf(options),
    resolution,
    observations,
    byId: new Map(observations.map((obs) => [obs.id, obs])),
    sharedIps: sharedAddresses(observations),
    decisions: loadDecisions(store),
  };
}
function assetsInScope(context, type) {
  return context.resolution.entities
    .filter((entity) => ASSET_TYPES.includes(entity.type))
    .filter((entity) => !type || entity.type === type)
    .filter((entity) =>
      entityInScope(context.scope, entity, context.observations),
    )
    .sort((a, b) => a.id.localeCompare(b.id));
}
export function assessAssets(
  store,
  scope,
  gates = {},
  input = {},
  options = {},
) {
  const data = parseInput(AssessInput, input);
  const context = contextFor(store, scope, gates, options);
  const assets = assetsInScope(context, data.type);
  const pageStart = data.cursor
    ? assets.filter((asset) => asset.id > data.cursor)
    : assets;
  const page = pageStart.slice(0, data.limit);
  return frame({
    items: page.map((asset) => assessOne(asset, context)),
    returned: page.length,
    limit: data.limit,
    next_cursor: pageStart.length > data.limit ? page.at(-1).id : null,
    total: assets.length,
    identity_resolution: identityResolutionFor(context.resolution.links),
  });
}
export function explainAsset(
  store,
  scope,
  gates = {},
  input = {},
  options = {},
) {
  const data = parseInput(ExplainAssetInput, input);
  const context = contextFor(store, scope, gates, options);
  const entity = context.resolution.entitiesById.get(data.entity_id);
  if (!entity) throw new Error("ENTITY_NOT_FOUND");
  if (
    !ASSET_TYPES.includes(entity.type) ||
    !entityInScope(context.scope, entity, context.observations)
  )
    throw new Error("ASSET_NOT_IN_SCOPE");
  const related = relatedObservations(entity, context.observations);
  const assessment = assessOne(entity, context, related);
  return frame({
    ...assessment,
    ...(data.challenge
      ? { challenge: challengeAsset(entity, assessment, related, context.asOf) }
      : {}),
    identity_resolution: identityResolutionFor(
      context.resolution.links.filter(
        (link) => link.left_id === entity.id || link.right_id === entity.id,
      ),
    ),
  });
}
