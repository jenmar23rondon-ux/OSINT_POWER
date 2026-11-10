import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { z } from "zod";
import { employeeValue, nameKey } from "./identity.js";
import { WORKFLOW_ALIASES, WORKFLOW_NAMES } from "./schema.js";
import { domain, normalized } from "./scope.js";
import { sourceFamily } from "./state.js";
import { validateStixBundle } from "./stix-validate.js";

// UUIDv5 (RFC 4122) over the DNS namespace. Names are prefixed so repeated
// exports of the same stored content keep the same STIX identifiers.
const DNS_NAMESPACE = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const EPOCH = "1970-01-01T00:00:00.000Z";
const MAX_ENTITIES = 200;
const MAX_OBSERVATIONS = 10;
const MAX_OBJECTS = 7000;
const RECORD_STATUSES = new Set([
  "completed",
  "not_found",
  "failed",
  "budget_exhausted",
  "not_run",
  "network_disabled",
  "active_disabled",
  "adapter_disabled",
]);
const DECISION_OPINION = {
  accept: "agree",
  reject: "disagree",
  "needs-more-evidence": "neutral",
};
const DECISION_LIMIT =
  "This records a stored analyst decision. It does not confirm identity, ownership, or phishing.";
const TYPE_ORDER = [
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

export const STIX_LIMITATIONS = [
  "Export reads stored evidence. It does not collect, review, monitor, or change phishing state.",
  "Out-of-scope entities are omitted. A suspected lookalike is included only when its protected apex is in scope, and only as a suspected indicator.",
  "Suspected leads and candidate links stay suspected or candidate. An analyst accept is an opinion, not a confirmation.",
  "Indicator confidence rescales the stored heuristic and is capped at 85. It is not a calibrated probability.",
  "Identifiers are UUIDv5 values from stored content. The bundle is deterministic for the same database and filters, and it is not a signed attestation.",
  "Entity types without a STIX 2.1 cyber-observable are notes. Certificate objects contain stored names, issuers and validity only; a certificate-transparency record id is not a serial number.",
  "At most 200 entities and 10 observations per entity are exported. A truncated bundle is a valid subset, not the whole workspace.",
  "With no investigation filter and a review filter of any or unreviewed, the configured apex may be added as a domain-name. That object is scope context, not a new sighting.",
];

const count = z.number().int().nonnegative();
const reviewStatus = z.enum([
  "any",
  "accepted",
  "rejected",
  "needs-more-evidence",
  "unreviewed",
]);
export const StixExportInput = z
  .object({
    investigation: z.string().min(1).max(80).optional(),
    target: z.string().min(1).max(253).optional(),
    review_status: reviewStatus.default("any"),
    since: z.iso.datetime().optional(),
    until: z.iso.datetime().optional(),
  })
  .strict();
const stixIdentifier = z
  .string()
  .regex(
    /^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
export const StixExportResult = z
  .object({
    format: z.literal("application/stix+json;version=2.1"),
    read_only: z.literal(true),
    bundle: z
      .object({
        type: z.literal("bundle"),
        id: stixIdentifier,
        objects: z.array(z.record(z.string(), z.json())).max(8000),
      })
      .strict(),
    validation: z
      .object({ valid: z.literal(true), error_count: z.literal(0) })
      .strict(),
    filters: z
      .object({
        investigation: z.string().nullable(),
        target: z.string().nullable(),
        review_status: reviewStatus,
        since: z.string().nullable(),
        until: z.string().nullable(),
      })
      .strict(),
    counts: z
      .object({
        objects: count,
        identities: count,
        scos: count,
        indicators: count,
        observed_data: count,
        relationships: count,
        notes: count,
        opinions: count,
        entities_included: count,
        entities_omitted_out_of_scope: count,
        suspected_indicators: count,
      })
      .strict(),
    truncated: z.boolean(),
    limitations: z.array(z.string()).min(1),
  })
  .strict();

export function uuidv5(name, namespace = DNS_NAMESPACE) {
  const ns = Buffer.from(namespace.replaceAll("-", ""), "hex");
  if (ns.length !== 16) throw new Error("INVALID_UUID_NAMESPACE");
  const digest = createHash("sha1").update(ns).update(name, "utf8").digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
export function stixId(type, key) {
  return `${type}--${uuidv5(`osint-power.stix.2.1|${type}|${key}`)}`;
}
export function stixTime(value) {
  if (typeof value !== "string" || !value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}
function clip(value, max) {
  const text = String(value ?? "");
  return text.length <= max ? text : text.slice(0, max);
}
function patternLiteral(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll("'", "\\'");
}
function sameOrChild(value, parent) {
  return value === parent || String(value).endsWith(`.${parent}`);
}
function parseJson(value, fallback) {
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" ? parsed : fallback;
  } catch {
    return fallback;
  }
}
function decimal(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "0";
  return String(Math.round(numeric * 1000) / 1000);
}
function indicatorConfidence(row) {
  const numeric = Number(row.confidence);
  if (!Number.isFinite(numeric)) return 0;
  return Math.min(85, Math.max(0, Math.round(numeric * 100)));
}
function inWindow(value, since, until) {
  const time = stixTime(value);
  if (!time) return false;
  if (since && time < since) return false;
  if (until && time > until) return false;
  return true;
}
function parseTarget(scope, value) {
  if (!value) return null;
  if (value.includes("@")) {
    try {
      const email = normalized("email", value);
      if (!scope.allows("email", email)) throw new Error("OUT_OF_SCOPE");
      return { kind: "email", value: email };
    } catch (error) {
      if (error.message === "OUT_OF_SCOPE") throw error;
      throw new Error("INVALID_INPUT");
    }
  }
  if (isIP(value)) {
    let ip;
    try {
      ip = normalized("ip", value);
    } catch {
      throw new Error("INVALID_INPUT");
    }
    if (!scope.allows("ip", ip, {})) throw new Error("OUT_OF_SCOPE");
    return { kind: "ip", value: ip };
  }
  try {
    const name = domain(value);
    if (!scope.host(name)) throw new Error("OUT_OF_SCOPE");
    return { kind: "domain", value: name };
  } catch (error) {
    if (error.message === "OUT_OF_SCOPE") throw error;
    const person = scope.person(value);
    if (person) return { kind: "person", value: person.name, person };
    throw new Error("INVALID_INPUT");
  }
}
function addIds(store, ids, runId) {
  for (const row of store.db
    .prepare("SELECT entity_id FROM run_observations WHERE run_id=?")
    .all(runId))
    ids.add(row.entity_id);
}
function addAssets(store, ids, monitorId) {
  for (const row of store.db
    .prepare(
      `SELECT entity_ids FROM monitor_assets
       WHERE run_id IN (SELECT id FROM monitor_runs WHERE monitor_id=?)`,
    )
    .all(monitorId)) {
    const parsed = parseJson(row.entity_ids, []);
    if (Array.isArray(parsed))
      for (const id of parsed) if (typeof id === "string") ids.add(id);
  }
}
function resolveInvestigation(store, value) {
  if (!value) return null;
  if (z.uuid().safeParse(value).success) {
    const monitor = store.db
      .prepare("SELECT * FROM monitors WHERE id=?")
      .get(value);
    const run = store.db.prepare("SELECT id FROM runs WHERE id=?").get(value);
    const job = store.db.prepare("SELECT id FROM jobs WHERE id=?").get(value);
    if (!monitor && !run && !job) throw new Error("INVESTIGATION_NOT_FOUND");
    const ids = new Set();
    if (run || job) addIds(store, ids, value);
    if (monitor) {
      for (const row of store.db
        .prepare("SELECT id FROM monitor_runs WHERE monitor_id=?")
        .all(monitor.id))
        addIds(store, ids, row.id);
      addAssets(store, ids, monitor.id);
    }
    return {
      kind: monitor ? "monitor" : "run",
      name: monitor?.investigation ?? null,
      monitor: monitor ?? null,
      ids,
    };
  }
  const name = WORKFLOW_ALIASES[value] ?? value;
  if (!new Set([...WORKFLOW_NAMES, "phishing", "collectors"]).has(name))
    throw new Error("INVALID_INPUT");
  const ids = new Set();
  const adapters = [`workflow:${name}`, `monitor:${name}`];
  if (name === "phishing") adapters.push("phishing");
  for (const adapter of adapters)
    for (const run of store.db
      .prepare("SELECT id FROM runs WHERE adapter=?")
      .all(adapter))
      addIds(store, ids, run.id);
  for (const monitor of store.db
    .prepare("SELECT * FROM monitors WHERE investigation=?")
    .all(name)) {
    for (const run of store.db
      .prepare("SELECT id FROM monitor_runs WHERE monitor_id=?")
      .all(monitor.id))
      addIds(store, ids, run.id);
    addAssets(store, ids, monitor.id);
  }
  return { kind: "name", name, monitor: null, ids };
}
function readSnapshot(store) {
  const read = () => {
    const observations = store.db
      .prepare("SELECT * FROM observations ORDER BY timestamp, id")
      .all()
      .map((row) => ({ ...row, evidence: parseJson(row.evidence, {}) }));
    const byEntity = new Map();
    for (const row of observations) {
      const list = byEntity.get(row.entity_id) ?? [];
      list.push(row);
      byEntity.set(row.entity_id, list);
    }
    const signals = new Map();
    for (const row of store.db
      .prepare("SELECT * FROM phishing_signals ORDER BY candidate_id, signal")
      .all()) {
      const list = signals.get(row.candidate_id) ?? [];
      list.push(row);
      signals.set(row.candidate_id, list);
    }
    const phishing = store.db
      .prepare(
        `SELECT * FROM phishing_candidates
         ORDER BY protected_domain, candidate_domain, id`,
      )
      .all()
      .map((row) => ({ ...row, signals: signals.get(row.id) ?? [] }));
    const phishingByEntity = new Map();
    for (const row of phishing)
      if (!phishingByEntity.has(row.entity_id))
        phishingByEntity.set(row.entity_id, row);
    return {
      entities: store.db
        .prepare("SELECT * FROM entities ORDER BY type, value, id")
        .all(),
      observations,
      byEntity,
      edges: store.db.prepare("SELECT * FROM edges ORDER BY id").all(),
      decisions: store.db
        .prepare(
          `SELECT * FROM review_decisions
           ORDER BY recorded_at ASC, rowid ASC`,
        )
        .all(),
      links: store.db
        .prepare("SELECT * FROM entity_links ORDER BY id")
        .all()
        .map((row) => ({
          ...row,
          shared_names: parseJson(row.shared_names, []),
          shared_handles: parseJson(row.shared_handles, []),
          shared_identifiers: parseJson(row.shared_identifiers, []),
        })),
      phishing,
      phishingByEntity,
    };
  };
  store.db.exec("BEGIN");
  try {
    const snapshot = read();
    store.db.exec("COMMIT");
    return snapshot;
  } catch (error) {
    try {
      store.db.exec("ROLLBACK");
    } catch {
      // The transaction may already be closed.
    }
    throw error;
  }
}
function latestDecision(decisions, entityId) {
  let latest = null;
  for (const decision of decisions)
    if (decision.subject_kind === "entity" && decision.subject_id === entityId)
      latest = decision;
  return latest;
}
function passesReview(latest, status) {
  if (status === "any") return true;
  if (status === "unreviewed") return !latest;
  if (status === "accepted") return latest?.decision === "accept";
  if (status === "rejected") return latest?.decision === "reject";
  return latest?.decision === "needs-more-evidence";
}
function entityInScope(scope, entity, observations) {
  if (
    observations.some((item) =>
      scope.allows(entity.type, entity.value, item.evidence),
    )
  )
    return true;
  return scope.allows(entity.type, entity.value, {});
}
function lookalikeInScope(scope, row) {
  if (!row || row.status !== "suspected") return false;
  try {
    return scope.host(row.protected_domain);
  } catch {
    return false;
  }
}
function passesInvestigation(entityId, investigation, lookalike) {
  if (!investigation) return true;
  if (investigation.ids.has(entityId)) return true;
  if (!lookalike) return false;
  if (investigation.kind === "name" && investigation.name === "phishing")
    return true;
  return Boolean(
    investigation.kind === "monitor" &&
    investigation.monitor?.investigation === "phishing" &&
    investigation.monitor.target === lookalike.protected_domain,
  );
}
function matchesTarget(entity, observations, target, runEntityIds) {
  if (!target) return true;
  if (runEntityIds.has(entity.id)) return true;
  if (target.kind === "domain") {
    if (
      ["domain", "company", "mail_domain"].includes(entity.type) &&
      sameOrChild(entity.value, target.value)
    )
      return true;
    if (entity.type === "email") {
      const host = entity.value.split("@")[1];
      if (host && sameOrChild(host, target.value)) return true;
    }
    if (entity.type === "url" || entity.type === "profile") {
      try {
        const host = new URL(entity.value).hostname.replace(/^\[|\]$/g, "");
        if (sameOrChild(host, target.value)) return true;
      } catch {
        // Stored value is not a URL; the other checks still apply.
      }
    }
    return observations.some((item) => {
      const evidence = item.evidence ?? {};
      const host = String(evidence.host ?? "");
      return (
        (host && sameOrChild(host, target.value)) ||
        evidence.company === target.value ||
        evidence.relatedValue === target.value ||
        (typeof evidence.account === "string" &&
          (evidence.account === target.value ||
            evidence.account.endsWith(`@${target.value}`) ||
            evidence.account.endsWith(`.${target.value}`)))
      );
    });
  }
  if (target.kind === "ip")
    return (
      (entity.type === "ip" && entity.value === target.value) ||
      observations.some((item) => item.evidence?.ip === target.value)
    );
  if (target.kind === "email")
    return (
      (entity.type === "email" && entity.value === target.value) ||
      observations.some((item) => item.evidence?.account === target.value)
    );
  if (target.kind === "person")
    return (
      observations.some(
        (item) =>
          nameKey(item.evidence?.person ?? "") === nameKey(target.value),
      ) ||
      (entity.type === "employee" &&
        entity.value === employeeValue(target.person))
    );
  return false;
}
function targetAllowsLookalike(lookalike, target) {
  if (!target) return true;
  if (target.kind !== "domain") return false;
  return sameOrChild(lookalike.protected_domain, target.value);
}
function entityInWindow(observations, since, until, fallback) {
  if (!since && !until) return true;
  if (observations.some((item) => inWindow(item.timestamp, since, until)))
    return true;
  return fallback.some((item) => inWindow(item, since, until));
}
function chooseObservations(observations, since, until) {
  const usable = observations.filter((item) => {
    if (!stixTime(item.timestamp)) return false;
    if ((since || until) && !inWindow(item.timestamp, since, until))
      return false;
    return true;
  });
  usable.sort(
    (left, right) =>
      right.timestamp.localeCompare(left.timestamp) ||
      left.id.localeCompare(right.id),
  );
  const truncated = usable.length > MAX_OBSERVATIONS;
  return {
    truncated,
    items: usable
      .slice(0, MAX_OBSERVATIONS)
      .sort(
        (left, right) =>
          left.timestamp.localeCompare(right.timestamp) ||
          left.id.localeCompare(right.id),
      ),
  };
}
function scoFor(entity) {
  if (["domain", "company", "mail_domain"].includes(entity.type)) {
    if (!entity.value || entity.value.length > 253 || /\s/.test(entity.value))
      return null;
    return { type: "domain-name", value: entity.value, key: entity.value };
  }
  if (entity.type === "ip") {
    const family = isIP(entity.value);
    if (family !== 4 && family !== 6) return null;
    return {
      type: family === 4 ? "ipv4-addr" : "ipv6-addr",
      value: entity.value,
      key: entity.value,
    };
  }
  if (entity.type === "email") {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(entity.value)) return null;
    return { type: "email-addr", value: entity.value, key: entity.value };
  }
  if (entity.type === "url" || entity.type === "profile") {
    try {
      const url = new URL(entity.value);
      if (!["http:", "https:"].includes(url.protocol)) return null;
      return { type: "url", value: entity.value, key: entity.value };
    } catch {
      return null;
    }
  }
  return null;
}
function certificateParts(observation, entityType) {
  const evidence = observation.evidence ?? {};
  if (
    ["crtsh", "certspotter"].includes(observation.source) &&
    entityType === "domain"
  ) {
    const record = String(evidence.record ?? "");
    if (!record || RECORD_STATUSES.has(record)) return null;
    if (
      evidence.verification &&
      evidence.verification !== "certificate_name_only"
    )
      return null;
    return {
      key: `ct|${observation.source}|${record}`,
      name: observation.value,
      evidence,
    };
  }
  if (
    observation.source === "httpx" &&
    entityType === "url" &&
    evidence.certificate_cn
  )
    return {
      key: `httpx|${evidence.certificate_cn}|${evidence.certificate_issuer ?? ""}`,
      name: String(evidence.certificate_cn),
      issuer: String(evidence.certificate_issuer ?? ""),
      evidence,
    };
  return null;
}
function suspectedObservation(observation) {
  const verification = String(observation.evidence?.verification ?? "");
  return (
    observation.source === "lookalike" ||
    /suspected|unconfirmed/i.test(verification)
  );
}
function selectEntities(scope, snapshot, filters) {
  const { investigation, target, review, since, until, runEntityIds } = filters;
  const selected = [];
  let omitted = 0;
  const seenCandidates = new Set();
  for (const entity of snapshot.entities) {
    const observations = snapshot.byEntity.get(entity.id) ?? [];
    const lookalike = snapshot.phishingByEntity.get(entity.id) ?? null;
    const scoped = entityInScope(scope, entity, observations);
    const asLookalike = lookalikeInScope(scope, lookalike) ? lookalike : null;
    if (!scoped && !asLookalike) {
      omitted++;
      continue;
    }
    if (!passesInvestigation(entity.id, investigation, asLookalike)) continue;
    const targetOk = asLookalike
      ? targetAllowsLookalike(asLookalike, target) ||
        matchesTarget(entity, observations, target, runEntityIds)
      : matchesTarget(entity, observations, target, runEntityIds);
    if (!targetOk) continue;
    if (
      !entityInWindow(
        observations,
        since,
        until,
        asLookalike ? [asLookalike.created_at, asLookalike.updated_at] : [],
      )
    )
      continue;
    if (!passesReview(latestDecision(snapshot.decisions, entity.id), review))
      continue;
    if (asLookalike) seenCandidates.add(asLookalike.id);
    selected.push({ entity, observations, lookalike: asLookalike });
  }
  for (const row of snapshot.phishing) {
    if (seenCandidates.has(row.id) || !lookalikeInScope(scope, row)) continue;
    const entity = {
      id: row.entity_id,
      type: "domain",
      value: row.candidate_domain,
      synthetic: true,
    };
    if (!passesInvestigation(entity.id, investigation, row)) continue;
    if (!targetAllowsLookalike(row, target)) continue;
    if (!entityInWindow([], since, until, [row.created_at, row.updated_at]))
      continue;
    if (!passesReview(latestDecision(snapshot.decisions, entity.id), review))
      continue;
    selected.push({ entity, observations: [], lookalike: row });
  }
  selected.sort(
    (left, right) =>
      left.entity.type.localeCompare(right.entity.type) ||
      left.entity.value.localeCompare(right.entity.value) ||
      left.entity.id.localeCompare(right.entity.id),
  );
  return { omitted, selected };
}
function orgName(scope, target) {
  if (target?.kind === "domain") return target.value;
  const names = scope.domains.slice().sort();
  if (names.length === 1) return names[0];
  if (names.length) return names.join(", ");
  return "Investigated organization";
}
function buildBundle(scope, snapshot, chosen, filters, omitted, truncated) {
  const times = [];
  const remember = (value) => {
    const time = stixTime(value);
    if (time && time !== EPOCH) times.push(time);
    return time;
  };
  const objects = [];
  const byId = new Map();
  const add = (object) => {
    if (!byId.has(object.id)) {
      byId.set(object.id, object);
      objects.push(object);
      remember(object.created);
      remember(object.valid_from);
      remember(object.first_observed);
    }
    return object.id;
  };
  const name = orgName(scope, filters.target);
  const toolId = stixId("identity", "system|OSINT POWER");
  const orgId = stixId("identity", `organization|${name}`);
  add({
    type: "identity",
    spec_version: "2.1",
    id: toolId,
    created: EPOCH,
    modified: EPOCH,
    name: "OSINT POWER",
    identity_class: "system",
    description:
      "Local read-only exporter. This identity produced the bundle from stored evidence and is not the investigated organization.",
  });
  add({
    type: "identity",
    spec_version: "2.1",
    id: orgId,
    created: EPOCH,
    modified: EPOCH,
    created_by_ref: toolId,
    name,
    identity_class: "organization",
    description: `Organization under investigation in this OSINT POWER workspace (${name}). This identity records the configured scope. It does not confirm legal ownership of every related observable.`,
  });
  const stixByEntity = new Map();
  const indicatorByEntity = new Map();
  const prepared = [];
  for (const item of chosen) {
    const observations = chooseObservations(
      item.observations,
      filters.since,
      filters.until,
    );
    if (observations.truncated) truncated = true;
    const scoEntity = {
      ...item.entity,
      value:
        item.lookalike && item.entity.type === "domain"
          ? item.lookalike.candidate_domain
          : item.entity.value,
    };
    const sco = scoFor(scoEntity);
    let objectId;
    if (sco) {
      objectId = add({
        type: sco.type,
        spec_version: "2.1",
        id: stixId(sco.type, sco.key),
        value: sco.value,
      });
    } else {
      const time =
        remember(observations.items[0]?.timestamp) ??
        remember(item.lookalike?.created_at) ??
        EPOCH;
      objectId = add({
        type: "note",
        spec_version: "2.1",
        id: stixId("note", `entity|${item.entity.id}`),
        created: time,
        modified: time,
        created_by_ref: toolId,
        abstract: `Stored ${item.entity.type}`,
        content: `Stored ${item.entity.type} is a note because STIX 2.1 has no cyber-observable for this type. Value: ${clip(item.entity.value, 500)}. This is not a confirmation of identity, ownership, or impact.`,
        authors: ["OSINT POWER"],
        object_refs: [orgId],
      });
    }
    stixByEntity.set(item.entity.id, objectId);
    prepared.push({
      ...item,
      observations: observations.items,
      scoId: objectId,
    });
  }
  const certificates = new Map();
  for (const item of prepared)
    for (const observation of item.observations) {
      const parts = certificateParts(observation, item.entity.type);
      if (!parts) continue;
      const current = certificates.get(parts.key) ?? {
        key: parts.key,
        names: new Set(),
        issuer: "",
        notBefore: null,
        notAfter: null,
      };
      if (parts.name) current.names.add(parts.name);
      if (parts.issuer) current.issuer = parts.issuer;
      const notBefore = stixTime(parts.evidence.valid_from);
      const notAfter = stixTime(parts.evidence.valid_until);
      if (notBefore) current.notBefore = notBefore;
      if (notAfter) current.notAfter = notAfter;
      certificates.set(parts.key, current);
    }
  const certificateIds = new Map();
  for (const certificate of [...certificates.values()].sort((left, right) =>
    left.key.localeCompare(right.key),
  )) {
    const names = [...certificate.names].sort().slice(0, 20);
    if (certificate.names.size > 20) truncated = true;
    const object = {
      type: "x509-certificate",
      spec_version: "2.1",
      id: stixId("x509-certificate", certificate.key),
      ...(names[0] ? { subject: names[0] } : {}),
      ...(certificate.issuer ? { issuer: clip(certificate.issuer, 500) } : {}),
      ...(certificate.notBefore
        ? { validity_not_before: certificate.notBefore }
        : {}),
      ...(certificate.notAfter
        ? { validity_not_after: certificate.notAfter }
        : {}),
      ...(names.length
        ? {
            x509_v3_extensions: {
              subject_alternative_name: names.join(", "),
            },
          }
        : {}),
    };
    certificateIds.set(certificate.key, add(object));
  }
  const observationById = new Map();
  const observedById = new Map();
  const exportedObservations = new Set();
  for (const item of prepared) {
    if (!item.lookalike) continue;
    const created =
      remember(item.lookalike.created_at) ??
      remember(item.observations[0]?.timestamp) ??
      EPOCH;
    const modified = remember(item.lookalike.updated_at) ?? created;
    const confidence = indicatorConfidence(item.lookalike);
    const signals = item.lookalike.signals
      .map(
        (signal) => `${signal.signal} ${signal.present ? "present" : "absent"}`,
      )
      .join(", ");
    const indicatorId = add({
      type: "indicator",
      spec_version: "2.1",
      id: stixId(
        "indicator",
        `${item.lookalike.protected_domain}|${item.lookalike.candidate_domain}`,
      ),
      created,
      modified: modified < created ? created : modified,
      created_by_ref: toolId,
      name: `Suspected phishing lookalike: ${item.lookalike.candidate_domain}`,
      description: [
        `Suspected phishing lookalike of ${item.lookalike.protected_domain}.`,
        "Not confirmed.",
        "Stored lead status: suspected.",
        `Stored basis: ${clip(item.lookalike.basis, 1000)}`,
        `Technique: ${item.lookalike.technique}. Similarity: ${decimal(item.lookalike.similarity)}.`,
        `Stored confidence ${decimal(item.lookalike.confidence)} rescaled to STIX confidence ${confidence} and capped at 85.`,
        signals ? `Signals: ${signals}.` : "No stored signals.",
        "An analyst accept does not confirm phishing.",
      ].join(" "),
      indicator_types: ["anomalous-activity"],
      pattern: `[domain-name:value = '${patternLiteral(item.lookalike.candidate_domain)}']`,
      pattern_type: "stix",
      pattern_version: "2.1",
      valid_from: created,
      confidence,
      labels: ["suspected"],
    });
    indicatorByEntity.set(item.entity.id, indicatorId);
  }
  const scoTypes = new Set([
    "domain-name",
    "ipv4-addr",
    "ipv6-addr",
    "email-addr",
    "url",
    "x509-certificate",
  ]);
  for (const item of prepared)
    for (const observation of item.observations) {
      if (!scoTypes.has(byId.get(item.scoId)?.type)) continue;
      const time = stixTime(observation.timestamp);
      if (!time) continue;
      const parts = certificateParts(observation, item.entity.type);
      const refs = [item.scoId];
      if (parts && certificateIds.has(parts.key))
        refs.push(certificateIds.get(parts.key));
      const family = sourceFamily(observation.source, observation.evidence);
      const suspected = suspectedObservation(observation);
      const confidence = Math.min(
        suspected ? 85 : 100,
        Math.max(0, Math.round(Number(observation.confidence) * 100) || 0),
      );
      const observedId = add({
        type: "observed-data",
        spec_version: "2.1",
        id: stixId("observed-data", observation.id),
        created: time,
        modified: time,
        created_by_ref: toolId,
        first_observed: time,
        last_observed: time,
        number_observed: 1,
        object_refs: [...new Set(refs)].sort(),
        confidence,
        ...(suspected ? { labels: ["suspected"] } : {}),
        external_references: [
          {
            source_name: clip(observation.source, 256) || "unknown",
            external_id: observation.id,
            description: `source_family=${family}`,
          },
        ],
      });
      observationById.set(observation.id, observation);
      observedById.set(observation.id, observedId);
      exportedObservations.add(observation.id);
      if (parts && certificateIds.has(parts.key))
        add({
          type: "relationship",
          spec_version: "2.1",
          id: stixId(
            "relationship",
            `${observation.id}|certificate|${parts.key}`,
          ),
          created: time,
          modified: time,
          created_by_ref: toolId,
          relationship_type: "related-to",
          source_ref: item.scoId,
          target_ref: certificateIds.get(parts.key),
          description:
            "Certificate name observed with this stored record. A certificate-transparency record id is not a serial number. Certificate presence is not proof of ownership.",
          external_references: [
            {
              source_name: clip(observation.source, 256) || "unknown",
              external_id: observation.id,
              description: `source_family=${family}`,
            },
          ],
        });
    }
  for (const edge of snapshot.edges) {
    if (!exportedObservations.has(edge.observation_id)) continue;
    const sourceRef = stixByEntity.get(edge.from_id);
    const targetRef = stixByEntity.get(edge.to_id);
    const observation = observationById.get(edge.observation_id);
    if (!sourceRef || !targetRef || !observation) continue;
    const time = stixTime(observation.timestamp);
    if (!time) continue;
    const source = byId.get(sourceRef);
    const target = byId.get(targetRef);
    const resolves =
      edge.relation === "resolves_to" &&
      source?.type === "domain-name" &&
      (target?.type === "ipv4-addr" || target?.type === "ipv6-addr");
    const candidate =
      edge.relation === "impersonates" ||
      String(edge.relation).startsWith("candidate");
    add({
      type: "relationship",
      spec_version: "2.1",
      id: stixId(
        "relationship",
        `${edge.id}|${resolves ? "resolves-to" : "related-to"}`,
      ),
      created: time,
      modified: time,
      created_by_ref: toolId,
      relationship_type: resolves ? "resolves-to" : "related-to",
      source_ref: sourceRef,
      target_ref: targetRef,
      description: [
        `Stored relation: ${edge.relation}.`,
        candidate
          ? "Suspected or candidate only; not confirmed."
          : "This records evidence and does not confirm ownership or identity.",
        `Observation ${observation.id} from ${observation.source} (${sourceFamily(observation.source, observation.evidence)}).`,
      ].join(" "),
      external_references: [
        {
          source_name: clip(observation.source, 256) || "unknown",
          external_id: observation.id,
          description: `stored_relation=${edge.relation}`,
        },
      ],
    });
  }
  for (const item of prepared) {
    const indicatorId = indicatorByEntity.get(item.entity.id);
    if (!indicatorId || !item.lookalike) continue;
    const protectedId = add({
      type: "domain-name",
      spec_version: "2.1",
      id: stixId("domain-name", item.lookalike.protected_domain),
      value: item.lookalike.protected_domain,
    });
    const created =
      stixTime(item.lookalike.created_at) ??
      stixTime(item.observations[0]?.timestamp) ??
      EPOCH;
    add({
      type: "relationship",
      spec_version: "2.1",
      id: stixId(
        "relationship",
        `related-to|${item.lookalike.protected_domain}|${item.lookalike.candidate_domain}`,
      ),
      created,
      modified: created,
      created_by_ref: toolId,
      relationship_type: "related-to",
      source_ref: indicatorId,
      target_ref: protectedId,
      description: `Suspected lookalike of in-scope ${item.lookalike.protected_domain}. Not confirmed phishing and not proof of ownership.`,
    });
    for (const observation of item.observations) {
      const observedId = observedById.get(observation.id);
      const time = stixTime(observation.timestamp);
      if (!observedId || !time) continue;
      add({
        type: "relationship",
        spec_version: "2.1",
        id: stixId("relationship", `based-on|${indicatorId}|${observation.id}`),
        created: time,
        modified: time,
        created_by_ref: toolId,
        relationship_type: "based-on",
        source_ref: indicatorId,
        target_ref: observedId,
        description:
          "Indicator is based on this stored observation. The lead remains suspected.",
      });
    }
  }
  if (
    filters.target?.kind === "domain" ||
    (!filters.target && scope.domains.length)
  ) {
    const anchor =
      filters.target?.kind === "domain"
        ? filters.target.value
        : scope.domains.slice().sort()[0];
    const alreadyPresent = byId.has(stixId("domain-name", anchor));
    const allowAnchor =
      (filters.review === "any" ||
        filters.review === "unreviewed" ||
        alreadyPresent) &&
      (!filters.investigation || alreadyPresent);
    if (anchor && scope.host(anchor) && allowAnchor) {
      const anchorId = add({
        type: "domain-name",
        spec_version: "2.1",
        id: stixId("domain-name", anchor),
        value: anchor,
      });
      const time = times.slice().sort()[0] ?? EPOCH;
      add({
        type: "relationship",
        spec_version: "2.1",
        id: stixId("relationship", `scope|${name}|${anchor}`),
        created: time,
        modified: time,
        created_by_ref: toolId,
        relationship_type: "related-to",
        source_ref: orgId,
        target_ref: anchorId,
        description:
          "Configured investigation scope. This relationship does not confirm legal ownership.",
      });
    }
  }
  for (const decision of snapshot.decisions) {
    if (
      (filters.since || filters.until) &&
      !inWindow(decision.recorded_at, filters.since, filters.until)
    )
      continue;
    const time = stixTime(decision.recorded_at);
    if (!time || !DECISION_OPINION[decision.decision]) continue;
    const objectId =
      decision.subject_kind === "entity"
        ? (indicatorByEntity.get(decision.subject_id) ??
          stixByEntity.get(decision.subject_id))
        : observedById.get(decision.subject_id);
    if (!objectId) continue;
    const reason = clip(decision.reason, 1500);
    add({
      type: "opinion",
      spec_version: "2.1",
      id: stixId("opinion", decision.id),
      created: time,
      modified: time,
      created_by_ref: toolId,
      opinion: DECISION_OPINION[decision.decision],
      explanation: `${DECISION_LIMIT} Stored decision: ${decision.decision}. Reason: ${reason}`,
      authors: [decision.analyst_id],
      object_refs: [objectId],
    });
    add({
      type: "note",
      spec_version: "2.1",
      id: stixId("note", `decision|${decision.id}`),
      created: time,
      modified: time,
      created_by_ref: toolId,
      abstract: `Analyst decision: ${decision.decision}`,
      content: `Analyst decision: ${decision.decision}. Analyst: ${decision.analyst_id}. Reason: ${reason}. ${DECISION_LIMIT}`,
      authors: [decision.analyst_id],
      object_refs: [objectId],
    });
  }
  for (const link of snapshot.links) {
    if (
      (filters.since || filters.until) &&
      !inWindow(link.updated_at, filters.since, filters.until)
    )
      continue;
    const left =
      indicatorByEntity.get(link.left_id) ?? stixByEntity.get(link.left_id);
    const right =
      indicatorByEntity.get(link.right_id) ?? stixByEntity.get(link.right_id);
    if (!left || !right) continue;
    const time = stixTime(link.updated_at) ?? times.slice().sort()[0] ?? EPOCH;
    const statusNote =
      link.status === "candidate"
        ? "A shared name or handle is not a confirmed identity."
        : "This export did not promote a candidate.";
    add({
      type: "note",
      spec_version: "2.1",
      id: stixId("note", `link|${link.id}`),
      created: time,
      modified: time,
      created_by_ref: toolId,
      abstract: `Stored link status: ${link.status}`,
      content: [
        `Stored link status: ${link.status}.`,
        `Basis: ${clip(link.basis, 200)}.`,
        clip(link.confidence_basis, 500),
        statusNote,
      ].join(" "),
      authors: ["OSINT POWER"],
      object_refs: [left, right].sort(),
    });
  }
  const limitationsId = add({
    type: "note",
    spec_version: "2.1",
    id: stixId("note", "limitations|osint-power"),
    created: EPOCH,
    modified: EPOCH,
    created_by_ref: toolId,
    abstract: "Export limitations",
    content: STIX_LIMITATIONS.join(" "),
    authors: ["OSINT POWER"],
    object_refs: [orgId],
  });
  const created = times.length ? times.slice().sort()[0] : EPOCH;
  const modified = times.length ? times.slice().sort().at(-1) : EPOCH;
  for (const id of [toolId, orgId, limitationsId]) {
    const object = byId.get(id);
    object.created = created;
    object.modified = modified < created ? created : modified;
  }
  if (!times.length)
    byId.get(orgId).description +=
      " No stored observation time matched this filter; the timestamp is a placeholder required by STIX.";
  for (const indicator of objects)
    if (indicator.type === "indicator") {
      const labels = indicator.labels ?? [];
      if (
        !labels.includes("suspected") ||
        indicator.confidence > 85 ||
        indicator.indicator_types.includes("malicious-activity") ||
        !indicator.description.includes("Not confirmed.")
      )
        throw new Error("STIX_EXPORT_INVALID");
    }
  objects.sort(
    (left, right) =>
      TYPE_ORDER.indexOf(left.type) - TYPE_ORDER.indexOf(right.type) ||
      left.id.localeCompare(right.id),
  );
  const bundle = {
    type: "bundle",
    id: stixId(
      "bundle",
      objects
        .map((object) => object.id)
        .sort()
        .join("|"),
    ),
    objects,
  };
  const errors = validateStixBundle(bundle);
  if (errors.length) {
    const failure = new Error("STIX_EXPORT_INVALID");
    failure.stixErrors = errors;
    throw failure;
  }
  const tally = (type) =>
    objects.filter((object) => object.type === type).length;
  const scoCount = objects.filter((object) =>
    [
      "domain-name",
      "ipv4-addr",
      "ipv6-addr",
      "email-addr",
      "url",
      "x509-certificate",
    ].includes(object.type),
  ).length;
  return {
    format: "application/stix+json;version=2.1",
    read_only: true,
    bundle,
    validation: { valid: true, error_count: 0 },
    filters: {
      investigation: filters.investigationLabel,
      target: filters.target?.value ?? null,
      review_status: filters.review,
      since: filters.since,
      until: filters.until,
    },
    counts: {
      objects: objects.length,
      identities: tally("identity"),
      scos: scoCount,
      indicators: tally("indicator"),
      observed_data: tally("observed-data"),
      relationships: tally("relationship"),
      notes: tally("note"),
      opinions: tally("opinion"),
      entities_included: chosen.length,
      entities_omitted_out_of_scope: omitted,
      suspected_indicators: objects.filter(
        (object) =>
          object.type === "indicator" && object.labels?.includes("suspected"),
      ).length,
    },
    truncated,
    limitations: STIX_LIMITATIONS,
  };
}
export function investigationCoverage(store, value) {
  const resolved = resolveInvestigation(store, value);
  if (!resolved) throw new Error("INVESTIGATION_NOT_FOUND");
  return {
    kind: resolved.kind,
    name: resolved.name,
    entity_ids: [...resolved.ids].sort(),
  };
}
export function exportStix(store, scope, input = {}) {
  const parsed = StixExportInput.safeParse(input ?? {});
  if (!parsed.success) throw new Error("INVALID_INPUT");
  const since = parsed.data.since ? stixTime(parsed.data.since) : null;
  const until = parsed.data.until ? stixTime(parsed.data.until) : null;
  if ((parsed.data.since && !since) || (parsed.data.until && !until))
    throw new Error("INVALID_INPUT");
  if (since && until && since > until) throw new Error("INVALID_INPUT");
  const target = parseTarget(scope, parsed.data.target);
  const investigation = resolveInvestigation(store, parsed.data.investigation);
  const runEntityIds = new Set();
  if (target)
    for (const row of store.db
      .prepare("SELECT DISTINCT entity_id FROM run_observations WHERE target=?")
      .all(target.value))
      runEntityIds.add(row.entity_id);
  const snapshot = readSnapshot(store);
  const filters = {
    investigation,
    investigationLabel: parsed.data.investigation ?? null,
    target,
    review: parsed.data.review_status,
    since,
    until,
    runEntityIds,
  };
  const { omitted, selected } = selectEntities(scope, snapshot, filters);
  let limit = Math.min(selected.length, MAX_ENTITIES);
  let truncated = selected.length > MAX_ENTITIES;
  let result = buildBundle(
    scope,
    snapshot,
    selected.slice(0, limit),
    filters,
    omitted,
    truncated,
  );
  while (result.counts.objects > MAX_OBJECTS && limit > 1) {
    limit = Math.floor(limit / 2);
    truncated = true;
    result = buildBundle(
      scope,
      snapshot,
      selected.slice(0, limit),
      filters,
      omitted,
      truncated,
    );
  }
  const checked = StixExportResult.safeParse(result);
  if (!checked.success) {
    const failure = new Error("STIX_EXPORT_INVALID");
    failure.stixErrors = checked.error.issues.slice(0, 8);
    throw failure;
  }
  return checked.data;
}
