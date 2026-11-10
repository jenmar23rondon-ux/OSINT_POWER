import { randomUUID } from "node:crypto";
import { z } from "zod";
import { hash } from "./store.js";
import { nameKey } from "./identity.js";
import { normalized } from "./scope.js";

// Schema v5 adds review tables. Schema v6 adds monitor tables in monitor.js.
// Opening a database creates the missing tables and does not rewrite existing rows.
export const SCHEMA_VERSION = 6;
const IDENTITY_TYPES = new Set(["email", "username", "profile", "employee"]);
const CONTRADICTION_FIELDS = [
  "public_company",
  "name",
  "person",
  "company",
  "title",
  "country",
  "account",
];
const MAX_ENTITIES_PER_KEY = 40;
const MAX_LINK_EVIDENCE = 40;

export const RESOLUTION_RULES = [
  "A shared name or handle across sources never confirms an identity.",
  "Confirmation requires a non-name identifier supported by at least two independent sources.",
  "Sources that share an upstream, a mirror origin, or a collector run are not independent.",
  "Analyst decisions are append-only history and do not merge or confirm entities.",
  "Only username, email, profile and employee entities are compared for identity.",
];

export const INDEPENDENCE_NOTE =
  "Sources that share an upstream, a mirror origin, or a collector run count as one source.";

export const DecisionInput = z
  .object({
    subject_kind: z.enum(["entity", "finding"]),
    subject_id: z.string().regex(/^[a-f0-9]{64}$/),
    decision: z.enum(["accept", "reject", "needs-more-evidence"]),
    reason: z.string().min(1).max(2000),
    analyst_id: z.string().regex(/^[A-Za-z0-9_.@-]{1,80}$/),
  })
  .strict();
export const ReviewQueueInput = z
  .object({
    limit: z.number().int().min(1).max(100).default(25),
    cursor: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
  })
  .strict();
export const ShowEntityInput = z
  .object({
    entity_id: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

function parseInput(schema, input) {
  const result = schema.safeParse(input);
  if (!result.success) throw new Error("INVALID_INPUT");
  return result.data;
}
function round2(value) {
  return Math.round(value * 100) / 100;
}
function label(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}
export function initializeReview(db) {
  const version = db.prepare("PRAGMA user_version").get().user_version;
  if (version > SCHEMA_VERSION) throw new Error("DATABASE_VERSION_TOO_NEW");
  db.exec(`
    CREATE TABLE IF NOT EXISTS review_decisions(
      id TEXT PRIMARY KEY,
      subject_kind TEXT NOT NULL CHECK(subject_kind IN ('entity','finding')),
      subject_id TEXT NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('accept','reject','needs-more-evidence')),
      reason TEXT NOT NULL,
      analyst_id TEXT NOT NULL,
      recorded_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS review_decisions_subject
      ON review_decisions(subject_kind, subject_id, recorded_at);
    CREATE TABLE IF NOT EXISTS entity_links(
      id TEXT PRIMARY KEY,
      left_id TEXT NOT NULL REFERENCES entities(id),
      right_id TEXT NOT NULL REFERENCES entities(id),
      status TEXT NOT NULL CHECK(status IN ('candidate','confirmed')),
      basis TEXT NOT NULL,
      confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
      confidence_basis TEXT NOT NULL,
      shared_names TEXT NOT NULL,
      shared_handles TEXT NOT NULL,
      shared_identifiers TEXT NOT NULL,
      independent_corroboration INTEGER NOT NULL,
      evidence TEXT NOT NULL,
      blocked_reason TEXT,
      updated_at TEXT NOT NULL,
      CHECK(left_id < right_id),
      CHECK(
        (status = 'candidate' AND confidence <= 0.4 AND basis <> 'independent_corroboration')
        OR (status = 'confirmed' AND basis = 'independent_corroboration'
            AND independent_corroboration >= 2 AND shared_identifiers <> '[]'
            AND confidence >= 0.7 AND confidence <= 0.95 AND blocked_reason IS NULL)));
    CREATE UNIQUE INDEX IF NOT EXISTS entity_links_pair ON entity_links(left_id, right_id);
    PRAGMA user_version=${SCHEMA_VERSION};`);
}
function decisionRow(row) {
  return {
    id: row.id,
    subject_kind: row.subject_kind,
    subject_id: row.subject_id,
    decision: row.decision,
    reason: row.reason,
    analyst_id: row.analyst_id,
    recorded_at: row.recorded_at,
  };
}
function decisionHistory(store, kind, subjectId) {
  return store.db
    .prepare(
      `SELECT id, subject_kind, subject_id, decision, reason, analyst_id, recorded_at
       FROM review_decisions WHERE subject_kind=? AND subject_id=?
       ORDER BY recorded_at ASC, rowid ASC`,
    )
    .all(kind, subjectId)
    .map(decisionRow);
}
export function loadDecisions(store) {
  const grouped = new Map();
  for (const row of store.db
    .prepare(
      `SELECT id, subject_kind, subject_id, decision, reason, analyst_id, recorded_at
       FROM review_decisions ORDER BY recorded_at ASC, rowid ASC`,
    )
    .all()) {
    const key = `${row.subject_kind}:${row.subject_id}`;
    const list = grouped.get(key) ?? [];
    list.push(decisionRow(row));
    grouped.set(key, list);
  }
  return grouped;
}
export function recordDecision(store, input) {
  const source = input && typeof input === "object" ? { ...input } : input;
  if (source && typeof source === "object") {
    if (typeof source.reason === "string") source.reason = source.reason.trim();
    if (typeof source.analyst_id === "string")
      source.analyst_id = source.analyst_id.trim();
  }
  const data = parseInput(DecisionInput, source);
  const table = data.subject_kind === "entity" ? "entities" : "observations";
  if (
    !store.db.prepare(`SELECT 1 FROM ${table} WHERE id=?`).get(data.subject_id)
  )
    throw new Error("SUBJECT_NOT_FOUND");
  const recorded = {
    id: randomUUID(),
    ...data,
    recorded_at: new Date().toISOString(),
  };
  store.db
    .prepare("INSERT INTO review_decisions VALUES(?,?,?,?,?,?,?)")
    .run(
      recorded.id,
      recorded.subject_kind,
      recorded.subject_id,
      recorded.decision,
      recorded.reason,
      recorded.analyst_id,
      recorded.recorded_at,
    );
  const history = decisionHistory(store, data.subject_kind, data.subject_id);
  return { current: history.at(-1), history, appended: true };
}
function canonicalIdentifier(attribute, value) {
  if (attribute === "email" || attribute === "account") {
    try {
      return { class: "email", value: normalized("email", value) };
    } catch {
      return null;
    }
  }
  if (attribute === "profile_url" || attribute === "profile") {
    try {
      return { class: "profile_url", value: normalized("profile", value) };
    } catch {
      return null;
    }
  }
  if (attribute === "fingerprint") {
    const compact = String(value).replace(/\s+/g, "").toLowerCase();
    if (compact.length < 16 || compact.length > 128) return null;
    return { class: "fingerprint", value: compact };
  }
  return null;
}
function pushClaim(target, claim) {
  if (!claim?.value) return;
  target.push(claim);
}
function claimsFor(entity, obs) {
  if (!IDENTITY_TYPES.has(entity.type)) return [];
  const out = [];
  const base = {
    entityId: entity.id,
    observationId: obs.id,
    source: obs.source,
    obs,
  };
  const handle = (attribute, value) => {
    const key = nameKey(String(value).replace(/^@/, ""));
    if (key.length < 2) return;
    pushClaim(out, {
      ...base,
      kind: "handle",
      attribute,
      value: key,
      raw: String(value).trim().slice(0, 200),
    });
  };
  const person = (attribute, value) => {
    const key = nameKey(value);
    if (key.length < 2) return;
    pushClaim(out, {
      ...base,
      kind: "name",
      attribute,
      value: key,
      raw: String(value).trim().slice(0, 200),
    });
  };
  const identifier = (attribute, value) => {
    const canonical = canonicalIdentifier(attribute, value);
    if (!canonical) return;
    pushClaim(out, {
      ...base,
      kind: "identifier",
      attribute: canonical.class,
      value: canonical.value,
      raw: canonical.value,
    });
  };
  if (entity.type === "username") handle("username", entity.value);
  if (entity.type === "email") {
    identifier("email", entity.value);
    handle("local_part", entity.value.split("@")[0]);
  }
  if (entity.type === "profile") identifier("profile_url", entity.value);
  if (entity.type === "employee")
    person("person", entity.value.split(" @ ")[0]);
  const evidence = obs.evidence ?? {};
  if (evidence.username) handle("username", evidence.username);
  if (evidence.handle) handle("handle", evidence.handle);
  if (evidence.name) person("name", evidence.name);
  if (evidence.person) person("person", evidence.person);
  if (typeof evidence.account === "string") {
    const email = canonicalIdentifier("email", evidence.account);
    if (email) {
      identifier("email", email.value);
      handle("local_part", email.value.split("@")[0]);
    }
  }
  if (evidence.profile_url) identifier("profile_url", evidence.profile_url);
  if (typeof evidence.fingerprint === "string")
    identifier("fingerprint", evidence.fingerprint);
  return out;
}
function dependent(left, right) {
  for (const runId of left.runIds) if (right.runIds.has(runId)) return true;
  const upstreamLeft = label(left.evidence.upstream);
  const upstreamRight = label(right.evidence.upstream);
  const sourceLeft = label(left.source);
  const sourceRight = label(right.source);
  if (
    upstreamLeft &&
    (upstreamLeft === upstreamRight || upstreamLeft === sourceRight)
  )
    return true;
  if (upstreamRight && upstreamRight === sourceLeft) return true;
  const mirrorLeft = label(left.evidence.mirror_of);
  const mirrorRight = label(right.evidence.mirror_of);
  if (mirrorLeft && (mirrorLeft === mirrorRight || mirrorLeft === sourceRight))
    return true;
  if (mirrorRight && mirrorRight === sourceLeft) return true;
  return false;
}
export function independentGroups(observations) {
  const unique = [];
  const seen = new Set();
  for (const obs of observations) {
    if (!obs || seen.has(obs.id)) continue;
    seen.add(obs.id);
    unique.push(obs);
  }
  if (!unique.length) return 0;
  const parent = unique.map((_, index) => index);
  const find = (index) =>
    parent[index] === index ? index : (parent[index] = find(parent[index]));
  for (let i = 0; i < unique.length; i++) {
    for (let j = i + 1; j < unique.length; j++) {
      if (!dependent(unique[i], unique[j])) continue;
      const rootA = find(i);
      const rootB = find(j);
      if (rootA !== rootB) parent[rootA] = rootB;
    }
  }
  return new Set(unique.map((_, index) => find(index))).size;
}
function loadObservations(store) {
  const runIds = new Map();
  for (const row of store.db
    .prepare("SELECT observation_id, run_id FROM run_observations")
    .all()) {
    const set = runIds.get(row.observation_id) ?? new Set();
    set.add(row.run_id);
    runIds.set(row.observation_id, set);
  }
  return store.db
    .prepare("SELECT id, entity_id, source, evidence FROM observations")
    .all()
    .map((row) => ({
      id: row.id,
      entity_id: row.entity_id,
      source: row.source,
      evidence: JSON.parse(row.evidence),
      runIds: runIds.get(row.id) ?? new Set(),
    }));
}
function attributeKey(field, value) {
  if (typeof value !== "string" || !value.trim()) return null;
  if (field === "account") {
    try {
      return normalized("email", value);
    } catch {
      return nameKey(value);
    }
  }
  return nameKey(value);
}
function groupAttribute(observations, field) {
  const groups = new Map();
  for (const obs of observations) {
    const key = attributeKey(field, obs.evidence[field]);
    if (!key) continue;
    const group = groups.get(key) ?? {
      value: String(obs.evidence[field]).trim().slice(0, 200),
      sources: new Set(),
      observation_ids: new Set(),
      obs: [],
    };
    group.sources.add(obs.source);
    group.observation_ids.add(obs.id);
    group.obs.push(obs);
    groups.set(key, group);
  }
  return groups;
}
function presentGroups(groups) {
  return [...groups.values()]
    .map((group) => ({
      value: group.value,
      sources: [...group.sources].sort(),
      observation_ids: [...group.observation_ids].sort(),
    }))
    .sort((a, b) => a.value.localeCompare(b.value));
}
function contradiction(scope, attribute, entityIds, groups, used) {
  return {
    scope,
    attribute,
    entity_ids: [...entityIds].sort(),
    values: presentGroups(groups),
    independent_disagreement: independentGroups(used) >= 2,
  };
}
function entityContradictions(entityId, observations) {
  const mine = observations.filter((obs) => obs.entity_id === entityId);
  const found = [];
  for (const field of CONTRADICTION_FIELDS) {
    const groups = groupAttribute(mine, field);
    if (groups.size < 2) continue;
    found.push(
      contradiction(
        "entity",
        field,
        [entityId],
        groups,
        [...groups.values()].flatMap((group) => group.obs),
      ),
    );
  }
  return found;
}
function linkContradictions(link, observations) {
  const left = observations.filter((obs) => obs.entity_id === link.left_id);
  const right = observations.filter((obs) => obs.entity_id === link.right_id);
  const found = [];
  for (const field of CONTRADICTION_FIELDS) {
    const a = groupAttribute(left, field);
    const b = groupAttribute(right, field);
    if (a.size !== 1 || b.size !== 1) continue;
    const [leftKey] = a.keys();
    const [rightKey] = b.keys();
    if (leftKey === rightKey) continue;
    const groups = new Map([...a, ...b]);
    found.push(
      contradiction(
        "linked_entity",
        field,
        [link.left_id, link.right_id],
        groups,
        [...a.values(), ...b.values()].flatMap((group) => group.obs),
      ),
    );
  }
  return found;
}
function eachPair(entityIds, visit) {
  const ids = [...entityIds].sort();
  if (ids.length < 2 || ids.length > MAX_ENTITIES_PER_KEY) return;
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) visit(ids[i], ids[j]);
  }
}
function evidenceRole(kind) {
  if (kind === "identifier") return "corroborating_identifier";
  if (kind === "handle") return "shared_handle";
  return "shared_name";
}
function buildLinks(entitiesById, observations) {
  const buckets = new Map();
  const add = (mapKey, claim) => {
    const bucket = buckets.get(mapKey) ?? {
      kind: claim.kind,
      entities: new Set(),
      claims: [],
    };
    bucket.entities.add(claim.entityId);
    bucket.claims.push(claim);
    buckets.set(mapKey, bucket);
  };
  for (const obs of observations) {
    const entity = entitiesById.get(obs.entity_id);
    if (!entity) continue;
    for (const claim of claimsFor(entity, obs)) {
      const mapKey =
        claim.kind === "identifier"
          ? `id:${claim.attribute}:${claim.value}`
          : `weak:${claim.value}`;
      add(mapKey, claim);
    }
  }
  const pairs = new Map();
  const entryFor = (left, right) => {
    const key = `${left}:${right}`;
    const entry = pairs.get(key) ?? {
      left,
      right,
      names: new Set(),
      handles: new Set(),
      identifiers: new Set(),
      claims: [],
    };
    pairs.set(key, entry);
    return entry;
  };
  for (const [mapKey, bucket] of buckets) {
    eachPair(bucket.entities, (left, right) => {
      const entry = entryFor(left, right);
      const relevant = bucket.claims.filter(
        (claim) => claim.entityId === left || claim.entityId === right,
      );
      entry.claims.push(...relevant);
      if (mapKey.startsWith("id:")) {
        entry.identifiers.add(mapKey.slice(3));
        return;
      }
      if (relevant.some((claim) => claim.kind === "handle"))
        entry.handles.add(mapKey.slice(5));
      if (relevant.some((claim) => claim.kind === "name"))
        entry.names.add(mapKey.slice(5));
    });
  }
  const now = new Date().toISOString();
  const links = [];
  for (const entry of pairs.values()) {
    if (!entry.names.size && !entry.handles.size && !entry.identifiers.size)
      continue;
    const support = [];
    const seenObs = new Set();
    for (const claim of entry.claims) {
      if (claim.kind !== "identifier" || seenObs.has(claim.observationId))
        continue;
      if (!entry.identifiers.has(`${claim.attribute}:${claim.value}`)) continue;
      seenObs.add(claim.observationId);
      support.push(claim.obs);
    }
    const independent = entry.identifiers.size ? independentGroups(support) : 0;
    const confirmed = entry.identifiers.size > 0 && independent >= 2;
    let basis;
    let confidence;
    let confidenceBasis;
    let blocked = null;
    if (confirmed) {
      basis = "independent_corroboration";
      confidence = Math.min(0.95, round2(0.75 + 0.05 * (independent - 2)));
      confidenceBasis = "Non-name identifier supported by independent sources.";
    } else if (entry.identifiers.size) {
      basis = "unconfirmed_identifier";
      confidence = 0.35;
      confidenceBasis =
        "Shared identifier lacks independent corroboration; the link stays a candidate.";
      blocked = "corroboration_not_independent";
    } else if (entry.handles.size) {
      basis = "shared_handle";
      confidence = 0.2;
      confidenceBasis =
        "Shared handle only; a matching name or handle never confirms identity.";
      blocked = "shared_name_or_handle_is_not_identity";
    } else {
      basis = "shared_name";
      confidence = 0.2;
      confidenceBasis =
        "Shared name only; a matching name or handle never confirms identity.";
      blocked = "shared_name_or_handle_is_not_identity";
    }
    if ((basis === "shared_name" || basis === "shared_handle") && confirmed)
      throw new Error("NAME_ONLY_CONFIRMATION_FORBIDDEN");
    const evidence = [];
    const seenEvidence = new Set();
    for (const claim of entry.claims) {
      const role = evidenceRole(claim.kind);
      const value = claim.kind === "identifier" ? claim.value : claim.raw;
      const key = `${claim.observationId}|${claim.attribute}|${role}|${value}`;
      if (seenEvidence.has(key)) continue;
      seenEvidence.add(key);
      evidence.push({
        observation_id: claim.observationId,
        entity_id: claim.entityId,
        source: claim.source,
        attribute: claim.attribute,
        value,
        role,
      });
    }
    evidence.sort((a, b) =>
      `${a.observation_id}:${a.attribute}`.localeCompare(
        `${b.observation_id}:${b.attribute}`,
      ),
    );
    const sharedIdentifiers = [...entry.identifiers].sort();
    if (confirmed && !sharedIdentifiers.length)
      throw new Error("NAME_ONLY_CONFIRMATION_FORBIDDEN");
    links.push({
      id: hash([entry.left, entry.right]),
      left_id: entry.left,
      right_id: entry.right,
      status: confirmed ? "confirmed" : "candidate",
      basis,
      confidence,
      confidence_basis: confidenceBasis,
      shared_names: [...entry.names].sort(),
      shared_handles: [...entry.handles].sort(),
      shared_identifiers: sharedIdentifiers,
      independent_corroboration: independent,
      evidence: evidence.slice(0, MAX_LINK_EVIDENCE),
      blocked_reason: blocked,
      updated_at: now,
    });
  }
  return links;
}
function persistLinks(store, links) {
  store.db.exec("BEGIN IMMEDIATE");
  try {
    store.db.prepare("DELETE FROM entity_links").run();
    const insert = store.db.prepare(
      "INSERT INTO entity_links VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    );
    for (const link of links) {
      insert.run(
        link.id,
        link.left_id,
        link.right_id,
        link.status,
        link.basis,
        link.confidence,
        link.confidence_basis,
        JSON.stringify(link.shared_names),
        JSON.stringify(link.shared_handles),
        JSON.stringify(link.shared_identifiers),
        link.independent_corroboration,
        JSON.stringify(link.evidence),
        link.blocked_reason,
        link.updated_at,
      );
    }
    store.db.exec("COMMIT");
  } catch (error) {
    store.db.exec("ROLLBACK");
    throw error;
  }
}
function readLinks(store) {
  return store.db
    .prepare("SELECT * FROM entity_links ORDER BY id")
    .all()
    .map((row) => ({
      id: row.id,
      left_id: row.left_id,
      right_id: row.right_id,
      status: row.status,
      basis: row.basis,
      confidence: row.confidence,
      confidence_basis: row.confidence_basis,
      shared_names: JSON.parse(row.shared_names),
      shared_handles: JSON.parse(row.shared_handles),
      shared_identifiers: JSON.parse(row.shared_identifiers),
      independent_corroboration: row.independent_corroboration,
      evidence: JSON.parse(row.evidence),
      blocked_reason: row.blocked_reason,
    }));
}
function resolutionInputs(store) {
  const entities = store.db
    .prepare("SELECT id, type, value, first_seen, last_seen FROM entities")
    .all();
  const entitiesById = new Map(entities.map((entity) => [entity.id, entity]));
  return { entities, entitiesById, observations: loadObservations(store) };
}
function contradictionsFor(entities, observations, links) {
  const contradictions = new Map();
  const add = (entityId, item) => {
    const list = contradictions.get(entityId) ?? [];
    list.push(item);
    contradictions.set(entityId, list);
  };
  for (const entity of entities) {
    for (const item of entityContradictions(entity.id, observations))
      add(entity.id, item);
  }
  for (const link of links) {
    for (const item of linkContradictions(link, observations)) {
      add(link.left_id, item);
      add(link.right_id, item);
    }
  }
  for (const [entityId, items] of contradictions) {
    items.sort((a, b) =>
      `${a.attribute}:${a.scope}:${a.entity_ids.join()}`.localeCompare(
        `${b.attribute}:${b.scope}:${b.entity_ids.join()}`,
      ),
    );
    contradictions.set(entityId, items);
  }
  return contradictions;
}
// Read-only view of the same candidate links and contradictions refreshResolution stores.
export function inspectResolution(store) {
  const { entities, entitiesById, observations } = resolutionInputs(store);
  const links = buildLinks(entitiesById, observations);
  return {
    entities,
    entitiesById,
    observations,
    links,
    contradictions: contradictionsFor(entities, observations, links),
  };
}
export function refreshResolution(store) {
  const { entities, entitiesById, observations } = resolutionInputs(store);
  const links = buildLinks(entitiesById, observations);
  persistLinks(store, links);
  const stored = readLinks(store);
  return {
    entities,
    entitiesById,
    observations,
    links: stored,
    contradictions: contradictionsFor(entities, observations, stored),
  };
}
function orient(link, entityId, entitiesById) {
  const otherId = link.left_id === entityId ? link.right_id : link.left_id;
  const other = entitiesById.get(otherId);
  if (!other) return null;
  return {
    id: link.id,
    status: link.status,
    basis: link.basis,
    confidence: link.confidence,
    confidence_basis: link.confidence_basis,
    other: { id: other.id, type: other.type, value: other.value },
    shared_names: link.shared_names,
    shared_handles: link.shared_handles,
    shared_identifiers: link.shared_identifiers,
    independent_corroboration: link.independent_corroboration,
    blocked_reason: link.blocked_reason,
    evidence: link.evidence,
  };
}
function queueReasons(decision, candidateCount, contradictionCount) {
  const reasons = [];
  if (!decision) reasons.push("needs_decision");
  else if (decision.decision === "needs-more-evidence")
    reasons.push("needs_more_evidence");
  if (candidateCount) reasons.push("unconfirmed_candidate");
  if (contradictionCount) reasons.push("contradiction");
  return reasons;
}
export function reviewQueue(store, input = {}) {
  const { limit, cursor } = parseInput(ReviewQueueInput, input);
  const { entities, links, contradictions } = refreshResolution(store);
  const decisions = loadDecisions(store);
  const items = [];
  for (const entity of entities) {
    const history = decisions.get(`entity:${entity.id}`) ?? [];
    const current = history.at(-1) ?? null;
    const related = links.filter(
      (link) => link.left_id === entity.id || link.right_id === entity.id,
    );
    const candidateCount = related.filter(
      (link) => link.status === "candidate",
    ).length;
    const confirmedCount = related.filter(
      (link) => link.status === "confirmed",
    ).length;
    const contradictionCount = (contradictions.get(entity.id) ?? []).length;
    const reasons = queueReasons(current, candidateCount, contradictionCount);
    if (!reasons.length) continue;
    items.push({
      entity_id: entity.id,
      type: entity.type,
      value: entity.value,
      current_decision: current,
      candidate_links: candidateCount,
      confirmed_links: confirmedCount,
      contradictions: contradictionCount,
      queue_reasons: reasons,
    });
  }
  items.sort((a, b) => a.entity_id.localeCompare(b.entity_id));
  const pageStart = cursor
    ? items.filter((item) => item.entity_id > cursor)
    : items;
  const page = pageStart.slice(0, limit);
  return {
    items: page,
    returned: page.length,
    limit,
    next_cursor: pageStart.length > limit ? page.at(-1).entity_id : null,
    total: items.length,
    rules: RESOLUTION_RULES,
  };
}
export function showEntity(store, input) {
  const { entity_id } = parseInput(ShowEntityInput, input);
  const { entitiesById, observations, links, contradictions } =
    refreshResolution(store);
  const entity = entitiesById.get(entity_id);
  if (!entity) throw new Error("ENTITY_NOT_FOUND");
  const decisions = loadDecisions(store);
  const history = decisions.get(`entity:${entity_id}`) ?? [];
  const oriented = links
    .filter((link) => link.left_id === entity_id || link.right_id === entity_id)
    .map((link) => orient(link, entity_id, entitiesById))
    .filter(Boolean)
    .sort((a, b) => a.other.id.localeCompare(b.other.id));
  const mine = observations.filter((obs) => obs.entity_id === entity_id);
  const findingDecisions = mine
    .map((obs) => {
      const rows = decisions.get(`finding:${obs.id}`) ?? [];
      if (!rows.length) return null;
      return {
        observation_id: obs.id,
        current_decision: rows.at(-1),
        history_count: rows.length,
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.observation_id.localeCompare(b.observation_id));
  return {
    entity: {
      id: entity.id,
      type: entity.type,
      value: entity.value,
      first_seen: entity.first_seen,
      last_seen: entity.last_seen,
    },
    current_decision: history.at(-1) ?? null,
    decision_history: history,
    finding_decisions: findingDecisions,
    candidates: oriented.filter((link) => link.status === "candidate"),
    confirmed_links: oriented.filter((link) => link.status === "confirmed"),
    contradictions: contradictions.get(entity_id) ?? [],
    independence: {
      observations: mine.length,
      independent_groups: independentGroups(mine),
      note: INDEPENDENCE_NOTE,
    },
    rules: RESOLUTION_RULES,
  };
}
