import { hash } from "./store.js";
import { z } from "zod";
import { assessEvidence } from "./quality.js";
import { SCHEMA_VERSION } from "./review.js";

export const UUID = z.uuid();
export function initializeState(db) {
  const version = db.prepare("PRAGMA user_version").get().user_version;
  if (version > SCHEMA_VERSION) throw new Error("DATABASE_VERSION_TOO_NEW");
  db.exec(`
    CREATE TABLE IF NOT EXISTS run_observations(
      run_id TEXT NOT NULL REFERENCES runs(id), observation_id TEXT NOT NULL,
      entity_id TEXT NOT NULL, collector TEXT NOT NULL, target TEXT NOT NULL,
      payload TEXT NOT NULL, provenance TEXT NOT NULL,
      PRIMARY KEY(run_id,observation_id,collector,target));
    CREATE INDEX IF NOT EXISTS snapshot_entity ON run_observations(entity_id,run_id);
    CREATE TABLE IF NOT EXISTS run_sources(
      run_id TEXT NOT NULL REFERENCES runs(id), collector TEXT NOT NULL, target TEXT NOT NULL,
      status TEXT NOT NULL, cached INTEGER NOT NULL, truncated INTEGER NOT NULL,
      collected_at TEXT NOT NULL, summary TEXT NOT NULL,
      PRIMARY KEY(run_id,collector,target));
    CREATE TABLE IF NOT EXISTS jobs(
      id TEXT PRIMARY KEY REFERENCES runs(id), request TEXT NOT NULL, plan_hash TEXT NOT NULL,
      status TEXT NOT NULL, cancel_requested INTEGER NOT NULL DEFAULT 0,
      owner TEXT, lease_until INTEGER NOT NULL DEFAULT 0, calls INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, result TEXT);
    CREATE TABLE IF NOT EXISTS job_steps(
      job_id TEXT NOT NULL REFERENCES jobs(id), step_key TEXT NOT NULL, stage TEXT NOT NULL,
      kind TEXT NOT NULL, input TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
      child_run_id TEXT, result TEXT, updated_at TEXT NOT NULL,
      PRIMARY KEY(job_id,step_key));
    CREATE TABLE IF NOT EXISTS job_batches(
      job_id TEXT NOT NULL REFERENCES jobs(id), name TEXT NOT NULL, value TEXT NOT NULL,
      PRIMARY KEY(job_id,name));
    CREATE TABLE IF NOT EXISTS provider_state(
      provider TEXT PRIMARY KEY, next_at INTEGER NOT NULL DEFAULT 0, cooldown_until INTEGER NOT NULL DEFAULT 0,
      window_start INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0,
      requests INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
      last_code TEXT, last_success TEXT, last_failure TEXT);
    CREATE TABLE IF NOT EXISTS discovery_state(adapter TEXT NOT NULL,target TEXT NOT NULL,cursor TEXT,exhausted INTEGER NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(adapter,target));`);
}
export function sourceFamily(source, evidence = {}) {
  const name = String(source).toLowerCase();
  const upstream = String(evidence.upstream ?? "").toLowerCase();
  if (
    ["crtsh", "certspotter"].includes(name) ||
    /^(crtsh|crt\.sh|certspotter)$/.test(upstream)
  )
    return "certificate_transparency";
  if (
    ["subfinder", "amass", "theharvester", "spiderfoot", "recon-ng"].includes(
      name,
    )
  )
    return "aggregated_unknown";
  if (["dnsx", "mx"].includes(name)) return "dns";
  if (name === "httpx" || name === "naabu") return "direct_observation";
  if (["hibp", "dehashed", "leakcheck"].includes(name)) return "breach_catalog";
  if (["rdap", "routing"].includes(name)) return "registry_or_routing";
  if (["workflow", "configuration", "lookalike"].includes(name))
    return "configured_or_derived";
  if (name === "business-context") return "source_assertion";
  if (name === "wayback") return "web_archive";
  return "unclassified";
}
export function capture(store, runId, items, context = {}) {
  if (!runId) return;
  const collectedAt = context.collected_at ?? new Date().toISOString();
  const insert = store.db.prepare(
    "INSERT OR REPLACE INTO run_observations VALUES(?,?,?,?,?,?,?)",
  );
  for (const o of items) {
    const entity = hash([o.type, o.value]);
    const observation = hash([entity, o.source, o.evidence]);
    const provenance = {
      parser_version: "0.4.0",
      framework_version: "0.4.0",
      collector_version: context.collector_version ?? "not_recorded",
      configuration_digest: context.configuration_digest ?? null,
      source_family: sourceFamily(o.source, o.evidence),
      collected_at: collectedAt,
      observed_at: o.timestamp,
      input_hash: context.input_hash ?? null,
      from_cache: Boolean(context.cached),
      origin_run_id: context.origin_run_id ?? runId,
      origin: context.collector?.startsWith("import:")
        ? "import"
        : "collection",
      independence: "not_established",
    };
    insert.run(
      runId,
      observation,
      entity,
      context.collector ?? o.source,
      context.target ?? "",
      JSON.stringify(o),
      JSON.stringify(provenance),
    );
  }
}
export function recordSource(store, runId, collector, target, summary) {
  if (!runId) return;
  store.db
    .prepare("INSERT OR REPLACE INTO run_sources VALUES(?,?,?,?,?,?,?,?)")
    .run(
      runId,
      collector,
      target,
      summary.status,
      Number(Boolean(summary.cached)),
      Number(Boolean(summary.truncated)),
      summary.collected_at ?? new Date().toISOString(),
      JSON.stringify(summary),
    );
}
export function mirrorRun(store, childId, parentId) {
  if (!parentId || childId === parentId) return;
  store.db
    .prepare(
      `INSERT OR REPLACE INTO run_observations
    SELECT ?,observation_id,entity_id,collector,target,payload,provenance FROM run_observations WHERE run_id=?`,
    )
    .run(parentId, childId);
  store.db
    .prepare(
      `INSERT OR REPLACE INTO run_sources
    SELECT ?,collector,target,status,cached,truncated,collected_at,summary FROM run_sources WHERE run_id=?`,
    )
    .run(parentId, childId);
}
export function sources(store, runId) {
  return store.db
    .prepare(
      "SELECT * FROM run_sources WHERE run_id=? ORDER BY collector,target",
    )
    .all(runId)
    .map((r) => ({
      ...r,
      cached: Boolean(r.cached),
      truncated: Boolean(r.truncated),
      summary: JSON.parse(r.summary),
    }));
}
const snapshotQuery = `WITH
  b AS (SELECT entity_id,group_concat(observation_id) AS state FROM
    (SELECT DISTINCT entity_id,observation_id FROM run_observations WHERE run_id=? ORDER BY entity_id,observation_id) GROUP BY entity_id),
  a AS (SELECT entity_id,group_concat(observation_id) AS state FROM
    (SELECT DISTINCT entity_id,observation_id FROM run_observations WHERE run_id=? ORDER BY entity_id,observation_id) GROUP BY entity_id),
  ids AS (SELECT entity_id FROM b UNION SELECT entity_id FROM a),
  changes AS (SELECT ids.entity_id, CASE
    WHEN b.state IS NULL THEN 'added'
    WHEN a.state IS NULL THEN CASE WHEN EXISTS(
      SELECT 1 FROM run_observations old WHERE old.run_id=? AND old.entity_id=ids.entity_id
      AND NOT EXISTS(SELECT 1 FROM run_sources current WHERE current.run_id=?
        AND current.collector=old.collector AND current.target=old.target
        AND current.status='completed' AND current.truncated=0 AND current.cached=0
        AND COALESCE(json_extract(current.summary,'$.coverage_complete'),1)=1))
      THEN 'coverage_gap' ELSE 'not_observed' END
    WHEN a.state<>b.state THEN 'evidence_changed' ELSE 'unchanged' END AS change
    FROM ids LEFT JOIN b USING(entity_id) LEFT JOIN a USING(entity_id))`;
export const CompareInput = z
  .object({
    before: z.uuid(),
    after: z.uuid(),
    limit: z.number().int().min(1).max(100).default(25),
    cursor: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
  })
  .strict();
export function compareRuns(store, input) {
  const { before, after, limit, cursor } = CompareInput.parse(input);
  const run = (id) => store.db.prepare("SELECT * FROM runs WHERE id=?").get(id);
  const b = run(before),
    a = run(after);
  if (!a || !b) throw new Error("RUN_NOT_FOUND");
  if (
    [before, after].some((id) =>
      store.db.prepare("SELECT 1 FROM jobs WHERE id=?").get(id),
    )
  )
    throw new Error("USE_IMMUTABLE_SNAPSHOT_ID");
  if (a.status === "running" || b.status === "running")
    throw new Error("RUN_STILL_ACTIVE");
  if (
    a.adapter !== b.adapter ||
    (a.target !== b.target && !a.adapter.startsWith("import:"))
  )
    throw new Error("INCOMPARABLE_RUNS");
  if (
    ![before, after].every((id) =>
      store.db.prepare("SELECT 1 FROM run_sources WHERE run_id=?").get(id),
    )
  )
    throw new Error("SNAPSHOT_UNAVAILABLE");
  const params = [before, after, before, after];
  const counts = Object.fromEntries(
    store.db
      .prepare(
        snapshotQuery +
          " SELECT change,COUNT(*) AS total FROM changes GROUP BY change",
      )
      .all(...params)
      .map((r) => [r.change, r.total]),
  );
  const rows = store.db
    .prepare(
      snapshotQuery +
        ` SELECT c.*,e.type,e.value FROM changes c JOIN entities e ON e.id=c.entity_id
    WHERE c.change<>'unchanged' AND c.entity_id>? ORDER BY c.entity_id LIMIT ?`,
    )
    .all(...params, cursor ?? "", limit + 1);
  const items = rows.slice(0, limit);
  const total = Object.entries(counts)
    .filter(([key]) => key !== "unchanged")
    .reduce((n, [, value]) => n + value, 0);
  return {
    before,
    after,
    counts,
    total,
    returned: items.length,
    items,
    limit,
    next_cursor: rows.length > limit ? items.at(-1).entity_id : null,
    sources: { before: sources(store, before), after: sources(store, after) },
    interpretation:
      "Changes describe captured evidence. not_observed is not removal; coverage_gap indicates failed, omitted, cached or truncated collection.",
  };
}
export function explainEntity(store, entityId, limit = 10) {
  if (!/^[a-f0-9]{64}$/.test(entityId)) throw new Error("INVALID_ENTITY_ID");
  const entity = store.db
    .prepare("SELECT * FROM entities WHERE id=?")
    .get(entityId);
  if (!entity) throw new Error("ENTITY_NOT_FOUND");
  const page = store.evidence(entityId, limit);
  const families = Object.entries(
    page.items.reduce((all, o) => {
      const f = sourceFamily(o.source, o.evidence);
      all[f] = (all[f] ?? 0) + 1;
      return all;
    }, {}),
  ).map(([family, observations]) => ({
    family,
    observations,
    independence: "not_established",
  }));
  const history = store.db
    .prepare(
      "SELECT run_id,collector,target,provenance FROM run_observations WHERE entity_id=? ORDER BY rowid DESC LIMIT ?",
    )
    .all(entityId, limit)
    .map((r) => ({ ...r, provenance: JSON.parse(r.provenance) }));
  return {
    entity,
    assessment: assessEvidence(
      page.items.map((o) => ({ ...o, type: entity.type })),
    ),
    assessment_sampled:
      store.db
        .prepare("SELECT COUNT(*) AS n FROM observations WHERE entity_id=?")
        .get(entityId).n > page.items.length,
    evidence: page,
    source_families: families,
    history,
    qualifications: [
      "Source families may overlap; counts are not independent confirmations.",
      "Different timestamps or source assertions do not establish identity, ownership or credential validity.",
    ],
    possible_changes: store.db
      .prepare(
        "SELECT COUNT(DISTINCT observation_id) AS n FROM run_observations WHERE entity_id=?",
      )
      .get(entityId).n,
  };
}
