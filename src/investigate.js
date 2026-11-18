import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { z } from "zod";
import { PASSIVE_ADAPTERS } from "./adapter-kinds.js";
import { ADAPTERS } from "./adapters.js";
import { CorrelationLink, correlateEntities } from "./correlation.js";
import { collectPassiveSources, summarizePassive } from "./passive-collect.js";
import { EntityType } from "./schema.js";
import { domain, normalized } from "./scope.js";
import { keyInfo } from "./sources.js";

export const INVESTIGATION_LIMITATIONS = [
  "Plan mode does not contact sources or write an investigation.",
  "Execute runs enabled passive adapters only. Active HTTP, DNS, and port probes stay off.",
  "Resume retries sources that did not complete or that recorded a coverage gap. Completed sources stay cached until the TTL expires.",
  "A diff describes stored observations. Absence is not removal.",
  "A shared handle, profile, or published email is a candidate link, not a confirmed identity.",
  "The findings count in correlation is a sample of at most 50 entities.",
];

const ABSENCE =
  "Observations absent from this run were not collected again. Absence is not removal. A source that did not complete is a coverage gap.";

const coverageGap = z
  .object({
    source: z.string().min(1).max(80),
    target: z.string().max(320),
    site: z.string().max(200),
    reason: z.enum([
      "rate_limited",
      "error",
      "missing_key",
      "unknown",
      "failed",
    ]),
  })
  .strict();
const action = z
  .object({
    rank: z.number().int().nonnegative(),
    action: z.string(),
    reason: z.string(),
  })
  .strict();
const plannedAdapter = z
  .object({
    name: z.string(),
    enabled: z.boolean(),
    mode: z.literal("passive"),
    key_status: z.enum([
      "missing",
      "present",
      "optional_missing",
      "optional_present",
      "not_required",
    ]),
    missing_required_env: z.array(z.string()).max(4),
    missing_optional_env: z.array(z.string()).max(4),
  })
  .strict();
const publicResult = z
  .object({
    adapter: z.string().min(1).max(80),
    status: z.string().min(1).max(40),
    target: z.string().max(320).optional(),
    code: z.string().max(80).optional(),
    run_id: z.string().max(80).optional(),
    cached: z.boolean().optional(),
    observations: z.number().int().nonnegative().optional(),
    inserted: z.number().int().nonnegative().optional(),
    repeated: z.number().int().nonnegative().optional(),
    truncated: z.boolean().optional(),
    attempts: z.number().int().nonnegative().optional(),
    retry_after_ms: z.number().int().nonnegative().optional(),
    coverage_gaps: z.array(coverageGap).max(200).optional(),
    next_actions: z.array(action).max(10).optional(),
  })
  .strict();
const diffItem = z
  .object({
    observation_id: z.string().regex(/^[a-f0-9]{64}$/),
    entity_id: z.string().regex(/^[a-f0-9]{64}$/),
    type: EntityType,
    value: z.string().min(1).max(2048),
    source: z.string().min(1).max(80),
  })
  .strict();
const diffSchema = z
  .object({
    baseline: z.enum(["none", "previous_investigation", "previous_attempt"]),
    baseline_id: z.uuid().nullable(),
    added: z.array(diffItem).max(50),
    absent: z.array(diffItem).max(50),
    unchanged: z.number().int().nonnegative(),
    truncated: z.boolean(),
    note: z.string().min(1).max(500),
  })
  .strict();

export const InvestigateInput = z
  .object({
    target: z.string().min(1).max(320).optional(),
    id: z.uuid().optional(),
    execute: z.boolean().default(false),
    resume: z.boolean().default(false),
  })
  .strict();

export const InvestigateResult = z
  .object({
    status: z.enum(["planned", "completed", "partial", "failed", "deferred"]),
    id: z.uuid().nullable(),
    kind: z.enum(["domain", "email", "username", "ip"]),
    target: z.string().min(1).max(320),
    mode: z.enum(["plan", "execute", "stored"]),
    network: z.boolean(),
    mutation: z.boolean(),
    resumed: z.boolean(),
    active_collection: z.literal(false),
    adapters: z.array(plannedAdapter).max(40),
    missing_keys: z.array(z.string()).max(20),
    results: z.array(publicResult).max(40),
    coverage_gaps: z.array(coverageGap).max(200),
    correlation: z
      .object({
        target: z.string(),
        findings: z.number().int().nonnegative(),
        sources: z.array(z.string()),
      })
      .strict(),
    links: z.array(CorrelationLink).max(50),
    links_truncated: z.boolean(),
    diff: diffSchema.nullable(),
    code: z.string().max(80).optional(),
    limitations: z.array(z.string()).max(12),
    next_actions: z.array(action).max(10),
  })
  .strict();

function classifiedTarget(value) {
  const raw = String(value ?? "").trim();
  if (!raw || raw.length > 320) throw new Error("INVALID_INPUT");
  if (isIP(raw)) return { kind: "ip", target: normalized("ip", raw) };
  if (raw.includes("@"))
    return { kind: "email", target: normalized("email", raw) };
  if (!raw.includes(".")) {
    if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(raw))
      throw new Error("INVALID_INPUT");
    return { kind: "username", target: raw };
  }
  return { kind: "domain", target: domain(raw) };
}

function assertScoped(engine, kind, target) {
  if (kind === "domain" && !engine.scope.host(target))
    throw new Error("OUT_OF_SCOPE");
  if (kind === "email" && !engine.scope.allows("email", target))
    throw new Error("OUT_OF_SCOPE");
  if (kind === "username" && !engine.scope.username(target))
    throw new Error("USERNAME_OUT_OF_SCOPE");
  if (
    kind === "ip" &&
    !engine.scope.host(target) &&
    !engine.store.ipHost(target, engine.scope)
  )
    throw new Error("OUT_OF_SCOPE");
}

function adapterPlan(engine, kind) {
  const enabled = new Set(engine.config.enabledAdapters);
  return (PASSIVE_ADAPTERS[kind] ?? [])
    .filter((name) => ADAPTERS[name]?.mode === "passive")
    .map((name) => {
      const keys = keyInfo(name);
      return {
        name,
        enabled: enabled.has(name),
        mode: "passive",
        key_status: keys.key_status,
        missing_required_env: keys.missing_required_env,
        missing_optional_env: keys.missing_optional_env,
      };
    });
}

function gapsOf(result) {
  if (!Array.isArray(result.coverage_gaps)) return undefined;
  const gaps = [];
  for (const gap of result.coverage_gaps) {
    if (!gap || typeof gap.source !== "string") continue;
    if (
      !["rate_limited", "error", "missing_key", "unknown", "failed"].includes(
        gap.reason,
      )
    )
      continue;
    gaps.push({
      source: gap.source,
      target: String(gap.target ?? ""),
      site: String(gap.site ?? ""),
      reason: gap.reason,
    });
    if (gaps.length === 200) break;
  }
  return gaps;
}

function publishResult(result) {
  const actions = Array.isArray(result.next_actions)
    ? result.next_actions.slice(0, 10).map((item) => ({
        rank: item.rank,
        action: String(item.action),
        reason: String(item.reason),
      }))
    : undefined;
  const published = {
    adapter: result.adapter,
    status: result.status,
    ...(result.target ? { target: String(result.target) } : {}),
    ...(result.code ? { code: String(result.code) } : {}),
    ...(result.run_id ? { run_id: String(result.run_id) } : {}),
    ...(typeof result.cached === "boolean" ? { cached: result.cached } : {}),
    ...(Number.isInteger(result.observations)
      ? { observations: result.observations }
      : {}),
    ...(Number.isInteger(result.inserted) ? { inserted: result.inserted } : {}),
    ...(Number.isInteger(result.repeated) ? { repeated: result.repeated } : {}),
    ...(typeof result.truncated === "boolean"
      ? { truncated: result.truncated }
      : {}),
    ...(Number.isInteger(result.attempts) ? { attempts: result.attempts } : {}),
    ...(Number.isInteger(result.retry_after_ms)
      ? { retry_after_ms: result.retry_after_ms }
      : {}),
    ...(gapsOf(result) ? { coverage_gaps: gapsOf(result) } : {}),
    ...(actions ? { next_actions: actions } : {}),
  };
  return publicResult.parse(published);
}

function linked(engine, target) {
  const correlated = correlateEntities(engine.store, engine.scope);
  const sample = engine.store.findings(target, 50);
  return {
    correlation: {
      target,
      findings: sample.items.length,
      sources: [],
    },
    links: correlated.items,
    links_truncated: correlated.truncated,
  };
}

function planBody(engine, kind, target) {
  const adapters = adapterPlan(engine, kind);
  const linkedRows = linked(engine, target);
  return {
    status: "planned",
    id: null,
    kind,
    target,
    mode: "plan",
    network: false,
    mutation: false,
    resumed: false,
    active_collection: false,
    adapters,
    missing_keys: [
      ...new Set(
        adapters
          .filter((item) => item.enabled)
          .flatMap((item) => item.missing_required_env),
      ),
    ].sort(),
    results: [],
    coverage_gaps: [],
    ...linkedRows,
    diff: null,
    limitations: INVESTIGATION_LIMITATIONS,
    next_actions: engine.next().map((item) => ({
      rank: item.rank,
      action: item.action,
      reason: item.reason,
    })),
  };
}

function emptySnapshot() {
  return { run_ids: [], observations: [], truncated: false };
}

function snapshotFor(store, runIds) {
  const ids = runIds.filter((id) => typeof id === "string").slice(0, 80);
  if (!ids.length) return emptySnapshot();
  const rows = store.db
    .prepare(
      `SELECT observation_id, entity_id, payload, collector
       FROM run_observations WHERE run_id IN (${ids.map(() => "?").join(",")})
       ORDER BY observation_id`,
    )
    .all(...ids);
  const seen = new Set();
  const observations = [];
  let truncated = ids.length < runIds.length;
  for (const row of rows) {
    if (seen.has(row.observation_id)) continue;
    seen.add(row.observation_id);
    if (observations.length === 500) {
      truncated = true;
      break;
    }
    let payload;
    try {
      payload = JSON.parse(row.payload);
    } catch {
      continue;
    }
    if (!EntityType.safeParse(payload.type).success) continue;
    const value = String(payload.value ?? "");
    const source = String(payload.source ?? row.collector ?? "");
    if (!value || !source) continue;
    observations.push({
      observation_id: row.observation_id,
      entity_id: row.entity_id,
      type: payload.type,
      value: value.slice(0, 2048),
      source: source.slice(0, 80),
    });
  }
  return { run_ids: ids, observations, truncated };
}

function noteFor(baseline) {
  if (baseline === "none")
    return `This is the first stored investigation for the target. ${ABSENCE}`;
  if (baseline === "previous_attempt")
    return `This diff compares the resumed run with the previous attempt. ${ABSENCE}`;
  return `This diff compares the run with the previous investigation of the same target. ${ABSENCE}`;
}

function diffSnapshots(baseline, baselineId, previous, next) {
  const before = new Map(
    (previous?.observations ?? []).map((item) => [item.observation_id, item]),
  );
  const after = new Map(
    next.observations.map((item) => [item.observation_id, item]),
  );
  const added = [];
  const absent = [];
  let addedCount = 0;
  let absentCount = 0;
  let unchanged = 0;
  for (const [id, item] of after) {
    if (before.has(id)) unchanged++;
    else {
      addedCount++;
      if (added.length < 50) added.push(item);
    }
  }
  for (const [id, item] of before) {
    if (after.has(id)) continue;
    absentCount++;
    if (absent.length < 50) absent.push(item);
  }
  return diffSchema.parse({
    baseline,
    baseline_id: baselineId,
    added,
    absent,
    unchanged,
    truncated:
      Boolean(previous?.truncated || next.truncated) ||
      addedCount > added.length ||
      absentCount > absent.length,
    note: noteFor(baseline),
  });
}

function needsRetry(result) {
  if (!result) return true;
  if (result.status !== "completed") return true;
  return Array.isArray(result.coverage_gaps) && result.coverage_gaps.length > 0;
}

function readRow(store, id) {
  const row = store.db
    .prepare("SELECT * FROM investigations WHERE id=?")
    .get(id);
  if (!row) throw new Error("INVESTIGATION_NOT_FOUND");
  return {
    ...row,
    body: JSON.parse(row.body),
    snapshot: JSON.parse(row.snapshot),
  };
}

function previousRow(store, target, id) {
  return store.db
    .prepare(
      `SELECT id, snapshot FROM investigations
       WHERE target=? AND id<>? ORDER BY started DESC, id DESC LIMIT 1`,
    )
    .get(target, id ?? "");
}

function writeRow(store, row) {
  store.db
    .prepare(
      `INSERT INTO investigations VALUES(?,?,?,?,?,?,?,?)
       ON CONFLICT(id) DO UPDATE SET
         finished=excluded.finished, status=excluded.status,
         body=excluded.body, snapshot=excluded.snapshot`,
    )
    .run(
      row.id,
      row.target,
      row.kind,
      row.started,
      row.finished,
      row.status,
      JSON.stringify(row.body),
      JSON.stringify(row.snapshot),
    );
}

function finish(engine, draft) {
  const summary = summarizePassive(engine, draft.target, draft.results);
  const body = InvestigateResult.parse({
    ...draft,
    status: draft.results.length ? summary.status : "partial",
    coverage_gaps: summary.coverage_gaps,
    correlation: summary.correlation,
    next_actions: summary.next_actions.map((item) => ({
      rank: item.rank,
      action: item.action,
      reason: item.reason,
    })),
    ...(draft.results.length ? {} : { code: draft.code ?? "ADAPTER_DISABLED" }),
  });
  return body;
}

async function executeInvestigation(engine, target, options = {}) {
  const { kind, target: scoped } = classifiedTarget(target);
  assertScoped(engine, kind, scoped);
  const adapters = adapterPlan(engine, kind);
  const enabled = adapters
    .filter((item) => item.enabled)
    .map((item) => item.name);
  const pending = options.pending ?? enabled;
  const id = options.id ?? randomUUID();
  const started = options.started ?? new Date().toISOString();
  const prior = Object.hasOwn(options, "prior")
    ? options.prior
    : previousRow(engine.store, scoped, id);
  const baselineSnapshot = options.baselineSnapshot ?? emptySnapshot();
  const baseline =
    options.baseline ?? (prior ? "previous_investigation" : "none");
  const baselineId = options.baselineId ?? (prior ? prior.id : null);
  if (!options.id) {
    const placeholder = InvestigateResult.parse({
      ...planBody(engine, kind, scoped),
      id,
      status: "partial",
      mode: "execute",
      network: engine.config.network === true,
      mutation: true,
    });
    writeRow(engine.store, {
      id,
      target: scoped,
      kind,
      started,
      finished: null,
      status: "partial",
      body: placeholder,
      snapshot: emptySnapshot(),
    });
  }
  const collected = pending.length
    ? await collectPassiveSources(engine, scoped, { only: pending })
    : { results: [] };
  const fresh = new Map(
    collected.results.map((result) => [result.adapter, publishResult(result)]),
  );
  const previous = new Map(
    (options.previousResults ?? []).map((result) => [result.adapter, result]),
  );
  const results = [];
  for (const adapter of adapters) {
    if (fresh.has(adapter.name)) results.push(fresh.get(adapter.name));
    else if (previous.has(adapter.name))
      results.push(previous.get(adapter.name));
  }
  const runIds = [...(options.runIds ?? [])];
  for (const result of collected.results) {
    if (result.run_id && !runIds.includes(result.run_id))
      runIds.push(result.run_id);
  }
  const snapshot = snapshotFor(engine.store, runIds);
  const linkedRows = linked(engine, scoped);
  const body = finish(engine, {
    id,
    kind,
    target: scoped,
    mode: "execute",
    network: engine.config.network === true,
    mutation: true,
    resumed: Boolean(options.resumed),
    active_collection: false,
    adapters,
    missing_keys: [
      ...new Set(
        adapters
          .filter((item) => item.enabled)
          .flatMap((item) => item.missing_required_env),
      ),
    ].sort(),
    results,
    links: linkedRows.links,
    links_truncated: linkedRows.links_truncated,
    diff: diffSnapshots(
      baseline,
      baseline === "none" ? null : baselineId,
      baseline === "previous_investigation" && prior
        ? JSON.parse(prior.snapshot)
        : baselineSnapshot,
      snapshot,
    ),
    limitations: INVESTIGATION_LIMITATIONS,
    ...(enabled.length ? {} : { code: "ADAPTER_DISABLED" }),
  });
  writeRow(engine.store, {
    id,
    target: scoped,
    kind,
    started,
    finished: new Date().toISOString(),
    status: body.status,
    body,
    snapshot,
  });
  return body;
}

export function initializeInvestigations(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS investigations(
      id TEXT PRIMARY KEY,
      target TEXT NOT NULL,
      kind TEXT NOT NULL,
      started TEXT NOT NULL,
      finished TEXT,
      status TEXT NOT NULL,
      body TEXT NOT NULL,
      snapshot TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS investigations_target
      ON investigations(target, started);`);
}

export async function runInvestigation(engine, input = {}) {
  const request = InvestigateInput.parse(input);
  if (request.resume && !request.id)
    throw new Error("INVESTIGATION_ID_REQUIRED");
  if (request.id && !request.execute && !request.resume) {
    const row = readRow(engine.store, request.id);
    return InvestigateResult.parse({
      ...row.body,
      mode: "stored",
      mutation: false,
      network: false,
      resumed: false,
    });
  }
  if (!request.execute && !request.resume) {
    if (!request.target) throw new Error("TARGET_REQUIRED");
    const { kind, target } = classifiedTarget(request.target);
    assertScoped(engine, kind, target);
    return InvestigateResult.parse(planBody(engine, kind, target));
  }
  if (request.resume) {
    const row = readRow(engine.store, request.id);
    const storedResults = Array.isArray(row.body.results)
      ? row.body.results
      : [];
    const pending = adapterPlan(engine, row.kind)
      .filter((item) => item.enabled)
      .filter((item) =>
        needsRetry(
          storedResults.find((result) => result.adapter === item.name),
        ),
      )
      .map((item) => item.name);
    if (!pending.length) {
      return InvestigateResult.parse({
        ...row.body,
        mode: "stored",
        mutation: false,
        network: false,
        resumed: false,
      });
    }
    return executeInvestigation(engine, row.target, {
      id: row.id,
      started: row.started,
      pending,
      previousResults: storedResults,
      runIds: row.snapshot.run_ids ?? [],
      baseline: "previous_attempt",
      baselineId: row.id,
      baselineSnapshot: row.snapshot,
      resumed: true,
      prior: null,
    });
  }
  if (!request.target) throw new Error("TARGET_REQUIRED");
  return executeInvestigation(engine, request.target);
}
