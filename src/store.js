import { DatabaseSync } from "node:sqlite";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { Observation, QueryInput } from "./schema.js";
import { normalized } from "./scope.js";

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, canonical(value[k])]),
    );
  return value;
}
export const hash = (value) =>
  createHash("sha256")
    .update(JSON.stringify(canonical(value)))
    .digest("hex");
export class Store {
  constructor(path = ":memory:") {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path, { timeout: 5000 });
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS entities(id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, entity_id TEXT NOT NULL REFERENCES entities(id), source TEXT NOT NULL, confidence REAL NOT NULL, timestamp TEXT NOT NULL, evidence TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS obs_entity ON observations(entity_id);
      CREATE TABLE IF NOT EXISTS edges(id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT NOT NULL, relation TEXT NOT NULL, observation_id TEXT NOT NULL REFERENCES observations(id));
      CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, expires INTEGER NOT NULL, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, adapter TEXT NOT NULL, target TEXT NOT NULL, started TEXT NOT NULL, finished TEXT, status TEXT NOT NULL, summary TEXT);
      PRAGMA user_version=1;`);
  }
  bindScope(scope) {
    const fingerprint = hash(scope);
    this.db
      .prepare("INSERT OR IGNORE INTO settings VALUES('scope', ?)")
      .run(fingerprint);
    if (
      this.db.prepare("SELECT value FROM settings WHERE key='scope'").get()
        .value !== fingerprint
    )
      throw new Error("SCOPE_DATABASE_MISMATCH");
  }
  ingest(items) {
    // Validate the entire batch before changing state.
    const observations = items.map((item) =>
      Observation.parse({ ...item, value: normalized(item.type, item.value) }),
    );
    let inserted = 0;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const o of observations) {
        const entityId = hash([o.type, o.value]);
        const observationId = hash([entityId, o.source, o.evidence]);
        const existed = this.db
          .prepare("SELECT 1 FROM observations WHERE id=?")
          .get(observationId);
        const now = new Date().toISOString();
        this.db
          .prepare(
            `INSERT INTO entities VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen`,
          )
          .run(entityId, o.type, o.value, now, now);
        this.db
          .prepare(
            `INSERT INTO observations VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen, timestamp=excluded.timestamp, confidence=excluded.confidence`,
          )
          .run(
            observationId,
            entityId,
            o.source,
            o.confidence,
            o.timestamp,
            JSON.stringify(o.evidence),
            now,
            now,
          );
        if (!existed) inserted++;
        const { host, relation, relatedType, relatedValue } = o.evidence;
        if (o.type === "ip" && host)
          this.edge(
            hash(["domain", host]),
            entityId,
            "resolves_to",
            observationId,
          );
        if (o.type === "url")
          this.edge(
            hash(["domain", new URL(o.value).hostname]),
            entityId,
            "serves",
            observationId,
          );
        if (o.type === "profile" && o.evidence.username)
          this.edge(
            hash(["username", o.evidence.username]),
            entityId,
            "username_match",
            observationId,
          );
        if (relation && relatedType && relatedValue)
          this.edge(
            entityId,
            hash([relatedType, relatedValue]),
            relation,
            observationId,
          );
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return {
      observations: observations.length,
      inserted,
      repeated: observations.length - inserted,
    };
  }
  edge(from, to, relation, observation) {
    this.db
      .prepare("INSERT OR IGNORE INTO edges VALUES(?,?,?,?,?)")
      .run(
        hash([from, to, relation, observation]),
        from,
        to,
        relation,
        observation,
      );
  }
  query(input = {}) {
    const { type, limit, cursor } = QueryInput.parse(input);
    const clauses = ["id > ?"];
    const args = [cursor ?? ""];
    if (type) {
      clauses.push("type = ?");
      args.push(type);
    }
    const rows = this.db
      .prepare(
        `SELECT * FROM entities WHERE ${clauses.join(" AND ")} ORDER BY id LIMIT ?`,
      )
      .all(...args, limit + 1);
    const more = rows.length > limit;
    const items = rows.slice(0, limit).map((row) => {
      const sources = this.db
        .prepare(
          "SELECT DISTINCT source FROM observations WHERE entity_id=? ORDER BY source LIMIT 20",
        )
        .all(row.id)
        .map((x) => x.source);
      const best = this.db
        .prepare(
          "SELECT MAX(confidence) AS confidence, COUNT(*) AS count FROM observations WHERE entity_id=?",
        )
        .get(row.id);
      return {
        ...row,
        sources,
        evidence_count: best.count,
        confidence: best.confidence,
        confidence_basis: "maximum source assessment; sources may overlap",
      };
    });
    return {
      items,
      next_cursor: more ? items.at(-1).id : null,
      limit,
      total: this.db
        .prepare(
          `SELECT COUNT(*) AS n FROM entities ${type ? "WHERE type=?" : ""}`,
        )
        .get(...(type ? [type] : [])).n,
    };
  }
  evidence(entityId, limit = 25, offset = 0) {
    if (
      !/^[a-f0-9]{64}$/.test(entityId) ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 100 ||
      !Number.isInteger(offset) ||
      offset < 0
    )
      throw new Error("INVALID_PAGINATION");
    const rows = this.db
      .prepare(
        "SELECT * FROM observations WHERE entity_id=? ORDER BY id LIMIT ? OFFSET ?",
      )
      .all(entityId, limit + 1, offset);
    return {
      items: rows.slice(0, limit).map((r) => ({
        ...r,
        evidence: JSON.parse(r.evidence),
        untrusted: true,
      })),
      next_offset: rows.length > limit ? offset + limit : null,
    };
  }
  graph(limit = 50, offset = 0) {
    if (
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 100 ||
      !Number.isInteger(offset) ||
      offset < 0
    )
      throw new Error("INVALID_PAGINATION");
    const rows = this.db
      .prepare(
        `SELECT e.*, a.value AS from_value, b.value AS to_value FROM edges e JOIN entities a ON a.id=e.from_id JOIN entities b ON b.id=e.to_id ORDER BY e.id LIMIT ? OFFSET ?`,
      )
      .all(limit + 1, offset);
    return {
      items: rows.slice(0, limit),
      next_offset: rows.length > limit ? offset + limit : null,
      note: "Relations describe evidence, not ownership or identity.",
    };
  }
  cached(key) {
    const row = this.db
      .prepare("SELECT value FROM cache WHERE key=? AND expires>?")
      .get(key, Date.now());
    return row ? JSON.parse(row.value) : null;
  }
  cache(key, value, ttlSeconds) {
    this.db
      .prepare("INSERT OR REPLACE INTO cache VALUES(?,?,?)")
      .run(key, Date.now() + ttlSeconds * 1000, JSON.stringify(value));
  }
  start(adapter, target) {
    const id = randomUUID();
    this.db
      .prepare("INSERT INTO runs VALUES(?,?,?,?,?,?,?)")
      .run(
        id,
        adapter,
        target,
        new Date().toISOString(),
        null,
        "running",
        null,
      );
    return id;
  }
  finish(id, status, summary) {
    this.db
      .prepare("UPDATE runs SET finished=?, status=?, summary=? WHERE id=?")
      .run(new Date().toISOString(), status, JSON.stringify(summary), id);
  }
  runs(limit = 20) {
    return this.db
      .prepare("SELECT * FROM runs ORDER BY started DESC LIMIT ?")
      .all(limit)
      .map((r) => ({
        ...r,
        summary: r.summary ? JSON.parse(r.summary) : null,
      }));
  }
  close() {
    this.db.close();
  }
}
