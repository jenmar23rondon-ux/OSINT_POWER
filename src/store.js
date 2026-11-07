import { DatabaseSync } from "node:sqlite";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { Observation, QueryInput } from "./schema.js";
import { normalized } from "./scope.js";
import { employeeValue } from "./identity.js";

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
        const ev = o.evidence;
        if (o.type === "domain") {
          const company = this.db
            .prepare(
              "SELECT id, value FROM entities WHERE type='company' ORDER BY length(value) DESC",
            )
            .all()
            .find(
              (c) => o.value === c.value || o.value.endsWith("." + c.value),
            );
          if (company)
            this.edge(company.id, entityId, "contains_domain", observationId);
        }
        if (ev.company && o.type !== "company")
          this.edge(
            hash(["company", ev.company]),
            entityId,
            o.type === "employee"
              ? "professional_association"
              : o.type === "place"
                ? "public_office"
                : "public_context",
            observationId,
          );
        if (ev.person && ev.company && o.type !== "employee")
          this.edge(
            hash([
              "employee",
              employeeValue({ name: ev.person, companyDomain: ev.company }),
            ]),
            entityId,
            o.type === "profile"
              ? "candidate_profile"
              : o.type === "username"
                ? "candidate_alias"
                : "public_context",
            observationId,
          );
        if (o.type === "username" && ev.account)
          this.edge(
            hash(["email", ev.account]),
            entityId,
            "derived_alias",
            observationId,
          );
        if (o.type === "email")
          this.edge(
            hash(["company", o.value.split("@")[1]]),
            entityId,
            "public_email",
            observationId,
          );
        if (o.type === "breach" && ev.account)
          this.edge(
            hash(["email", ev.account]),
            entityId,
            "breach_association",
            observationId,
          );
        if (["network", "asn"].includes(o.type) && ev.ip)
          this.edge(
            hash(["ip", ev.ip]),
            entityId,
            o.type === "asn" ? "announced_by" : "registered_or_routed_network",
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
  domainEntities(type, target, limit = 10) {
    return this.db
      .prepare(
        "SELECT * FROM entities WHERE type=? AND (value=? OR value LIKE ? OR value LIKE ?) ORDER BY id LIMIT ?",
      )
      .all(type, target, "%." + target, "%@" + target, Math.min(100, limit));
  }
  ipHost(value, scope) {
    const rows = this.db
      .prepare(
        "SELECT o.evidence FROM observations o JOIN entities e ON e.id=o.entity_id WHERE e.type='ip' AND e.value=? LIMIT 100",
      )
      .all(value);
    for (const row of rows) {
      const host = JSON.parse(row.evidence).host;
      if (host && scope.allows("domain", host)) return host;
    }
    return null;
  }
  domainIPs(target, limit = 10) {
    return this.db
      .prepare(
        "SELECT DISTINCT ip.* FROM entities ip JOIN edges edge ON edge.to_id=ip.id AND edge.relation='resolves_to' JOIN entities host ON host.id=edge.from_id WHERE ip.type='ip' AND (host.value=? OR host.value LIKE ?) ORDER BY ip.id LIMIT ?",
      )
      .all(target, "%." + target, Math.min(100, limit));
  }
  contextEntities(type, target, limit = 25) {
    return this.db
      .prepare(
        "SELECT DISTINCT e.* FROM entities e JOIN observations o ON o.entity_id=e.id WHERE e.type=? AND json_extract(o.evidence,'$.company')=? ORDER BY e.id LIMIT ?",
      )
      .all(type, target, Math.min(100, limit));
  }
  findings(target, limit = 25) {
    const rows = this.db
      .prepare(
        "SELECT e.id,e.type,e.value,o.source,o.confidence,o.timestamp,o.evidence FROM entities e JOIN observations o ON o.entity_id=e.id WHERE e.value=? OR (e.type='domain' AND e.value LIKE ?) OR json_extract(o.evidence,'$.company')=? OR json_extract(o.evidence,'$.host')=? OR json_extract(o.evidence,'$.host') LIKE ? OR (e.type='email' AND e.value LIKE ?) OR json_extract(o.evidence,'$.account') LIKE ? ORDER BY o.last_seen DESC,o.id LIMIT ?",
      )
      .all(
        target,
        "%." + target,
        target,
        target,
        "%." + target,
        "%@" + target,
        "%@" + target,
        Math.min(100, limit),
      );
    return {
      items: rows.map((r) => ({
        ...r,
        evidence: JSON.parse(r.evidence),
        untrusted: true,
      })),
      limit,
      bounded: true,
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
