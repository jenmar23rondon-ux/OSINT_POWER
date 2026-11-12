import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { Resolver } from "node:dns/promises";
import { z } from "zod";
import { domain } from "./scope.js";

const RECORD_LABEL = "_osint-power-verification";
const CHALLENGE_MS = 60 * 60 * 1000;
const PROOF_MS = 30 * 24 * 60 * 60 * 1000;
const PROVIDER = "dns:system";
const TOKEN = /^osint-power=[A-Za-z0-9_-]{43}$/;
const timestamp = z.iso.datetime();
const date = (milliseconds) =>
  milliseconds === null ? null : new Date(milliseconds).toISOString();
const hashToken = (token) => createHash("sha256").update(token).digest();
const nowFor = (engine) => (engine.dependencies.now ?? Date.now)();

export const DomainChallengeInput = z
  .object({ target: z.string().min(1).max(253) })
  .strict();
export const DomainControlIdInput = z.object({ id: z.uuid() }).strict();
export const DomainControlHistoryInput = DomainChallengeInput.extend({
  limit: z.number().int().min(1).max(50).default(20),
  offset: z.number().int().min(0).max(10000).default(0),
});
const domainControlRecord = z
  .object({
    id: z.uuid(),
    domain: z.string(),
    record_name: z.string(),
    method: z.literal("dns_txt"),
    status: z.enum(["pending", "verified", "expired", "revoked"]),
    issued_at: timestamp,
    challenge_expires_at: timestamp,
    verified_at: timestamp.nullable(),
    proof_expires_at: timestamp.nullable(),
    revoked_at: timestamp.nullable(),
    observed_txt_sha256: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .nullable(),
  })
  .strict();
export const DomainControlHistoryResult = z
  .object({
    domain: z.string(),
    as_of: timestamp,
    items: z.array(domainControlRecord).max(50),
    next_offset: z.number().int().nonnegative().nullable(),
  })
  .strict();

function configuredDomain(scope, value) {
  const target = domain(value);
  if (!scope.domains.includes(target) || !scope.host(target))
    throw new Error("DOMAIN_CONTROL_REQUIRES_CONFIGURED_DOMAIN");
  return target;
}

function statusOf(row, now) {
  if (row.revoked_at !== null) return "revoked";
  if (row.verified_at !== null)
    return now < row.proof_expires_at ? "verified" : "expired";
  return now < row.challenge_expires_at ? "pending" : "expired";
}

function present(row, now) {
  return {
    id: row.id,
    domain: row.domain,
    record_name: row.record_name,
    method: "dns_txt",
    status: statusOf(row, now),
    issued_at: date(row.issued_at),
    challenge_expires_at: date(row.challenge_expires_at),
    verified_at: date(row.verified_at),
    proof_expires_at: date(row.proof_expires_at),
    revoked_at: date(row.revoked_at),
    observed_txt_sha256: row.verified_at === null ? null : row.token_sha256,
  };
}

function challengeById(store, scope, id) {
  const row = store.db
    .prepare("SELECT * FROM domain_control_challenges WHERE id=?")
    .get(id);
  if (!row) throw new Error("DOMAIN_CHALLENGE_NOT_FOUND");
  configuredDomain(scope, row.domain);
  return row;
}

export function issueDomainChallenge(engine, input) {
  const { target: raw } = DomainChallengeInput.parse(input);
  const target = configuredDomain(engine.scope, raw);
  const name = RECORD_LABEL + "." + target;
  if (name.length > 253) throw new Error("DOMAIN_CONTROL_RECORD_TOO_LONG");
  const db = engine.store.db;
  db.exec("BEGIN IMMEDIATE");
  try {
    const now = nowFor(engine);
    const existing = db
      .prepare(
        `
      SELECT 1 FROM domain_control_challenges
      WHERE domain=? AND verified_at IS NULL AND revoked_at IS NULL AND challenge_expires_at>?
    `,
      )
      .get(target, now);
    if (existing) throw new Error("DOMAIN_CHALLENGE_ALREADY_PENDING");
    const id = randomUUID();
    const value = "osint-power=" + randomBytes(32).toString("base64url");
    db.prepare(
      `
      INSERT INTO domain_control_challenges
        (id,domain,record_name,token_sha256,issued_at,challenge_expires_at)
      VALUES (?,?,?,?,?,?)
    `,
    ).run(
      id,
      target,
      name,
      hashToken(value).toString("hex"),
      now,
      now + CHALLENGE_MS,
    );
    const row = challengeById(engine.store, engine.scope, id);
    const result = { ...present(row, now), txt_value: value };
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

export function domainControlHistory(store, scope, input, now = Date.now()) {
  const { target: raw, limit, offset } = DomainControlHistoryInput.parse(input);
  const target = configuredDomain(scope, raw);
  const rows = store.db
    .prepare(
      `
    SELECT * FROM domain_control_challenges WHERE domain=?
    ORDER BY issued_at DESC,id DESC LIMIT ? OFFSET ?
  `,
    )
    .all(target, limit + 1, offset);
  return {
    domain: target,
    as_of: date(now),
    items: rows.slice(0, limit).map((row) => present(row, now)),
    next_offset:
      rows.length > limit && offset + limit <= 10000 ? offset + limit : null,
  };
}

async function resolveChallenge(engine, name, signal) {
  signal?.throwIfAborted();
  const timeout = Math.min(engine.config.limits.timeoutMs, 5000);
  const resolver =
    engine.dependencies.domainControlResolver ??
    new Resolver({ timeout, tries: 1 });
  const cancel = () => resolver.cancel();
  const timer = setTimeout(cancel, timeout);
  signal?.addEventListener("abort", cancel, { once: true });
  try {
    return await resolver.resolveTxt(name + ".");
  } catch (error) {
    signal?.throwIfAborted();
    if (["ENODATA", "ENOTFOUND"].includes(error.code)) return [];
    engine.providers.failure(PROVIDER, "DNS_LOOKUP_FAILED");
    throw new Error("DNS_LOOKUP_FAILED");
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
  }
}

export async function verifyDomainChallenge(engine, input, signal) {
  const { id } = DomainControlIdInput.parse(input);
  const pending = () => {
    const row = challengeById(engine.store, engine.scope, id);
    if (statusOf(row, nowFor(engine)) !== "pending")
      throw new Error("DOMAIN_CHALLENGE_NOT_PENDING");
    return row;
  };
  pending();
  if (!engine.config.network) throw new Error("NETWORK_DISABLED");
  if (!engine.config.active) throw new Error("ACTIVE_DISABLED");
  await engine.providers.before(PROVIDER, signal);
  const row = pending();
  const records = await resolveChallenge(engine, row.record_name, signal);
  signal?.throwIfAborted();
  engine.providers.success(PROVIDER);

  const expected = Buffer.from(row.token_sha256, "hex");
  const found = records.some((chunks) => {
    // TXT chunks belong to one resource record. Separate records are distinct.
    const text = chunks.join("");
    return TOKEN.test(text) && timingSafeEqual(hashToken(text), expected);
  });
  if (!found) throw new Error("DOMAIN_CONTROL_TXT_NOT_FOUND");
  const now = nowFor(engine);
  const proof = engine.store.db
    .prepare(
      `
    UPDATE domain_control_challenges SET verified_at=?,proof_expires_at=?
    WHERE id=? AND verified_at IS NULL AND revoked_at IS NULL AND challenge_expires_at>?
    RETURNING *
  `,
    )
    .get(now, now + PROOF_MS, id, now);
  if (!proof) throw new Error("DOMAIN_CHALLENGE_NOT_PENDING");
  return present(proof, now);
}

export function revokeDomainChallenge(engine, input) {
  const { id } = DomainControlIdInput.parse(input);
  challengeById(engine.store, engine.scope, id);
  const now = nowFor(engine);
  engine.store.db
    .prepare(
      `
    UPDATE domain_control_challenges SET revoked_at=? WHERE id=? AND revoked_at IS NULL
  `,
    )
    .run(now, id);
  return present(challengeById(engine.store, engine.scope, id), now);
}
