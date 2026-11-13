import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Engine } from "../src/engine.js";
import { Store, hash } from "../src/store.js";
import { explainEntity } from "../src/state.js";
import { RESULT_SCHEMAS, toolResponse } from "../src/contracts.js";
import {
  SCHEMA_VERSION,
  recordDecision,
  reviewQueue,
  showEntity,
} from "../src/review.js";

const at = "2026-06-01T00:00:00.000Z";
const settings = {
  version: 1,
  scope: { domains: ["example.com"], usernames: ["alice"] },
};
function releaseStore(store) {
  try {
    // Drop the WAL sidecars before unlink. Windows keeps the directory locked
    // while those files are still open.
    store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } catch {
    // The handle may already be closed.
  }
  store.close();
}
function removeTemp(dir) {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
function workspace(t, path) {
  const store = new Store(path);
  t.after(() => releaseStore(store));
  return { store, engine: new Engine(settings, store) };
}
function line(row) {
  return JSON.stringify({
    confidence: 0.6,
    timestamp: at,
    ...row,
    evidence: row.evidence ?? {},
  });
}
function load(engine, rows) {
  const result = engine.import({
    adapter: "jsonl",
    data: rows.map(line).join("\n"),
  });
  assert.equal(result.skipped, 0);
  assert.equal(result.invalid, 0);
  return result;
}
function entity(store, type, value) {
  const found = store
    .query({ type, limit: 100 })
    .items.find((item) => item.value === value);
  assert.ok(found, `${type} ${value}`);
  return found;
}
function assertContract(name, value) {
  const parsed = RESULT_SCHEMAS[name].safeParse(value);
  assert.equal(
    parsed.success,
    true,
    JSON.stringify(parsed.error?.issues?.slice(0, 4)),
  );
  assert.equal(toolResponse(name, value).ok, true);
}
const github = {
  type: "profile",
  value: "https://github.com/alice",
  source: "github-profile",
  evidence: { username: "alice", name: "Alice Doe", public_company: "Acme" },
};
const email = {
  type: "email",
  value: "alice@example.com",
  source: "people-search",
  evidence: { name: "Alice Doe", public_company: "Globex" },
};

test("analyst decisions are append-only and survive reopening the database", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-review-"));
  const path = join(dir, "state.sqlite");
  // The reopened handle must be the one closed before cleanup. Windows denies
  // removal while SQLite still has the file.
  let store = new Store(path);
  const engine = new Engine(settings, store);
  t.after(() => {
    releaseStore(store);
    removeTemp(dir);
  });
  load(engine, [
    {
      type: "domain",
      value: "example.com",
      source: "registry",
      evidence: {},
    },
  ]);
  const id = entity(store, "domain", "example.com").id;
  assert.deepEqual(
    reviewQueue(store).items.map((item) => item.queue_reasons),
    [["needs_decision"]],
  );
  const accepted = recordDecision(store, {
    subject_kind: "entity",
    subject_id: id,
    decision: "accept",
    reason: "  Matches the scoped domain.  ",
    analyst_id: "analyst-1",
  });
  assert.equal(accepted.appended, true);
  assert.equal(accepted.current.decision, "accept");
  assert.equal(accepted.current.reason, "Matches the scoped domain.");
  assert.equal(accepted.current.analyst_id, "analyst-1");
  assert.match(accepted.current.recorded_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(reviewQueue(store).total, 0);
  const revised = recordDecision(store, {
    subject_kind: "entity",
    subject_id: id,
    decision: "needs-more-evidence",
    reason: "Need a second registry extract.",
    analyst_id: "analyst-2",
  });
  assert.equal(revised.history.length, 2);
  assert.equal(revised.history[0].decision, "accept");
  assert.equal(revised.history[0].reason, "Matches the scoped domain.");
  assert.notEqual(revised.history[0].id, revised.history[1].id);
  assert.equal(revised.current.decision, "needs-more-evidence");
  assert.equal(
    reviewQueue(store).items[0].queue_reasons[0],
    "needs_more_evidence",
  );
  const findingId = store.evidence(id).items[0].id;
  const finding = recordDecision(store, {
    subject_kind: "finding",
    subject_id: findingId,
    decision: "reject",
    reason: "Duplicate capture of the same registry row.",
    analyst_id: "analyst-1",
  });
  assert.equal(finding.history.length, 1);
  assert.equal(finding.current.subject_kind, "finding");
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM review_decisions").get().n,
    3,
  );
  assert.equal(explainEntity(store, id).assessment.review_status, "unreviewed");
  assertContract("record_decision", revised);
  releaseStore(store);
  store = new Store(path);
  const view = showEntity(store, { entity_id: id });
  assert.equal(view.decision_history.length, 2);
  assert.equal(view.decision_history[0].decision, "accept");
  assert.equal(view.current_decision.decision, "needs-more-evidence");
  assert.equal(view.finding_decisions[0].observation_id, findingId);
  assert.equal(view.finding_decisions[0].current_decision.decision, "reject");
  assert.equal(view.finding_decisions[0].history_count, 1);
  assertContract("show_entity", view);
  assert.throws(
    () =>
      recordDecision(store, {
        subject_kind: "entity",
        subject_id: id,
        decision: "accept",
        reason: " ",
        analyst_id: "analyst-1",
      }),
    /INVALID_INPUT/,
  );
  assert.throws(
    () =>
      recordDecision(store, {
        subject_kind: "entity",
        subject_id: "a".repeat(64),
        decision: "reject",
        reason: "Missing subject.",
        analyst_id: "analyst-1",
      }),
    /SUBJECT_NOT_FOUND/,
  );
});

test("the same name or handle across sources is never a confirmed identity", (t) => {
  const { store, engine } = workspace(t);
  load(engine, [github]);
  load(engine, [
    {
      type: "profile",
      value: "https://gitlab.com/alice",
      source: "gitlab-profile",
      evidence: { username: "alice", name: "Alice Doe" },
    },
  ]);
  load(engine, [email]);
  const profileId = entity(store, "profile", "https://github.com/alice").id;
  const view = showEntity(store, { entity_id: profileId });
  const emailLink = view.candidates.find((link) => link.other.type === "email");
  assert.ok(emailLink);
  assert.equal(emailLink.status, "candidate");
  assert.equal(emailLink.basis, "shared_handle");
  assert.equal(emailLink.confidence <= 0.4, true);
  assert.equal(
    emailLink.blocked_reason,
    "shared_name_or_handle_is_not_identity",
  );
  assert.equal(emailLink.shared_handles.includes("alice"), true);
  assert.equal(emailLink.shared_names.includes("alice doe"), true);
  assert.equal(emailLink.shared_identifiers.length, 0);
  assert.equal(
    emailLink.evidence.some((item) => item.role === "shared_handle"),
    true,
  );
  assert.equal(view.confirmed_links.length, 0);
  assert.equal(view.candidates.length, 2);
  const conflict = view.contradictions.find(
    (item) =>
      item.scope === "linked_entity" && item.attribute === "public_company",
  );
  assert.ok(conflict);
  assert.equal(conflict.independent_disagreement, true);
  assert.deepEqual(conflict.values.map((item) => item.value).sort(), [
    "Acme",
    "Globex",
  ]);
  assert.equal(
    store.db
      .prepare(
        "SELECT COUNT(*) AS n FROM entity_links WHERE status='confirmed'",
      )
      .get().n,
    0,
  );
  recordDecision(store, {
    subject_kind: "entity",
    subject_id: profileId,
    decision: "accept",
    reason:
      "The GitHub profile is in scope, but the email is only a handle match.",
    analyst_id: "analyst-1",
  });
  const accepted = showEntity(store, { entity_id: profileId });
  assert.equal(accepted.current_decision.decision, "accept");
  assert.equal(accepted.confirmed_links.length, 0);
  assert.equal(accepted.candidates.length, 2);
  const queued = reviewQueue(store).items.find(
    (item) => item.entity_id === profileId,
  );
  assert.equal(queued.queue_reasons.includes("unconfirmed_candidate"), true);
  assert.equal(queued.queue_reasons.includes("contradiction"), true);
  assert.equal(
    view.rules.some((rule) => rule.includes("never confirms")),
    true,
  );
});

test("independent non-name identifiers can confirm a link, and dependent ones cannot", (t) => {
  const confirmed = workspace(t);
  load(confirmed.engine, [
    {
      type: "profile",
      value: "https://github.com/alice",
      source: "github-profile",
      evidence: { username: "alice", account: "alice@example.com" },
    },
  ]);
  load(confirmed.engine, [
    {
      type: "email",
      value: "alice@example.com",
      source: "business-context",
      evidence: { profile_url: "https://github.com/alice" },
    },
  ]);
  const confirmedView = showEntity(confirmed.store, {
    entity_id: entity(confirmed.store, "profile", "https://github.com/alice")
      .id,
  });
  assert.equal(confirmedView.candidates.length, 0);
  assert.equal(confirmedView.confirmed_links.length, 1);
  const link = confirmedView.confirmed_links[0];
  assert.equal(link.status, "confirmed");
  assert.equal(link.basis, "independent_corroboration");
  assert.equal(link.blocked_reason, null);
  assert.equal(link.independent_corroboration >= 2, true);
  assert.equal(link.confidence >= 0.7 && link.confidence <= 0.95, true);
  assert.equal(
    link.shared_identifiers.includes("email:alice@example.com"),
    true,
  );
  const sources = new Set(link.evidence.map((item) => item.source));
  assert.equal(sources.has("github-profile"), true);
  assert.equal(sources.has("business-context"), true);
  assert.equal(
    link.evidence.some((item) => item.role === "corroborating_identifier"),
    true,
  );
  assertContract("show_entity", confirmedView);

  const sameRun = workspace(t);
  load(sameRun.engine, [
    {
      type: "profile",
      value: "https://github.com/alice",
      source: "github-profile",
      evidence: { username: "alice", account: "alice@example.com" },
    },
    {
      type: "email",
      value: "alice@example.com",
      source: "business-context",
      evidence: { profile_url: "https://github.com/alice" },
    },
  ]);
  const sameRunView = showEntity(sameRun.store, {
    entity_id: entity(sameRun.store, "email", "alice@example.com").id,
  });
  assert.equal(sameRunView.confirmed_links.length, 0);
  assert.equal(sameRunView.candidates[0].basis, "unconfirmed_identifier");
  assert.equal(sameRunView.candidates[0].independent_corroboration < 2, true);
  assert.equal(
    sameRunView.candidates[0].blocked_reason,
    "corroboration_not_independent",
  );

  for (const evidence of [
    { profile_url: "https://github.com/alice", mirror_of: "github-profile" },
    { profile_url: "https://github.com/alice", upstream: "github-profile" },
  ]) {
    const blocked = workspace(t);
    load(blocked.engine, [
      {
        type: "profile",
        value: "https://github.com/alice",
        source: "github-profile",
        evidence: { username: "alice", account: "alice@example.com" },
      },
    ]);
    load(blocked.engine, [
      {
        type: "email",
        value: "alice@example.com",
        source: "directory-copy",
        evidence,
      },
    ]);
    const blockedView = showEntity(blocked.store, {
      entity_id: entity(blocked.store, "profile", "https://github.com/alice")
        .id,
    });
    assert.equal(blockedView.confirmed_links.length, 0);
    assert.equal(blockedView.candidates[0].status, "candidate");
    assert.equal(blockedView.candidates[0].independent_corroboration < 2, true);
  }
});

test("corroboration cannot pool different identifiers or repeat one source", (t) => {
  const { store, engine } = workspace(t);
  const left = "https://github.com/alice";
  const right = "https://gitlab.com/alice";
  const leftId = hash(["profile", left]);
  const rightId = hash(["profile", right]);
  const row = (value, source, evidence) => ({
    type: "profile",
    value,
    source,
    evidence: { username: "alice", name: "Alice Doe", ...evidence },
  });
  // Both records repeat one account assertion in separate imports. A second
  // identifier has a different source, but also lacks corroboration.
  load(engine, [row(left, "directory", { account: "alice@example.com" })]);
  load(engine, [row(right, "directory", { account: "alice@example.com" })]);
  const profile_url = "https://example.com/team/alice";
  load(engine, [
    row(left, "profile-catalog", { profile_url }),
    row(right, "profile-catalog", { profile_url }),
  ]);
  const before = showEntity(store, { entity_id: leftId });
  const candidate = before.candidates.find((link) => link.other.id === rightId);
  assert.equal(candidate.shared_identifiers.length, 2);
  assert.equal(candidate.independent_corroboration, 1);
  assert.equal(
    before.confirmed_links.some((link) => link.other.id === rightId),
    false,
  );
  assertContract("show_entity", before);

  load(engine, [
    row(right, "owner-published-directory", { account: "alice@example.com" }),
  ]);
  const after = showEntity(store, { entity_id: leftId });
  assert.equal(
    after.confirmed_links.find((link) => link.other.id === rightId)
      .independent_corroboration,
    2,
  );
});

test("reused image fingerprints cannot corroborate an identity link", (t) => {
  const { store, engine } = workspace(t);
  const fingerprint = "a".repeat(64);
  const left = { ...github, evidence: { username: "alice", fingerprint } };
  const right = {
    ...left,
    source: "profile-catalog",
    value: "https://gitlab.com/alice",
  };
  load(engine, [left]);
  load(engine, [right]);
  const result = showEntity(store, {
    entity_id: hash(["profile", left.value]),
  });
  assert.equal(result.confirmed_links.length, 0);
  assert.equal(result.candidates[0].basis, "shared_handle");
  assert.deepEqual(result.candidates[0].shared_identifiers, []);
});

test("disagreements are flagged, and only independent sources count as corroboration", (t) => {
  const sameRun = workspace(t);
  load(sameRun.engine, [
    {
      type: "domain",
      value: "example.com",
      source: "registry-a",
      evidence: { public_company: "Acme" },
    },
    {
      type: "domain",
      value: "example.com",
      source: "registry-b",
      evidence: { public_company: "Globex" },
    },
  ]);
  const same = showEntity(sameRun.store, {
    entity_id: entity(sameRun.store, "domain", "example.com").id,
  });
  assert.equal(same.independence.observations, 2);
  assert.equal(same.independence.independent_groups, 1);
  assert.equal(same.contradictions[0].attribute, "public_company");
  assert.equal(same.contradictions[0].scope, "entity");
  assert.equal(same.contradictions[0].independent_disagreement, false);
  assert.equal(same.candidates.length, 0);
  assert.equal(same.confirmed_links.length, 0);
  const queued = reviewQueue(sameRun.store);
  assert.equal(queued.items[0].contradictions, 1);
  assert.equal(queued.items[0].queue_reasons.includes("contradiction"), true);
  assertContract("list_review_queue", queued);

  const split = workspace(t);
  load(split.engine, [
    {
      type: "domain",
      value: "example.com",
      source: "registry-a",
      evidence: { public_company: "Acme" },
    },
  ]);
  load(split.engine, [
    {
      type: "domain",
      value: "example.com",
      source: "registry-b",
      evidence: { public_company: "Globex" },
    },
  ]);
  load(split.engine, [
    {
      type: "domain",
      value: "example.com",
      source: "registry-c",
      evidence: { public_company: "ACME" },
    },
  ]);
  const disagreed = showEntity(split.store, {
    entity_id: entity(split.store, "domain", "example.com").id,
  });
  assert.equal(disagreed.contradictions[0].values.length, 2);
  assert.equal(disagreed.contradictions[0].independent_disagreement, true);

  const counted = workspace(t);
  load(counted.engine, [
    { type: "domain", value: "example.com", source: "crtsh", evidence: {} },
  ]);
  load(counted.engine, [
    {
      type: "domain",
      value: "example.com",
      source: "subfinder",
      evidence: { upstream: "crtsh" },
    },
  ]);
  load(counted.engine, [
    { type: "domain", value: "example.com", source: "dnsx", evidence: {} },
  ]);
  const groups = showEntity(counted.store, {
    entity_id: entity(counted.store, "domain", "example.com").id,
  });
  assert.equal(groups.independence.observations, 3);
  assert.equal(groups.independence.independent_groups, 2);

  const mirrored = workspace(t);
  load(mirrored.engine, [
    {
      type: "domain",
      value: "example.com",
      source: "directory-a",
      evidence: { mirror_of: "export-1" },
    },
  ]);
  load(mirrored.engine, [
    {
      type: "domain",
      value: "example.com",
      source: "directory-b",
      evidence: { mirror_of: "export-1" },
    },
  ]);
  assert.equal(
    showEntity(mirrored.store, {
      entity_id: entity(mirrored.store, "domain", "example.com").id,
    }).independence.independent_groups,
    1,
  );
});

test("review queue pages are stable and an accept drops entities with no open issue", (t) => {
  const { store, engine } = workspace(t);
  load(
    engine,
    ["a", "b", "c"].map((name) => ({
      type: "domain",
      value: `${name}.example.com`,
      source: "subfinder",
      evidence: {},
    })),
  );
  const first = reviewQueue(store, { limit: 2 });
  assert.equal(first.total, 3);
  assert.equal(first.returned, 2);
  const second = reviewQueue(store, { limit: 2, cursor: first.next_cursor });
  assert.equal(second.returned, 1);
  assert.equal(second.next_cursor, null);
  assert.equal(
    new Set([...first.items, ...second.items].map((item) => item.entity_id))
      .size,
    3,
  );
  for (const item of [...first.items, ...second.items])
    recordDecision(store, {
      subject_kind: "entity",
      subject_id: item.entity_id,
      decision: "accept",
      reason: "In-scope hostname with no conflicting attribute.",
      analyst_id: "analyst-1",
    });
  assert.equal(reviewQueue(store).total, 0);
});

test("schema v5 migrates an existing database without rewriting its evidence", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-migrate-"));
  t.after(() => removeTemp(dir));
  const path = join(dir, "legacy.sqlite");
  const id = hash(["domain", "kept.example.com"]);
  const legacy = new DatabaseSync(path);
  legacy.exec(`CREATE TABLE entities(
    id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)`);
  legacy
    .prepare("INSERT INTO entities VALUES(?,?,?,?,?)")
    .run(
      id,
      "domain",
      "kept.example.com",
      "2020-01-01T00:00:00.000Z",
      "2020-01-01T00:00:00.000Z",
    );
  legacy.exec("PRAGMA user_version=4");
  legacy.close();
  let store = new Store(path);
  t.after(() => releaseStore(store));
  assert.equal(
    store.db.prepare("PRAGMA user_version").get().user_version,
    SCHEMA_VERSION,
  );
  assert.equal(
    store.db.prepare("SELECT value FROM entities WHERE id=?").get(id).value,
    "kept.example.com",
  );
  assert.equal(
    store.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='review_decisions'",
      )
      .get().name,
    "review_decisions",
  );
  assert.equal(reviewQueue(store).total, 1);
  recordDecision(store, {
    subject_kind: "entity",
    subject_id: id,
    decision: "reject",
    reason: "Legacy row is out of the current question.",
    analyst_id: "analyst-1",
  });
  releaseStore(store);
  store = new Store(path);
  assert.equal(showEntity(store, { entity_id: id }).decision_history.length, 1);
  releaseStore(store);
  const bumped = new DatabaseSync(path);
  bumped.exec(`PRAGMA user_version=${SCHEMA_VERSION + 1}`);
  bumped.close();
  assert.throws(() => new Store(path), /DATABASE_VERSION_TOO_NEW/);
  const preserved = new DatabaseSync(path);
  assert.equal(
    preserved.prepare("PRAGMA user_version").get().user_version,
    SCHEMA_VERSION + 1,
  );
  assert.equal(
    preserved.prepare("SELECT value FROM entities WHERE id=?").get(id).value,
    "kept.example.com",
  );
  assert.equal(
    preserved.prepare("SELECT COUNT(*) AS n FROM review_decisions").get().n,
    1,
  );
  preserved.close();
});

test("CLI review commands record decisions and keep same-handle links unconfirmed", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-review-cli-"));
  t.after(() => removeTemp(dir));
  const config = join(dir, "config.json");
  const db = join(dir, "state.sqlite");
  const file = join(dir, "findings.jsonl");
  writeFileSync(config, JSON.stringify(settings));
  writeFileSync(file, [github, email].map(line).join("\n"));
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const call = (args) =>
    JSON.parse(
      execFileSync(
        process.execPath,
        [cli, ...args, "--config", config, "--db", db],
        { encoding: "utf8" },
      ),
    ).result;
  assert.equal(
    call(["import", "--adapter", "jsonl", "--file", file]).inserted,
    2,
  );
  const queue = call(["review-queue", "--limit", "10"]);
  const profile = queue.items.find((item) => item.type === "profile");
  assert.equal(profile.candidate_links >= 1, true);
  const shown = call(["show-entity", "--id", profile.entity_id]);
  assert.equal(shown.confirmed_links.length, 0);
  assert.equal(shown.candidates[0].status, "candidate");
  assert.equal(
    shown.candidates[0].blocked_reason,
    "shared_name_or_handle_is_not_identity",
  );
  const decided = call([
    "decide",
    "--subject",
    "entity",
    "--id",
    profile.entity_id,
    "--decision",
    "needs-more-evidence",
    "--reason",
    "Same handle on GitHub and in an email.",
    "--analyst",
    "analyst-1",
  ]);
  assert.equal(decided.current.decision, "needs-more-evidence");
  assert.equal(decided.history.length, 1);
  assert.equal(
    call(["show-entity", "--id", profile.entity_id]).confirmed_links.length,
    0,
  );
  assert.throws(() =>
    call(["decide", "--subject", "entity", "--id", profile.entity_id]),
  );
  assert.throws(() => call(["explain"]));
});

test(
  "MCP review tools are additive and preserve the existing explain_entity contract",
  { timeout: 20_000 },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "osint-review-mcp-"));
    const config = join(dir, "config.json");
    writeFileSync(config, JSON.stringify({ ...settings, network: false }));
    const client = new Client({ name: "osint-review-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../src/mcp.js", import.meta.url))],
      env: { ...process.env, OSINT_POWER_CONFIG: config },
      stderr: "pipe",
    });
    t.after(async () => {
      await client.close();
      removeTemp(dir);
    });
    await client.connect(transport);
    const list = await client.listTools();
    const names = new Set(list.tools.map((tool) => tool.name));
    assert.equal(list.tools.length, 49);
    for (const name of [
      "list_review_queue",
      "record_decision",
      "show_entity",
      "explain_entity",
      "query_findings",
    ])
      assert.equal(names.has(name), true);
    const call = async (name, args = {}) => {
      const response = await client.callTool({ name, arguments: args });
      assert.equal(response.isError, undefined, name);
      assert.notEqual(
        response.structuredContent?.result?.code,
        "INTERNAL_OUTPUT_VALIDATION",
        name,
      );
      return response.structuredContent.result;
    };
    assert.equal(
      (
        await call("import_findings", {
          adapter: "jsonl",
          data: [github, email].map(line).join("\n"),
        })
      ).inserted,
      2,
    );
    const queue = await call("list_review_queue", { limit: 10 });
    const profile = queue.items.find((item) => item.type === "profile");
    const shown = await call("show_entity", { entity_id: profile.entity_id });
    assert.equal(shown.confirmed_links.length, 0);
    assert.equal(shown.candidates[0].basis, "shared_handle");
    const decided = await call("record_decision", {
      subject_kind: "entity",
      subject_id: profile.entity_id,
      decision: "needs-more-evidence",
      reason: "Handle match only.",
      analyst_id: "analyst-1",
    });
    assert.equal(decided.appended, true);
    assert.equal(decided.history.length, 1);
    const explained = await call("explain_entity", {
      entity_id: profile.entity_id,
    });
    assert.equal(explained.assessment.review_status, "unreviewed");
    assert.equal(explained.assessment.identity, "candidate_unverified");
  },
);
