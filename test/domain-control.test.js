import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createSocket } from "node:dgram";
import { Resolver } from "node:dns/promises";
import { once } from "node:events";
import test from "node:test";
import {
  DomainControlHistoryResult,
  domainControlHistory,
  issueDomainChallenge,
  revokeDomainChallenge,
  verifyDomainChallenge,
} from "../src/domain-control.js";
import { Engine } from "../src/engine.js";
import { Store } from "../src/store.js";

const day = 86_400_000;
const hour = 3_600_000;
const domain = "example.com";
const recordName = "_osint-power-verification." + domain;

function workspace(t, config = {}, dependencies = {}) {
  const store = new Store();
  t.after(() => store.close());
  let time = Date.parse("2026-11-10T00:00:00.000Z");
  const engine = new Engine(
    {
      version: 1,
      scope: {
        domains: [domain, "example.net"],
        excludeDomains: ["example.net"],
      },
      network: true,
      active: true,
      limits: { minIntervalMs: 0 },
      ...config,
    },
    store,
    { now: () => time, ...dependencies },
  );
  return {
    engine,
    issue: () => issueDomainChallenge(engine, { target: domain }),
    history: (page = {}) =>
      DomainControlHistoryResult.parse(
        domainControlHistory(
          store,
          engine.scope,
          { target: domain, ...page },
          time,
        ),
      ),
    advance: (duration) => {
      time += duration;
    },
  };
}

test("issuance is local, exact-scope and stores only a digest", async (t) => {
  const { engine, issue, history } = workspace(t, {
    network: false,
    active: false,
  });
  for (const target of ["other.example", "child.example.com", "example.net"])
    assert.throws(
      () => issueDomainChallenge(engine, { target }),
      /DOMAIN_CONTROL_REQUIRES_CONFIGURED_DOMAIN/,
    );
  const challenge = issueDomainChallenge(engine, { target: "EXAMPLE.COM." });
  assert.equal(challenge.domain, domain);
  assert.equal(challenge.record_name, recordName);
  assert.match(challenge.txt_value, /^osint-power=[A-Za-z0-9_-]{43}$/);
  assert.throws(issue, /DOMAIN_CHALLENGE_ALREADY_PENDING/);
  const { txt_value, ...publicChallenge } = challenge;
  assert.deepEqual(history().items, [publicChallenge]);
  assert.equal(publicChallenge.observed_txt_sha256, null);
  const stored = engine.store.db
    .prepare("SELECT * FROM domain_control_challenges WHERE id=?")
    .get(challenge.id);
  assert.equal(
    stored.token_sha256,
    createHash("sha256").update(txt_value).digest("hex"),
  );
  assert.equal(Object.values(stored).includes(txt_value), false);
  await assert.rejects(
    verifyDomainChallenge(engine, { id: challenge.id }),
    /NETWORK_DISABLED/,
  );
  assert.deepEqual(engine.providers.health().providers, []);
});

test("an enabled network still requires active mode", async (t) => {
  const { engine, issue } = workspace(t, { active: false });
  const { id } = issue();
  await assert.rejects(
    verifyDomainChallenge(engine, { id }),
    /ACTIVE_DISABLED/,
  );
  assert.deepEqual(engine.providers.health().providers, []);
});

test("only one matching TXT record verifies an unused challenge", async (t) => {
  let records = [];
  const names = [];
  const { engine, issue, history, advance } = workspace(
    t,
    {},
    {
      domainControlResolver: {
        async resolveTxt(name) {
          names.push(name);
          return records;
        },
        cancel() {},
      },
    },
  );
  const { id, txt_value } = issue();
  const chunks = [txt_value.slice(0, 16), txt_value.slice(16)];
  records = chunks.map((chunk) => [chunk]);
  await assert.rejects(
    verifyDomainChallenge(engine, { id }),
    /DOMAIN_CONTROL_TXT_NOT_FOUND/,
  );
  assert.equal(history().items[0].status, "pending");
  records = [["unrelated"], chunks];
  const proof = await verifyDomainChallenge(engine, { id });
  assert.equal(proof.status, "verified");
  assert.equal(
    Date.parse(proof.proof_expires_at) - Date.parse(proof.verified_at),
    30 * day,
  );
  assert.equal(
    proof.observed_txt_sha256,
    createHash("sha256").update(txt_value).digest("hex"),
  );
  assert.deepEqual(history().items, [proof]);
  await assert.rejects(
    verifyDomainChallenge(engine, { id }),
    /DOMAIN_CHALLENGE_NOT_PENDING/,
  );
  assert.deepEqual(names, [recordName + ".", recordName + "."]);
  assert.equal(
    engine.store.db.prepare("SELECT COUNT(*) AS n FROM observations").get().n,
    0,
  );

  advance(30 * day);
  assert.equal(history().items[0].status, "expired");
  const expired = issue();
  advance(hour);
  await assert.rejects(
    verifyDomainChallenge(engine, { id: expired.id }),
    /DOMAIN_CHALLENGE_NOT_PENDING/,
  );
  const replacement = issue();
  assert.notEqual(replacement.txt_value, expired.txt_value);
  const first = history({ limit: 1 });
  assert.deepEqual(
    first.items.map((item) => item.id),
    [replacement.id],
  );
  assert.equal(first.next_offset, 1);
  assert.deepEqual(
    history({ limit: 1, offset: first.next_offset }).items.map(
      (item) => item.id,
    ),
    [expired.id],
  );
  records = [[replacement.txt_value]];
  const renewed = await verifyDomainChallenge(engine, { id: replacement.id });
  const revoked = revokeDomainChallenge(engine, { id: replacement.id });
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.verified_at, renewed.verified_at);
  assert.equal(revoked.observed_txt_sha256, renewed.observed_txt_sha256);
});

test("revocation during DNS resolution prevents verification from committing", async (t) => {
  const started = Promise.withResolvers();
  const reply = Promise.withResolvers();
  const { engine, issue, history, advance } = workspace(
    t,
    {},
    {
      domainControlResolver: {
        resolveTxt() {
          started.resolve();
          return reply.promise;
        },
        cancel() {},
      },
    },
  );
  const { id, txt_value } = issue();
  const verification = verifyDomainChallenge(engine, { id });
  await started.promise;
  const revoked = revokeDomainChallenge(engine, { id });
  advance(day);
  assert.deepEqual(revokeDomainChallenge(engine, { id }), revoked);
  reply.resolve([[txt_value]]);
  await assert.rejects(verification, /DOMAIN_CHALLENGE_NOT_PENDING/);
  assert.deepEqual(history().items, [revoked]);
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.verified_at, null);
});

test("the native resolver verifies a TXT response from a loopback DNS fixture", async (t) => {
  const socket = createSocket("udp4");
  socket.bind(0, "127.0.0.1");
  await once(socket, "listening");
  t.after(() => socket.close());
  const resolver = new Resolver({ timeout: 1000, tries: 1 });
  resolver.setServers([`127.0.0.1:${socket.address().port}`]);
  const { engine, issue } = workspace(
    t,
    {},
    { domainControlResolver: resolver },
  );
  const { id, txt_value } = issue();
  let question;
  socket.on("message", (query, remote) => {
    const labels = [];
    let end = 12;
    while (query[end]) {
      const length = query[end++];
      labels.push(query.toString("ascii", end, end + length));
      end += length;
    }
    question = { name: labels.join("."), type: query.readUInt16BE(end + 1) };
    const header = Buffer.from(query.subarray(0, end + 5));
    header.writeUInt16BE(0x8180, 2);
    header.writeUInt16BE(1, 6);
    header.writeUInt16BE(0, 10);
    const answer = Buffer.alloc(13);
    answer.writeUInt16BE(0xc00c, 0);
    answer.writeUInt16BE(16, 2);
    answer.writeUInt16BE(1, 4);
    answer.writeUInt16BE(txt_value.length + 1, 10);
    answer[12] = txt_value.length;
    socket.send(
      Buffer.concat([header, answer, Buffer.from(txt_value)]),
      remote.port,
      remote.address,
    );
  });
  assert.equal(
    (await verifyDomainChallenge(engine, { id })).status,
    "verified",
  );
  assert.deepEqual(question, { name: recordName, type: 16 });
});
