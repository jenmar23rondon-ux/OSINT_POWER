import { z } from "zod";
import { EntityType } from "./schema.js";
import { normalized } from "./scope.js";

const RELATIONS = [
  "mailbox_on_domain",
  "shared_handle",
  "github_login",
  "github_commit_email",
  "github_profile_email",
  "gravatar_profile",
  "keybase_account",
];

const WHY = {
  mailbox_on_domain:
    "The mailbox uses this domain. That connects the address to the domain. It does not show who controls the mailbox.",
  shared_handle:
    "The mailbox local part matches this username. A shared handle is not an identity.",
  github_login:
    "A public GitHub profile or key was collected for this username. The login matches. It does not prove who controls the account.",
  github_commit_email:
    "A public GitHub event lists this email on a commit for this login. The address was published with the login. It does not prove one person controls both.",
  github_profile_email:
    "The public GitHub profile lists this email for this login. A listed address is not proof a person controls both.",
  gravatar_profile:
    "Gravatar returned a profile URL for this email hash. The profile is a candidate account, not a confirmed person.",
  keybase_account:
    "Keybase returned this username. That is a public account lookup, not identity confirmation.",
};

const CONFIDENCE = {
  mailbox_on_domain: 0.6,
  shared_handle: 0.25,
  github_login: 0.55,
  github_commit_email: 0.7,
  github_profile_email: 0.65,
  gravatar_profile: 0.4,
  keybase_account: 0.5,
};

export const CorrelationLink = z
  .object({
    from_id: z.string().regex(/^[a-f0-9]{64}$/),
    to_id: z.string().regex(/^[a-f0-9]{64}$/),
    from_type: EntityType,
    from_value: z.string().min(1).max(2048),
    to_type: EntityType,
    to_value: z.string().min(1).max(2048),
    relation: z.enum(RELATIONS),
    confidence: z.number().min(0).max(1),
    why: z.string().min(1).max(500),
    sources: z.array(z.string().min(1).max(80)).min(1).max(20),
    candidate: z.literal(true),
    identity: z.literal(false),
  })
  .strict();

function entityMap(rows) {
  return new Map(rows.map((row) => [row.id, row]));
}

function usernameFor(usernames, value) {
  const exact = usernames.find((row) => row.value === value);
  if (exact) return exact;
  const folded = usernames.filter(
    (row) => row.value.toLowerCase() === String(value).toLowerCase(),
  );
  return folded.length === 1 ? folded[0] : undefined;
}

function addLink(links, from, to, relation, source) {
  if (!from || !to || from.id === to.id) return;
  const key = `${from.id}\0${to.id}\0${relation}`;
  const existing = links.get(key);
  if (existing) {
    if (!existing.sources.includes(source)) existing.sources.push(source);
    return;
  }
  links.set(key, {
    from_id: from.id,
    to_id: to.id,
    from_type: from.type,
    from_value: from.value,
    to_type: to.type,
    to_value: to.value,
    relation,
    confidence: CONFIDENCE[relation],
    why: WHY[relation],
    sources: [source],
    candidate: true,
    identity: false,
  });
}

export function correlateEntities(store, scope) {
  const rows = store.db
    .prepare(
      `SELECT id, type, value FROM entities
       WHERE type IN ('email','username','profile','domain')
       ORDER BY id LIMIT 301`,
    )
    .all();
  const truncatedEntities = rows.length > 300;
  const entities = rows.slice(0, 300);
  const emails = entities.filter(
    (row) => row.type === "email" && scope.allows("email", row.value),
  );
  const emailByValue = new Map(emails.map((row) => [row.value, row]));
  const domains = entities.filter(
    (row) => row.type === "domain" && scope.allows("domain", row.value),
  );
  const domainByValue = new Map(domains.map((row) => [row.value, row]));
  const usernames = entities.filter(
    (row) =>
      row.type === "username" &&
      (scope.username(row.value) ||
        emails.some(
          (email) => email.value.split("@")[0] === row.value.toLowerCase(),
        )),
  );
  const profiles = entities.filter((row) => row.type === "profile");
  const byId = entityMap([...emails, ...domains, ...usernames, ...profiles]);
  const links = new Map();
  if (byId.size) {
    const ids = [...byId.keys()];
    const observations = store.db
      .prepare(
        `SELECT entity_id, source, evidence FROM observations
         WHERE entity_id IN (${ids.map(() => "?").join(",")})
         ORDER BY id LIMIT 800`,
      )
      .all(...ids);
    for (const email of emails) {
      const domainName = email.value.split("@")[1];
      addLink(
        links,
        email,
        domainByValue.get(domainName),
        "mailbox_on_domain",
        "derived",
      );
      addLink(
        links,
        email,
        usernameFor(usernames, email.value.split("@")[0]),
        "shared_handle",
        "derived",
      );
    }
    for (const observation of observations) {
      let evidence = {};
      try {
        evidence = JSON.parse(observation.evidence);
      } catch {
        continue;
      }
      const entity = byId.get(observation.entity_id);
      if (!entity) continue;
      const user = evidence.username
        ? usernameFor(usernames, evidence.username)
        : undefined;
      let account;
      if (typeof evidence.account === "string") {
        try {
          account = emailByValue.get(normalized("email", evidence.account));
        } catch {
          account = undefined;
        }
      }
      if (
        entity.type === "email" &&
        user &&
        observation.source === "github-events"
      )
        addLink(links, entity, user, "github_commit_email", observation.source);
      if (
        entity.type === "email" &&
        user &&
        observation.source === "github-profile"
      )
        addLink(
          links,
          entity,
          user,
          "github_profile_email",
          observation.source,
        );
      if (
        entity.type === "profile" &&
        user &&
        ["github-profile", "github-keys"].includes(observation.source)
      )
        addLink(links, user, entity, "github_login", observation.source);
      if (entity.type === "profile" && user && observation.source === "keybase")
        addLink(links, user, entity, "keybase_account", observation.source);
      if (
        entity.type === "profile" &&
        account &&
        observation.source === "gravatar"
      )
        addLink(links, account, entity, "gravatar_profile", observation.source);
    }
  }
  const items = [...links.values()]
    .map((link) => ({ ...link, sources: [...link.sources].sort() }))
    .sort(
      (left, right) =>
        right.confidence - left.confidence ||
        left.relation.localeCompare(right.relation) ||
        left.from_value.localeCompare(right.from_value) ||
        left.to_value.localeCompare(right.to_value),
    );
  return {
    items: items.slice(0, 50).map((link) => CorrelationLink.parse(link)),
    truncated: truncatedEntities || items.length > 50,
  };
}
