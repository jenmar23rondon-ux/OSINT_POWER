import { z } from "zod";
import { ImportInput } from "./schema.js";
import { domain } from "./scope.js";

const hashId = z.string().regex(/^[a-f0-9]{64}$/);
const username = z.string().regex(/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/);
const maigretRow = z.object({
  url_user: z.string().max(2048),
  status: z.object({
    username,
    site_name: z.string().min(1).max(80),
    url: z.string().max(2048),
    status: z.enum(["Claimed", "Available", "Unknown", "Illegal"]),
  }),
});
const maigretHosts = new Set(["github.com", "gitlab.com", "codeberg.org"]);
const spiderFootRow = z.object({
  data: z.string().min(1).max(253),
  event_type: z.string().min(1).max(80),
  module: z.string().min(1).max(80),
  false_positive: z.union([z.literal(0), z.literal(1)]),
  last_seen: z.string().regex(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/),
  scan_target: z.string().min(1).max(253),
});
export const EXTERNAL_OSINT_SOURCES = Object.freeze({
  maigret: "maigret",
  "spiderfoot-json": "spiderfoot",
});

export const ExternalOsintImportInput = ImportInput.extend({
  adapter: z.enum(Object.keys(EXTERNAL_OSINT_SOURCES)),
});

export function readMaigretReport(text, scope, observedAt, emit) {
  if (!observedAt) throw new Error("OBSERVED_AT_REQUIRED");
  const report = JSON.parse(text);
  if (!report || typeof report !== "object" || Array.isArray(report))
    throw new Error("INVALID_MAIGRET_REPORT");
  const stats = { skipped: 0, invalid: 0 };
  const timestamp = new Date(observedAt).toISOString();
  for (const [site, raw] of Object.entries(report)) {
    const parsed = maigretRow.safeParse(raw);
    if (!parsed.success || parsed.data.status.site_name !== site) {
      stats.invalid++;
      continue;
    }
    const { status, url_user } = parsed.data;
    if (
      status.status !== "Claimed" ||
      !scope.config.scope.usernames.includes(status.username)
    ) {
      stats.skipped++;
      continue;
    }
    let profile;
    try {
      profile = new URL(url_user);
      if (
        profile.href !== new URL(status.url).href ||
        profile.protocol !== "https:" ||
        profile.username ||
        profile.password ||
        profile.port ||
        profile.pathname.replace(/\/$/, "") !== "/" + status.username
      )
        throw new Error("INVALID_PROFILE_URL");
    } catch {
      stats.invalid++;
      continue;
    }
    if (!maigretHosts.has(profile.hostname)) {
      stats.skipped++;
      continue;
    }
    profile.pathname = "/" + status.username;
    profile.search = "";
    profile.hash = "";
    const evidence = {
      status: "reported_claimed",
      verification: "candidate",
      inferred: true,
      upstream: profile.hostname,
    };
    emit("username", status.username, evidence, 0.4, "maigret", timestamp);
    emit(
      "profile",
      profile.href,
      { ...evidence, username: status.username },
      0.4,
      "maigret",
      timestamp,
    );
  }
  return stats;
}

const datedEvent = z.iso.datetime({ offset: true });
const asciiHostname = /^[a-z0-9.-]+$/i;
const certificateEvents = new Set([
  "DOMAIN_NAME",
  "INTERNET_NAME",
  "INTERNET_NAME_UNRESOLVED",
]);

export function readSpiderFootReport(text, scope, sourceUtcOffset, emit) {
  const rows = JSON.parse(text);
  if (!Array.isArray(rows)) throw new Error("INVALID_SPIDERFOOT_REPORT");
  const stats = { skipped: 0, invalid: 0 };
  for (const raw of rows) {
    if (raw?.module !== "sfp_crt" || !certificateEvents.has(raw.event_type)) {
      stats.skipped++;
      continue;
    }
    const parsed = spiderFootRow.safeParse(raw);
    if (!parsed.success) {
      stats.invalid++;
      continue;
    }
    const row = parsed.data;
    if (row.false_positive === 1) {
      stats.skipped++;
      continue;
    }
    try {
      if (!asciiHostname.test(row.scan_target) || !asciiHostname.test(row.data))
        throw new Error("INVALID_DOMAIN");
      const target = domain(row.scan_target);
      const hostname = domain(row.data);
      if (
        !scope.domains.includes(target) ||
        !scope.host(target) ||
        !scope.host(hostname) ||
        (hostname !== target && !hostname.endsWith("." + target))
      ) {
        stats.skipped++;
        continue;
      }
      const time = datedEvent.parse(
        row.last_seen.replace(" ", "T") + sourceUtcOffset,
      );
      emit(
        "domain",
        hostname,
        {
          upstream: "crt.sh",
          record: "sfp_crt",
          historical: true,
          status: "reported",
          verification: "certificate_name_only",
        },
        0.65,
        "spiderfoot",
        new Date(time).toISOString(),
      );
    } catch {
      stats.invalid++;
    }
  }
  return stats;
}

export const CorrelateOsintInput = z
  .object({
    run_id: z.uuid(),
    limit: z.number().int().min(1).max(50).default(20),
    cursor: hashId.optional(),
  })
  .strict();

export const CorrelateOsintResult = z
  .object({
    run_id: z.uuid(),
    comparison: z.literal("exact_entity_overlap"),
    items: z
      .array(
        z
          .object({
            entity_id: hashId,
            type: z.enum(["username", "profile", "domain"]),
            value: z.string(),
            imported_observation_id: hashId,
            other_observations: z
              .array(z.object({ id: hashId, source: z.string() }).strict())
              .max(5),
            more_observations: z.boolean(),
          })
          .strict(),
      )
      .max(50),
    next_cursor: hashId.nullable(),
  })
  .strict();

export function correlateOsintResults(store, input) {
  const { run_id, limit, cursor } = CorrelateOsintInput.parse(input);
  const run = store.db
    .prepare("SELECT adapter,status FROM runs WHERE id=?")
    .get(run_id);
  const adapter =
    run?.adapter.startsWith("import:") && run.adapter.slice("import:".length);
  if (
    !Object.hasOwn(EXTERNAL_OSINT_SOURCES, adapter) ||
    !["completed", "partial"].includes(run.status)
  )
    throw new Error("EXTERNAL_IMPORT_NOT_FOUND");

  const page = store.db
    .prepare(
      `
    SELECT e.id AS entity_id, e.type, e.value, MIN(r.observation_id) AS imported_observation_id
    FROM run_observations r JOIN entities e ON e.id = r.entity_id
    WHERE r.run_id = ? AND e.id > ?
    GROUP BY e.id ORDER BY e.id LIMIT ?
  `,
    )
    .all(run_id, cursor ?? "", limit + 1);
  const otherObservations = store.db.prepare(`
    SELECT id,source FROM observations
    WHERE entity_id=? AND source<>?
    ORDER BY id LIMIT 6
  `);
  return {
    run_id,
    comparison: "exact_entity_overlap",
    items: page.slice(0, limit).map((item) => {
      const others = otherObservations.all(
        item.entity_id,
        EXTERNAL_OSINT_SOURCES[adapter],
      );
      return {
        ...item,
        other_observations: others.slice(0, 5),
        more_observations: others.length > 5,
      };
    }),
    next_cursor: page.length > limit ? page[limit - 1].entity_id : null,
  };
}
