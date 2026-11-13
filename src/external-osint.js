import { z } from "zod";
import { ImportInput } from "./schema.js";

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
const externalAdapters = ["maigret"];

export const ExternalOsintImportInput = ImportInput.extend({
  adapter: z.enum(externalAdapters),
  observed_at: z.iso.datetime({ offset: true }),
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
            type: z.enum(["username", "profile"]),
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
  if (
    !run ||
    !externalAdapters.some((adapter) => run.adapter === "import:" + adapter) ||
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
        run.adapter.slice("import:".length),
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
