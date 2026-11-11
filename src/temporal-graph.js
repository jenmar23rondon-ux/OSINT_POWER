import { z } from "zod";
import { domain, normalized } from "./scope.js";
import { hash } from "./store.js";

const instant = z.iso.datetime({ offset: true });
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const cursorFormat = /^[a-f0-9]{64}:-?\d+(?:\.\d+)?:[1-9]\d*$/;

export const TemporalGraphInput = z
  .object({
    host: z.string().min(1).max(253).optional(),
    ip: z.string().min(1).max(45).optional(),
    since: instant,
    until: instant,
    as_of: instant,
    limit: z.number().int().min(1).max(100).default(25),
    cursor: z.string().max(120).regex(cursorFormat).optional(),
  })
  .strict()
  .refine((input) => input.host || input.ip, {
    message: "Provide a host, an IP, or both.",
  });

export const TemporalGraphResult = z
  .object({
    host: z.string().nullable(),
    ip: z.string().nullable(),
    since: instant,
    until: instant,
    as_of: instant,
    items: z
      .array(
        z
          .object({
            from: z.string(),
            to: z.string(),
            relation: z.enum(["resolves_to", "serves", "historically_served"]),
            observed_at: instant,
            collected_at: instant,
            known_at: instant,
            run_id: z.uuid(),
            observation_id: digest,
            collector: z.enum([
              "dnsx",
              "import:dnsx",
              "httpx",
              "import:httpx",
              "wayback",
              "import:wayback",
            ]),
            source_family: z.enum(["dns", "direct_observation", "web_archive"]),
            confidence: z.number().min(0).max(1),
          })
          .strict(),
      )
      .max(100),
    limit: z.number().int().min(1).max(100),
    next_cursor: z.string().regex(cursorFormat).nullable(),
    interpretation: z.string(),
  })
  .strict();

// Origin captures retain their original clock and scope. Mirrors, cached
// copies and the mutable workspace graph cannot introduce historical edges.
const query = (host, ip) => `
  WITH captures AS (
    SELECT o.rowid AS capture_id, o.run_id, o.observation_id, o.collector,
      json_extract(o.payload, '$.evidence.host') AS host,
      e.value AS endpoint,
      CASE
        WHEN e.type='ip' THEN 'resolves_to'
        WHEN o.collector IN ('wayback', 'import:wayback') THEN 'historically_served'
        ELSE 'serves'
      END AS relation,
      CASE
        WHEN e.type='ip' THEN 'dns'
        WHEN o.collector IN ('wayback', 'import:wayback') THEN 'web_archive'
        ELSE 'direct_observation'
      END AS source_family,
      json_extract(o.payload, '$.confidence') AS confidence,
      json_extract(o.provenance, '$.observed_at') AS observed_at,
      json_extract(o.provenance, '$.collected_at') AS collected_at,
      r.finished AS finished_at
    FROM run_observations o
    JOIN runs r ON r.id=o.run_id AND r.adapter=o.collector
    JOIN entities e ON e.id=o.entity_id
    WHERE o.collector IN ('dnsx', 'import:dnsx', 'httpx', 'import:httpx', 'wayback', 'import:wayback')
      AND (
        (e.type='ip' AND o.collector IN ('dnsx', 'import:dnsx'))
        OR (e.type='url' AND o.collector IN ('httpx', 'import:httpx', 'wayback', 'import:wayback'))
      )
      AND o.run_id=json_extract(o.provenance, '$.origin_run_id')
      AND COALESCE(json_extract(o.provenance, '$.from_cache'), 0)=0
      AND r.status IN ('completed', 'partial')
      ${host ? "AND json_extract(o.payload, '$.evidence.host')=:host" : ""}
      ${ip ? "AND o.entity_id=:ip_id" : ""}
  ), history AS (
    SELECT *,
      unixepoch(observed_at, 'subsec') AS observed_time,
      max(unixepoch(collected_at, 'subsec'), unixepoch(finished_at, 'subsec')) AS known_time
    FROM captures c
    WHERE EXISTS (SELECT 1 FROM json_each(:domains) d
      WHERE c.host=d.value OR substr(c.host, -length(d.value)-1)='.' || d.value)
      AND NOT EXISTS (SELECT 1 FROM json_each(:excluded) d
        WHERE c.host=d.value OR substr(c.host, -length(d.value)-1)='.' || d.value)
  )
  SELECT *, strftime('%Y-%m-%dT%H:%M:%fZ', known_time, 'unixepoch') AS known_at
  FROM history
  WHERE observed_time>=:start AND observed_time<:end
    AND observed_time<=:cutoff AND known_time<=:cutoff
    AND (:after_time IS NULL OR (observed_time, capture_id)>(:after_time, :after_id))
  ORDER BY observed_time, capture_id
  LIMIT :limit
`;

export function temporalGraph(store, scope, input) {
  const parsed = TemporalGraphInput.safeParse(input);
  if (!parsed.success) throw new Error("INVALID_INPUT");
  const { limit, cursor } = parsed.data;
  const host = parsed.data.host ? domain(parsed.data.host) : null;
  if (host && !scope.host(host)) throw new Error("OUT_OF_SCOPE");
  const ip = parsed.data.ip ? normalized("ip", parsed.data.ip) : null;
  const start = Date.parse(parsed.data.since);
  const end = Date.parse(parsed.data.until);
  const cutoff = Date.parse(parsed.data.as_of);
  if (![start, end, cutoff].every(Number.isFinite) || start >= end)
    throw new Error("INVALID_TIME_RANGE");
  if (cutoff > Date.now()) throw new Error("AS_OF_IN_FUTURE");

  const identity = hash([host, ip, start, end, cutoff]);
  let afterTime = null;
  let afterId = 0;
  if (cursor) {
    const [filterHash, time, rowId] = cursor.split(":");
    afterTime = Number(time);
    afterId = Number(rowId);
    if (filterHash !== identity || !Number.isSafeInteger(afterId))
      throw new Error("INVALID_TEMPORAL_CURSOR");
  }
  const rows = store.db.prepare(query(host, ip)).all({
    ...(host ? { host } : {}),
    ...(ip ? { ip_id: hash(["ip", ip]) } : {}),
    domains: JSON.stringify(scope.domains),
    excluded: JSON.stringify(scope.excluded),
    start: start / 1000,
    end: end / 1000,
    cutoff: cutoff / 1000,
    after_time: afterTime,
    after_id: afterId,
    limit: limit + 1,
  });
  const page = rows.slice(0, limit);
  const last = page.at(-1);
  return {
    host,
    ip,
    since: new Date(start).toISOString(),
    until: new Date(end).toISOString(),
    as_of: new Date(cutoff).toISOString(),
    items: page.map((row) => ({
      from: row.host,
      to: row.endpoint,
      relation: row.relation,
      observed_at: row.observed_at,
      collected_at: row.collected_at,
      known_at: row.known_at,
      run_id: row.run_id,
      observation_id: row.observation_id,
      collector: row.collector,
      source_family: row.source_family,
      confidence: row.confidence,
    })),
    limit,
    next_cursor:
      rows.length > limit
        ? `${identity}:${last.observed_time}:${last.capture_id}`
        : null,
    interpretation:
      "Each edge represents one recorded observation. Several DNS answers can coexist. Archive records describe historical captures. Continuous validity and ownership require separate evidence.",
  };
}
