import { createHash } from "node:crypto";
import { z } from "zod";
import { hash } from "./store.js";
import { sources } from "./state.js";

export const BundleInput = z
  .object({
    run_id: z.uuid(),
    limit: z.number().int().min(1).max(100).default(25),
    cursor: z
      .string()
      .regex(/^[a-f0-9]{64}:[a-f0-9]{64}$/)
      .optional(),
  })
  .strict();
const redact = (value) => {
  if (typeof value === "string")
    return value.replace(
      /(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})/g,
      "[REDACTED]",
    );
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, redact(v)]),
    );
  return value;
};
const captureRow = (row) =>
  redact({
    observation_id: row.observation_id,
    entity_id: row.entity_id,
    collector: row.collector,
    target: row.target,
    payload: JSON.parse(row.payload),
    provenance: JSON.parse(row.provenance),
  });
const keyFor = (row) =>
  `${row.observation_id}:${hash([row.collector, row.target])}`;
const query =
  "SELECT * FROM run_observations WHERE run_id=? ORDER BY observation_id,collector,target";

function manifestFor(store, runId) {
  const run = store.db
    .prepare(
      "SELECT id,adapter,target,started,finished,status FROM runs WHERE id=?",
    )
    .get(runId);
  if (!run) throw new Error("RUN_NOT_FOUND");
  if (store.db.prepare("SELECT 1 FROM jobs WHERE id=?").get(runId))
    throw new Error("USE_IMMUTABLE_SNAPSHOT_ID");
  if (run.status === "running" || !run.finished)
    throw new Error("RUN_STILL_ACTIVE");
  const summaries = sources(store, runId);
  if (!summaries.length) throw new Error("SNAPSHOT_UNAVAILABLE");
  const digest = createHash("sha256");
  let count = 0;
  for (const row of store.db.prepare(query).iterate(runId)) {
    digest.update(hash(captureRow(row)) + "\n");
    count++;
  }
  return {
    run: { ...run },
    capture_count: count,
    capture_digest: digest.digest("hex"),
    source_summaries: summaries.map((s) => ({
      collector: s.collector,
      target: s.target,
      status: s.status,
      cached: s.cached,
      truncated: s.truncated,
      collected_at: s.collected_at,
      coverage_complete:
        s.summary.coverage_complete ??
        (!s.cached && !s.truncated && s.status === "completed"),
      input_hash: s.summary.input_hash ?? null,
      configuration_digest: s.summary.configuration_digest ?? null,
      collector_version: s.summary.collector_version ?? "not_recorded",
    })),
    excerpt_policy:
      "Normalized observations and selected evidence only; raw source bodies, credentials and complete documents are not retained.",
    authenticity:
      "Unkeyed integrity digests detect changes; they do not authenticate the publisher or prove the source was truthful.",
  };
}
function seal(manifest, captures, page) {
  const payload = {
    format: "osint-power-evidence",
    schema_version: "0.4",
    manifest,
    captures,
    page,
  };
  return {
    ...payload,
    integrity: {
      algorithm: "sha256-canonical-json-v1",
      manifest_sha256: hash(manifest),
      page_sha256: hash(payload),
    },
  };
}
export function exportEvidence(store, input) {
  const { run_id, limit, cursor } = BundleInput.parse(input);
  const manifest = manifestFor(store, run_id);
  const captures = [];
  let found = !cursor,
    more = false,
    last;
  // Stream the immutable capture; never accumulate the full run for an MCP page.
  for (const row of store.db.prepare(query).iterate(run_id)) {
    const key = keyFor(row);
    if (!found) {
      if (key === cursor) found = true;
      continue;
    }
    if (captures.length === limit) {
      more = true;
      break;
    }
    captures.push(captureRow(row));
    last = key;
  }
  if (!found) throw new Error("INVALID_BUNDLE_CURSOR");
  return seal(manifest, captures, {
    limit,
    total: manifest.capture_count,
    returned: captures.length,
    next_cursor: more ? last : null,
    complete: !cursor && !more,
  });
}
export function completeEvidence(store, runId) {
  const manifest = manifestFor(store, z.uuid().parse(runId));
  if (manifest.capture_count > 10000)
    throw new Error("BUNDLE_TOO_LARGE_USE_PAGINATION");
  const captures = [];
  let bytes = 0;
  for (const row of store.db.prepare(query).iterate(runId)) {
    const capture = captureRow(row);
    bytes += Buffer.byteLength(JSON.stringify(capture));
    if (bytes > 40_000_000) throw new Error("BUNDLE_TOO_LARGE_USE_PAGINATION");
    captures.push(capture);
  }
  return seal(manifest, captures, {
    limit: 10000,
    total: captures.length,
    returned: captures.length,
    next_cursor: null,
    complete: true,
  });
}
export function verifyEvidence(bundle) {
  if (
    !bundle ||
    bundle.format !== "osint-power-evidence" ||
    bundle.schema_version !== "0.4" ||
    !Array.isArray(bundle.captures) ||
    !bundle.manifest ||
    !bundle.page ||
    !bundle.integrity
  )
    throw new Error("INVALID_EVIDENCE_BUNDLE");
  const { integrity, ...payload } = bundle;
  let valid =
    integrity.algorithm === "sha256-canonical-json-v1" &&
    integrity.manifest_sha256 === hash(bundle.manifest) &&
    integrity.page_sha256 === hash(payload) &&
    bundle.page.returned === bundle.captures.length &&
    bundle.page.total === bundle.manifest.capture_count;
  if (bundle.page.complete) {
    const digest = createHash("sha256");
    for (const capture of bundle.captures) digest.update(hash(capture) + "\n");
    valid &&=
      bundle.page.total === bundle.captures.length &&
      bundle.page.next_cursor === null &&
      bundle.manifest.capture_digest === digest.digest("hex");
  }
  return {
    status: valid ? "completed" : "failed",
    code: valid ? "INTEGRITY_VALID" : "INTEGRITY_MISMATCH",
    complete: valid && bundle.page.complete === true,
    captures: bundle.captures.length,
    authenticity: "not_authenticated",
    interpretation: bundle.page.complete
      ? "Complete capture integrity checked"
      : "Page integrity checked; complete capture requires all pages",
  };
}
