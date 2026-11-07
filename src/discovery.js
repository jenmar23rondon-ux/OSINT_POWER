import { fetchText } from "./transport.js";

export const HISTORICAL_ADAPTERS = ["certspotter", "wayback"];
const opaque = (value) => {
  if (
    typeof value !== "string" ||
    !value.length ||
    value.length > 4096 ||
    /[\r\n\x00-\x1f]/.test(value)
  )
    throw new Error("INVALID_DISCOVERY_CURSOR");
  return value;
};

// One provider page per invocation. Response-controlled values are query parameters,
// never URLs. ProviderGate still meters every underlying HTTP request.
export async function collectDiscovery(
  adapter,
  target,
  config,
  dependencies = {},
) {
  const cursor = dependencies.discoveryCursor;
  const url = new URL(
    adapter === "certspotter"
      ? "https://api.certspotter.com/v1/issuances"
      : "https://web.archive.org/cdx/search/cdx",
  );
  const headers = {};
  if (adapter === "certspotter") {
    url.searchParams.set("domain", target);
    url.searchParams.set("include_subdomains", "true");
    url.searchParams.set("expand", "dns_names");
    if (cursor) url.searchParams.set("after", opaque(cursor));
    if (process.env.CERTSPOTTER_API_KEY)
      headers.Authorization = `Bearer ${process.env.CERTSPOTTER_API_KEY}`;
  } else {
    url.searchParams.set("url", target);
    url.searchParams.set("matchType", "domain");
    url.searchParams.set("output", "json");
    url.searchParams.set("fl", "timestamp,original,statuscode,digest");
    url.searchParams.set(
      "limit",
      String(
        Math.min(1000, Math.max(1, Math.floor(config.limits.maxRecords / 2))),
      ),
    );
    url.searchParams.set("showResumeKey", "true");
    if (cursor) url.searchParams.set("resumeKey", opaque(cursor));
  }
  return fetchText(
    url.href,
    config.limits,
    headers,
    dependencies.fetcher ?? fetch,
  );
}

export function decodeDiscovery(adapter, text) {
  const rows = JSON.parse(text);
  if (!Array.isArray(rows)) throw new Error("INVALID_DISCOVERY_RESPONSE");
  if (adapter === "certspotter") {
    for (const row of rows) {
      if (
        !row ||
        typeof row !== "object" ||
        !Array.isArray(row.dns_names) ||
        !row.dns_names.every((v) => typeof v === "string") ||
        typeof row.id !== "string"
      )
        throw new Error("INVALID_DISCOVERY_RESPONSE");
      opaque(row.id);
    }
    return {
      records: rows,
      next_cursor: rows.length ? rows.at(-1).id : null,
      exhausted: !rows.length,
    };
  }
  if (!rows.length) return { records: [], next_cursor: null, exhausted: true };
  const header = rows.shift();
  if (
    JSON.stringify(header) !==
    JSON.stringify(["timestamp", "original", "statuscode", "digest"])
  )
    throw new Error("INVALID_DISCOVERY_RESPONSE");
  let cursor = null;
  const emptyIndex = rows.findIndex((r) => Array.isArray(r) && r.length === 0);
  if (emptyIndex !== -1) {
    if (
      emptyIndex !== rows.length - 2 ||
      !Array.isArray(rows.at(-1)) ||
      rows.at(-1).length !== 1
    )
      throw new Error("INVALID_DISCOVERY_RESPONSE");
    cursor = opaque(rows.at(-1)[0]);
    rows.splice(emptyIndex);
  }
  if (
    rows.some(
      (r) =>
        !Array.isArray(r) ||
        r.length !== 4 ||
        !r.every((v) => typeof v === "string"),
    )
  )
    throw new Error("INVALID_DISCOVERY_RESPONSE");
  return { records: rows, next_cursor: cursor, exhausted: cursor === null };
}

export function archiveTimestamp(value) {
  if (!/^\d{14}$/.test(value)) throw new Error("INVALID_ARCHIVE_TIMESTAMP");
  const iso = `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(8, 10)}:${value.slice(10, 12)}:${value.slice(12, 14)}.000Z`;
  if (!Number.isFinite(Date.parse(iso)) || new Date(iso).toISOString() !== iso)
    throw new Error("INVALID_ARCHIVE_TIMESTAMP");
  return iso;
}
