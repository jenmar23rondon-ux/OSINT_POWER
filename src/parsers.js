import { basename } from "node:path";
import { Observation } from "./schema.js";
import { normalized } from "./scope.js";
import { parseBusiness, BreachSummary } from "./context.js";
import {
  decodeDiscovery,
  archiveTimestamp,
  HISTORICAL_ADAPTERS,
} from "./discovery.js";

const evidenceKeys = new Set([
  "host",
  "document",
  "field",
  "username",
  "status",
  "port",
  "technology",
  "record",
  "name",
  "account",
  "reason",
  "line",
  "rule",
  "fingerprint",
  "upstream",
  "inferred",
  "parser",
  "company",
  "person",
  "source_url",
  "place_kind",
  "verification",
  "ip",
  "country",
  "handle",
  "start",
  "end",
  "prefix",
  "mx",
  "mailbox",
  "catch_all",
  "date",
  "title",
  "certificate_cn",
  "certificate_issuer",
  "credential_kind",
  "provider",
  "public_company",
  "historical",
  "archive_timestamp",
  "valid_from",
  "valid_until",
]);
function sanitize(evidence) {
  if (typeof evidence.source_url === "string") {
    const u = new URL(evidence.source_url);
    if (!["https:", "http:"].includes(u.protocol) || u.username || u.password)
      throw new Error("INVALID_SOURCE_URL");
    u.search = "";
    u.hash = "";
    evidence = { ...evidence, source_url: u.href };
  }
  const scalar = (value) => {
    if (typeof value === "string")
      return value
        .slice(0, 500)
        .replace(
          /(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})/g,
          "[REDACTED]",
        );
    if (
      typeof value === "boolean" ||
      typeof value === "number" ||
      value === null
    )
      return value;
    return "[unsupported evidence value]";
  };
  return Object.fromEntries(
    Object.entries(evidence)
      .filter(([k]) => evidenceKeys.has(k))
      .map(([k, v]) => [
        k,
        Array.isArray(v) ? v.slice(0, 20).map(scalar) : scalar(v),
      ]),
  );
}
function records(text) {
  const data = text.trim();
  if (!data) return [];
  if (data.startsWith("[")) {
    const parsed = JSON.parse(data);
    if (!Array.isArray(parsed)) throw new Error("ARRAY_REQUIRED");
    return parsed;
  }
  try {
    return [JSON.parse(data)];
  } catch {
    return data
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      });
  }
}
export function csv(text) {
  const rows = [];
  let row = [],
    field = "",
    quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' && quoted && text[i + 1] === '"') {
      field += '"';
      i++;
    } else if (c === '"') quoted = !quoted;
    else if (c === "," && !quoted) {
      row.push(field);
      field = "";
    } else if (c === "\n" && !quoted) {
      row.push(field.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      field = "";
    } else field += c;
  }
  if (quoted) throw new Error("INVALID_CSV");
  if (field || row.length) {
    row.push(field.replace(/\r$/, ""));
    rows.push(row);
  }
  const headers = rows.shift() ?? [];
  return rows
    .filter((r) => r.some(Boolean))
    .map((r) => Object.fromEntries(headers.map((h, i) => [h, r[i] ?? ""])));
}
export function parse(adapter, text, scope, maxRecords = 2000, context = {}) {
  const items = [];
  let skipped = 0;
  let invalid = 0;
  let truncated = false;
  let discovery;
  const emit = (
    type,
    value,
    evidence = {},
    confidence = 0.65,
    source = adapter,
    timestamp = new Date().toISOString(),
  ) => {
    if (items.length >= maxRecords) {
      truncated = true;
      return;
    }
    try {
      if (type === "secret")
        evidence = {
          ...evidence,
          verification: "unverified",
          credential_kind: evidence.credential_kind ?? "possible_secret",
        };
      if (type === "secret")
        value = `${evidence.document}:${Number(evidence.line) || 0}:${String(evidence.rule ?? "unknown").slice(0, 100)}`;
      const valueNormalized = normalized(type, value);
      if (type === "url")
        evidence = {
          ...evidence,
          host: new URL(valueNormalized).hostname.replace(/^\[|\]$/g, ""),
        };
      const safeEvidence = sanitize(evidence);
      if (!scope.allows(type, valueNormalized, safeEvidence)) {
        skipped++;
        return;
      }
      items.push(
        Observation.parse({
          type,
          value: valueNormalized,
          source,
          confidence,
          timestamp,
          evidence: safeEvidence,
        }),
      );
    } catch {
      invalid++;
    }
  };
  if (HISTORICAL_ADAPTERS.includes(adapter)) {
    const page = decodeDiscovery(adapter, text);
    discovery = {
      next_cursor: page.next_cursor,
      exhausted: page.exhausted,
      records: page.records.length,
      coverage_mode: "incremental_page",
      coverage_complete: false,
    };
    for (const row of page.records) {
      if (adapter === "certspotter") {
        for (const name of row.dns_names)
          emit(
            "domain",
            name,
            {
              record: row.id,
              historical: true,
              ...(typeof row.not_before === "string"
                ? { valid_from: row.not_before }
                : {}),
              ...(typeof row.not_after === "string"
                ? { valid_until: row.not_after }
                : {}),
              verification: "certificate_name_only",
            },
            0.8,
          );
      } else {
        try {
          const timestamp = archiveTimestamp(row[0]);
          const archivedHost = new URL(normalized("url", row[1])).hostname;
          emit(
            "domain",
            archivedHost,
            {
              historical: true,
              archive_timestamp: timestamp,
              verification: "archived_hostname_live_status_unknown",
            },
            0.6,
            adapter,
            timestamp,
          );
          emit(
            "url",
            row[1],
            {
              historical: true,
              archive_timestamp: timestamp,
              status: row[2],
              fingerprint: row[3],
              source_url: "https://web.archive.org/",
              verification: "archived_capture_live_status_unknown",
            },
            0.65,
            adapter,
            timestamp,
          );
        } catch {
          invalid++;
        }
      }
    }
  } else if (["subfinder", "amass"].includes(adapter)) {
    for (const line of text.split(/\r?\n/).filter(Boolean)) {
      if (line.trim().startsWith("{")) {
        let r;
        try {
          r = JSON.parse(line);
        } catch {
          invalid++;
          continue;
        }
        emit(
          "domain",
          r.host ?? r.name,
          { upstream: r.source ?? adapter },
          0.7,
        );
      } else emit("domain", line, {}, 0.7);
    }
  } else if (adapter === "crtsh") {
    for (const r of records(text)) {
      if (!r || typeof r !== "object") {
        invalid++;
        continue;
      }
      for (const name of String(r.name_value ?? "").split("\n"))
        emit("domain", name, { record: String(r.id ?? "") }, 0.8);
    }
  } else if (adapter === "dnsx") {
    for (const r of records(text)) {
      if (!r || typeof r !== "object") {
        invalid++;
        continue;
      }
      emit("domain", r.host, {}, 0.85);
      if (
        (r.a !== undefined && !Array.isArray(r.a)) ||
        (r.aaaa !== undefined && !Array.isArray(r.aaaa))
      ) {
        invalid++;
        continue;
      }
      let host;
      try {
        host = normalized("domain", r.host);
      } catch {
        invalid++;
        continue;
      }
      for (const ip of [...(r.a ?? []), ...(r.aaaa ?? [])])
        emit("ip", ip, { host }, 0.85);
    }
  } else if (adapter === "httpx") {
    for (const r of records(text)) {
      if (!r || typeof r !== "object") {
        invalid++;
        continue;
      }
      const url = r.url ?? r.input;
      if (r.tech !== undefined && !Array.isArray(r.tech)) {
        invalid++;
        continue;
      }
      emit(
        "url",
        url,
        {
          status: r.status_code ?? 0,
          technology: (r.tech ?? []).map(String).slice(0, 20),
          title: String(r.title ?? "").slice(0, 200),
          certificate_cn: String(r.tls?.subject_cn ?? "").slice(0, 200),
          certificate_issuer: String(r.tls?.issuer_cn ?? "").slice(0, 200),
        },
        0.8,
      );
    }
  } else if (adapter === "naabu") {
    for (const r of records(text)) {
      if (!r || typeof r !== "object") {
        invalid++;
        continue;
      }
      const host = r.host || r.ip;
      const port = Number(r.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        invalid++;
        continue;
      }
      emit("service", `${host}:${port}`, { host, port }, 0.8);
    }
  } else if (adapter === "sherlock") {
    // Native Sherlock --csv, not the debugging --dump-response output.
    for (const r of csv(text)) {
      if (r.exists !== "Claimed") continue;
      const username = r.username;
      emit("username", username, {}, 0.45);
      emit(
        "profile",
        r.url_user,
        {
          username,
          inferred: true,
          reason: "Username match; identity unverified",
        },
        0.45,
      );
    }
  } else if (adapter === "whatsmyname") {
    for (const r of records(text)) {
      if (
        !r ||
        typeof r !== "object" ||
        typeof r.username !== "string" ||
        typeof r.url !== "string" ||
        !["found", "not_found", "unknown"].includes(r.status)
      ) {
        invalid++;
        continue;
      }
      if (r.status !== "found") continue;
      emit("username", r.username, { inferred: true }, 0.4);
      emit(
        "profile",
        r.url,
        {
          username: r.username,
          inferred: true,
          reason: "Imported username match; identity unverified",
        },
        0.4,
      );
    }
  } else if (adapter === "business-context") {
    for (const r of records(text)) {
      try {
        parseBusiness(r, scope, emit);
      } catch {
        invalid++;
      }
    }
  } else if (adapter === "breach-summary") {
    for (const record of records(text)) {
      const parsed = BreachSummary.safeParse(record);
      if (!parsed.success) {
        invalid++;
        continue;
      }
      const r = parsed.data;
      emit(
        "breach",
        `${r.email}:${r.breach}`,
        {
          account: r.email,
          name: r.breach,
          provider: r.provider,
          ...(r.date ? { date: r.date } : {}),
          verification: "breach_association_only",
        },
        0.65,
        r.provider,
        r.timestamp,
      );
    }
  } else if (adapter === "trufflehog") {
    for (const r of records(text)) {
      if (!r || typeof r !== "object") {
        invalid++;
        continue;
      }
      const git =
        r.SourceMetadata?.Data?.Git ?? r.SourceMetadata?.Data?.Filesystem ?? {};
      const document = basename(String(git.file ?? "").replaceAll("\\", "/"));
      const rule = String(r.DetectorName ?? "unknown").slice(0, 100);
      emit(
        "secret",
        `${document}:${Number(git.line) || 0}:${rule}`,
        {
          document,
          line: Number(git.line) || 0,
          rule,
          credential_kind: "possible_secret",
          verification: "unverified",
        },
        0.6,
      );
    }
  } else if (adapter === "mx") {
    const r = JSON.parse(text);
    emit(
      "mail_domain",
      r.domain,
      {
        host: r.domain,
        mx: (r.records ?? [])
          .slice(0, 20)
          .map((x) => `${x.priority} ${x.exchange}`),
        status: r.status,
        mailbox: "unknown",
        catch_all: "unknown",
      },
      0.85,
    );
  } else if (adapter === "rdap" || adapter === "routing") {
    const r = JSON.parse(text);
    const evidence = {
      ip: context.target,
      ...(context.relatedHost ? { host: context.relatedHost } : {}),
      inferred: false,
      reason:
        "Registry/routing data does not establish ownership or physical location",
    };
    if (adapter === "rdap") {
      if (!r.startAddress || !r.endAddress)
        throw new Error("INVALID_RDAP_RESPONSE");
      emit(
        "network",
        `${r.startAddress}-${r.endAddress}`,
        {
          ...evidence,
          start: r.startAddress,
          end: r.endAddress,
          handle: String(r.handle ?? ""),
          country: String(r.country ?? ""),
        },
        0.8,
      );
    } else {
      if (r.status !== "ok" || !r.data || !Array.isArray(r.data.asns))
        throw new Error("INVALID_ROUTING_RESPONSE");
      if (r.data.prefix)
        emit(
          "network",
          r.data.prefix,
          { ...evidence, prefix: r.data.prefix },
          0.8,
        );
      for (const asn of r.data.asns.slice(0, 10))
        if (/^\d{1,10}$/.test(String(asn)))
          emit("asn", `AS${asn}`, evidence, 0.8);
    }
  } else if (adapter === "github-profile") {
    const r = JSON.parse(text);
    const username = context.target;
    if (String(r.login).toLowerCase() !== username.toLowerCase())
      throw new Error("PROFILE_MISMATCH");
    emit("username", username, {}, 0.6);
    emit(
      "profile",
      `https://github.com/${encodeURIComponent(username)}`,
      {
        username,
        public_company: String(r.company ?? ""),
        verification: "account_exists_identity_unverified",
        inferred: true,
      },
      0.6,
    );
    if (r.email)
      emit(
        "email",
        r.email,
        { username, verification: "publicly_listed_mailbox_unknown" },
        0.65,
      );
  } else if (adapter === "theharvester") {
    for (const r of records(text)) {
      if (
        !r ||
        typeof r !== "object" ||
        (r.emails !== undefined && !Array.isArray(r.emails)) ||
        (r.hosts !== undefined && !Array.isArray(r.hosts))
      ) {
        invalid++;
        continue;
      }
      for (const email of r.emails ?? []) emit("email", email, {}, 0.6);
      for (const host of r.hosts ?? [])
        emit("domain", String(host).split(":")[0], {}, 0.6);
    }
  } else if (adapter === "exiftool") {
    for (const r of records(text)) {
      if (!r || typeof r !== "object") {
        invalid++;
        continue;
      }
      const document = basename(
        String(r.SourceFile ?? "").replaceAll("\\", "/"),
      );
      emit("document", document, { document }, 0.8);
      for (const field of [
        "Author",
        "Creator",
        "Producer",
        "Software",
        "Title",
      ])
        if (typeof r[field] === "string")
          emit(
            "metadata",
            `${document}:${field}:${r[field].slice(0, 200)}`,
            { document, field, inferred: false },
            0.6,
          );
    }
  } else if (adapter === "gitleaks") {
    for (const r of records(text)) {
      if (!r || typeof r !== "object") {
        invalid++;
        continue;
      }
      const document = basename(String(r.File ?? "").replaceAll("\\", "/"));
      // Intentionally discard Secret, Match, author and commit message.
      emit(
        "secret",
        `${document}:${Number(r.StartLine) || 0}:${String(r.RuleID).slice(0, 100)}`,
        {
          document,
          line: Number(r.StartLine) || 0,
          rule: String(r.RuleID).slice(0, 100),
          credential_kind: /password/i.test(String(r.RuleID))
            ? "possible_credential"
            : "possible_secret",
          verification: "unverified",
        },
        0.6,
      );
    }
  } else if (["recon-ng", "spiderfoot", "jsonl"].includes(adapter)) {
    // Bridge contract, NOT a promise to parse every native export version.
    for (const r of records(text)) {
      const result = Observation.safeParse(r);
      if (!result.success) {
        invalid++;
        continue;
      }
      emit(
        r.type,
        r.value,
        r.evidence,
        Math.min(r.confidence, 0.7),
        adapter === "jsonl" ? r.source : adapter,
        r.timestamp,
      );
    }
  } else throw new Error("UNKNOWN_PARSER");
  return {
    items,
    skipped,
    invalid,
    truncated,
    ...(discovery ? { discovery } : {}),
  };
}
