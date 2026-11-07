import { basename } from "node:path";
import { Observation } from "./schema.js";
import { normalized } from "./scope.js";

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
]);
function sanitize(evidence) {
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
export function parse(adapter, text, scope, maxRecords = 2000) {
  const items = [];
  let skipped = 0;
  let invalid = 0;
  let truncated = false;
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
      const valueNormalized = normalized(type, value);
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
  if (["subfinder", "amass"].includes(adapter)) {
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
  return { items, skipped, invalid, truncated };
}
