import { csv } from "./parsers.js";
import { domain, normalized } from "./scope.js";

const truthy = (value) => /^(true|1|yes)$/i.test(String(value ?? "").trim());
const falsey = (value) => {
  const text = String(value ?? "").trim();
  return text === "" || /^(false|0|no|none|null)$/i.test(text);
};

function httpsUrl(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.port)
    throw new Error("INVALID_URL");
  url.search = "";
  url.hash = "";
  return url;
}

export function readHoleheReport(text, scope, target, emit) {
  const rows = csv(text);
  const stats = { skipped: 0, invalid: 0, coverage_gaps: [] };
  for (const row of rows) {
    let account;
    try {
      account = normalized("email", String(row.email || target || "").trim());
    } catch {
      stats.invalid++;
      continue;
    }
    if (!scope.allows("email", account)) {
      stats.skipped++;
      continue;
    }
    const site = String(row.name || row.domain || "")
      .trim()
      .slice(0, 80);
    const host = String(row.domain || "")
      .trim()
      .replace(/^https?:\/\//, "")
      .split("/")[0];
    if (!site || !host) {
      stats.invalid++;
      continue;
    }
    const rateLimited = truthy(row.rateLimit) || truthy(row.rate_limit);
    if (rateLimited || !falsey(row.error)) {
      stats.coverage_gaps.push({
        source: "holehe",
        target: account,
        site,
        reason: rateLimited ? "rate_limited" : "error",
      });
      continue;
    }
    if (!truthy(row.exists)) continue;
    let url;
    try {
      url = `https://${domain(host)}/`;
    } catch {
      stats.invalid++;
      continue;
    }
    emit(
      "profile",
      url,
      {
        account,
        site_name: site,
        status: "registered",
        provider: "holehe",
        verification: "site_reports_registration",
        inferred: true,
      },
      0.45,
      "holehe",
    );
  }
  return stats;
}

function socialGroups(report) {
  if (Array.isArray(report)) return [{ items: report, kind: "flat" }];
  if (!report || typeof report !== "object")
    throw new Error("INVALID_SOCIAL_ANALYZER");
  return [
    { items: report.detected ?? report.found ?? [], kind: "found" },
    { items: report.unknown ?? [], kind: "unknown" },
    { items: report.failed ?? [], kind: "failed" },
  ];
}

function socialKind(group, item) {
  if (group !== "flat") return group;
  const status = String(item.status ?? "found").toLowerCase();
  if (["unknown", "rate_limited", "ratelimited"].includes(status))
    return status.startsWith("rate") ? "rate_limited" : "unknown";
  if (["failed", "error", "timeout"].includes(status)) return "failed";
  if (["not_found", "not found", "available", "none"].includes(status))
    return "absent";
  return "found";
}

export function readSocialAnalyzerReport(text, scope, emit) {
  const stats = { skipped: 0, invalid: 0, coverage_gaps: [] };
  const groups = socialGroups(JSON.parse(text));
  for (const group of groups) {
    if (!Array.isArray(group.items)) {
      stats.invalid++;
      continue;
    }
    for (const item of group.items) {
      if (!item || typeof item !== "object") {
        stats.invalid++;
        continue;
      }
      const username = String(item.username ?? item.user ?? "").trim();
      const link = String(item.link ?? item.url ?? "").trim();
      if (!username || !link) {
        stats.invalid++;
        continue;
      }
      if (!scope.username(username)) {
        stats.skipped++;
        continue;
      }
      const kind = socialKind(group.kind, item);
      let url;
      try {
        url = httpsUrl(link);
      } catch {
        stats.invalid++;
        continue;
      }
      const site = url.hostname;
      if (kind === "absent") continue;
      if (kind !== "found") {
        stats.coverage_gaps.push({
          source: "social-analyzer",
          target: username,
          site,
          reason:
            kind === "unknown"
              ? "unknown"
              : kind === "rate_limited"
                ? "rate_limited"
                : "failed",
        });
        continue;
      }
      const evidence = {
        username,
        site_name: site,
        status: "found",
        provider: "social-analyzer",
        verification: "candidate",
        inferred: true,
      };
      emit("username", username, evidence, 0.4, "social-analyzer");
      emit("profile", url.href, evidence, 0.4, "social-analyzer");
    }
  }
  return stats;
}
