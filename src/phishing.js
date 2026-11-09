import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToUnicode } from "node:url";
import { z } from "zod";
import { collectDiscovery, decodeDiscovery } from "./discovery.js";
import { domain } from "./scope.js";
import { hash } from "./store.js";
import { recordSource } from "./state.js";
import { fetchText } from "./transport.js";

// Offline lookalikes of one in-scope apex, then passive enrichment of only
// those names. The assessment is always suspected. Analyst decisions stay in
// the review tables and never rewrite this status into confirmed phishing.
export const RECENT_REGISTRATION_DAYS = 400;
export const PHISHING_LIMITATIONS = [
  "Candidates are unverified leads. This workflow never labels a domain as confirmed phishing.",
  "Generation is a capped, deterministic edit of one in-scope apex: typos, homoglyphs, a final-label TLD swap, login/secure/support additions and hyphenation. Multi-part public suffixes are not understood.",
  "Apex labels must be 4–32 characters and cannot already contain a hyphen. Variants beyond the cap are a coverage gap, not a clean result.",
  "Passive enrichment queries configured crt.sh, Cert Spotter, IANA domain RDAP and Wayback for generated candidates only, one attempt each. It does not download site or archive content, submit forms, use credentials, or fetch a phishing kit.",
  "Domain RDAP hosts are taken from the IANA DNS bootstrap. Link relations inside a registry response are not followed.",
  "DNS A/MX/NS queries run only when network is enabled, active mode is on, and the mx adapter is enabled. An MX record does not prove a mailbox.",
  "Historical CT and Wayback calls are a single page and do not advance the in-scope discovery cursors.",
  "An analyst accept or reject is required before notification or takedown. Accept still does not prove phishing.",
];
export const RECOMMENDED_ACTIONS = [
  "Keep every candidate unverified until an analyst records a decision on its entity.",
  "If the analyst accepts the lead, notify the in-scope organization's defensive contacts and include the stored signals.",
  "A registrar, host, or certificate-authority notice is appropriate only after that decision, and only for the recorded candidate.",
  "Do not open the candidate in a session that submits credentials, and do not download or execute a suspected kit.",
];
const KEYWORDS = ["login", "secure", "support"];
const TLDS = [
  "com",
  "net",
  "org",
  "info",
  "biz",
  "co",
  "io",
  "app",
  "xyz",
  "online",
];
const TECHNIQUE_ORDER = [
  "homoglyph",
  "digit",
  "tld_swap",
  "keyword",
  "hyphenation",
  "omission",
  "transposition",
  "duplication",
  "adjacent",
];
const TECHNIQUE_PRIOR = {
  homoglyph: 0.9,
  digit: 0.78,
  tld_swap: 0.84,
  keyword: 0.66,
  hyphenation: 0.76,
  omission: 0.72,
  transposition: 0.74,
  duplication: 0.7,
  adjacent: 0.68,
};
const HOMOGLYPHS = {
  a: "\u0430",
  c: "\u0441",
  e: "\u0435",
  i: "\u0456",
  o: "\u043e",
  p: "\u0440",
  x: "\u0445",
  y: "\u0443",
};
const DIGITS = { o: "0", i: "1", l: "1", e: "3" };
const FOLD = new Map([
  ["\u0430", "a"],
  ["\u0441", "c"],
  ["\u0435", "e"],
  ["\u0456", "i"],
  ["\u043e", "o"],
  ["\u0440", "p"],
  ["\u0445", "x"],
  ["\u0443", "y"],
  ["0", "o"],
  ["3", "e"],
]);
const ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
const SIGNAL_NAMES = [
  "name_similarity",
  "recently_registered",
  "has_mx",
  "certificate_brand_terms",
  "shares_infrastructure",
];
const ENRICHMENT_SOURCES = ["crtsh", "certspotter", "wayback", "rdap", "dns"];
const ENRICHMENT_STATUS = [
  "completed",
  "not_run",
  "network_disabled",
  "active_disabled",
  "adapter_disabled",
  "budget_exhausted",
  "failed",
  "not_found",
];
const REVIEW_NOTE_STORED =
  "Stored candidates remain suspected. They stay in the review queue until an analyst records accept or reject. Accept does not confirm phishing.";
const REVIEW_NOTE_PLAN =
  "Plan mode does not store leads or contact sources. Execute to add suspected candidates to the review queue.";

const technique = z.enum(TECHNIQUE_ORDER);
const signalName = z.enum(SIGNAL_NAMES);
const enrichmentStatus = z.enum(ENRICHMENT_STATUS);
const json = z.record(z.string(), z.json());
const signalSchema = z
  .object({
    signal: signalName,
    present: z.boolean(),
    collected: z.boolean(),
    basis: z.string().min(1).max(500),
    source: z.string().min(1).max(80),
    evidence: json,
  })
  .strict();
const enrichmentSchema = z
  .object({
    source: z.enum(ENRICHMENT_SOURCES),
    status: enrichmentStatus,
    basis: z.string().min(1).max(500),
    requests: z.number().int().nonnegative(),
    evidence: json,
  })
  .strict();
const candidateSchema = z
  .object({
    id: z.string().regex(/^[a-f0-9]{64}$/),
    entity_id: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .nullable(),
    domain: z.string().min(1).max(253),
    technique,
    similarity: z.number().min(0).max(0.95),
    status: z.literal("suspected"),
    confidence: z.number().min(0).max(0.85),
    basis: z.string().min(1).max(500),
    analyst_decision: z
      .enum(["accept", "reject", "needs-more-evidence"])
      .nullable(),
    signals: z.array(signalSchema).length(5),
    enrichment: z.array(enrichmentSchema).length(5),
  })
  .strict();
const actionSchema = z
  .object({
    rank: z.number().int().nonnegative(),
    action: z.string(),
    reason: z.string(),
  })
  .strict();
export const PhishingInput = z
  .object({
    target: z.string().min(1).max(253),
    execute: z.boolean().default(false),
    maxCandidates: z.number().int().min(1).max(40).default(20),
    maxCalls: z.number().int().min(1).max(30).default(10),
  })
  .strict();
export const PhishingReportInput = z
  .object({
    target: z.string().min(1).max(253),
  })
  .strict();
export const PhishingWorkflowResult = z
  .object({
    workflow: z.literal("phishing"),
    mode: z.enum(["plan", "execute"]),
    status: z.enum(["planned", "completed", "partial"]),
    target: z.string(),
    protected_domain: z.string(),
    persisted: z.boolean(),
    network: z.boolean(),
    active: z.boolean(),
    run_id: z.uuid().nullable(),
    candidates: z.array(candidateSchema),
    returned: z.number().int().nonnegative(),
    variant_count: z.number().int().nonnegative(),
    truncated: z.boolean(),
    calls: z.number().int().nonnegative(),
    http_requests: z.number().int().nonnegative(),
    coverage_complete: z.literal(false),
    budget: z
      .object({
        maxCandidates: z.number().int().nonnegative(),
        maxCalls: z.number().int().nonnegative(),
      })
      .strict(),
    review: z
      .object({
        queued: z.number().int().nonnegative(),
        note: z.string(),
      })
      .strict(),
    limitations: z.array(z.string()),
    next_actions: z.array(actionSchema),
  })
  .strict();
export const PhishingReportResult = z
  .object({
    project: z.literal("OSINT_POWER"),
    title: z.literal("Phishing intelligence report"),
    classification: z.literal("unverified_leads"),
    generated_at: z.iso.datetime(),
    protected_domain: z.string(),
    candidates: z.array(candidateSchema),
    returned: z.number().int().nonnegative(),
    truncated: z.boolean(),
    recommended_actions: z.array(z.string()),
    limitations: z.array(z.string()),
    markdown: z.string(),
  })
  .strict();

function round2(value) {
  return Math.round((value + Number.EPSILON) * 100) / 100;
}
function clip(value, max = 500) {
  const text = String(value ?? "").trim();
  return text.length > max
    ? text.slice(0, max - 1) + "…"
    : text || "No basis recorded.";
}
function priority(name) {
  const index = TECHNIQUE_ORDER.indexOf(name);
  return index < 0 ? TECHNIQUE_ORDER.length : index;
}
function fold(value) {
  return [...String(value).toLowerCase()]
    .map((character) => FOLD.get(character) ?? character)
    .join("");
}
function levenshtein(leftText, rightText) {
  const left = [...leftText];
  const right = [...rightText];
  const row = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i++) {
    let previous = i - 1;
    row[0] = i;
    for (let j = 1; j <= right.length; j++) {
      const current = row[j];
      const cost = left[i - 1] === right[j - 1] ? 0 : 1;
      row[j] = Math.min(previous + cost, row[j] + 1, row[j - 1] + 1);
      previous = current;
    }
  }
  return row[right.length];
}
function neighbors(character) {
  for (const row of ROWS) {
    const index = row.indexOf(character);
    if (index < 0) continue;
    return [row[index - 1], row[index + 1]].filter(Boolean);
  }
  return [];
}
function replaceAt(label, index, value) {
  return label.slice(0, index) + value + label.slice(index + 1);
}
function tryHost(value) {
  try {
    return domain(value);
  } catch {
    return null;
  }
}
export function authorizeApex(scope, input) {
  let name;
  try {
    name = domain(input);
  } catch {
    throw new Error("INVALID_DOMAIN");
  }
  if (!scope.host(name)) throw new Error("OUT_OF_SCOPE");
  const labels = name.split(".");
  if (labels.length !== 2) throw new Error("APEX_DOMAIN_REQUIRED");
  const brand = labels[0];
  if (brand.length < 4 || brand.length > 32 || brand.includes("-"))
    throw new Error("BRAND_LABEL_UNSUPPORTED");
  return name;
}
export function blockedCandidate(scope, name) {
  let value;
  try {
    value = domain(name);
  } catch {
    return true;
  }
  if (scope.host(value)) return true;
  return scope.excluded.some(
    (parent) => value === parent || value.endsWith(`.${parent}`),
  );
}
export function mentionsBrand(hostname, brand) {
  let unicode;
  try {
    unicode = domainToUnicode(domain(String(hostname).replace(/^\*\./, "")));
  } catch {
    return false;
  }
  const foldedBrand = fold(brand);
  if (foldedBrand.length < 4) return false;
  for (const label of unicode.split(".")) {
    const folded = fold(label).replaceAll("-", "");
    if (folded === foldedBrand) return true;
    for (const keyword of KEYWORDS) {
      if (folded === keyword + foldedBrand || folded === foldedBrand + keyword)
        return true;
    }
  }
  return false;
}
function visualSimilarity(brand, label, kind) {
  const left = fold(brand);
  let right = fold(domainToUnicode(label));
  if (kind === "hyphenation" || kind === "keyword")
    right = right.replaceAll("-", "");
  if (kind === "keyword") {
    for (const keyword of KEYWORDS) {
      if (right.startsWith(keyword)) right = right.slice(keyword.length);
      else if (right.endsWith(keyword)) right = right.slice(0, -keyword.length);
    }
  }
  if (!left || !right) return 0.5;
  const distance = Math.min(
    levenshtein(left, right),
    levenshtein(left, right.replaceAll("1", "l")),
    levenshtein(left, right.replaceAll("1", "i")),
  );
  if (distance === 0) return 0.95;
  return Math.max(0.5, 1 - distance / Math.max(left.length, right.length, 1));
}
export function scoreCandidate(protectedDomain, candidateDomain, kind) {
  const visual = visualSimilarity(
    protectedDomain.split(".")[0],
    candidateDomain.split(".")[0],
    kind,
  );
  const similarity = round2(
    Math.min(0.95, visual * 0.5 + TECHNIQUE_PRIOR[kind] * 0.5),
  );
  return {
    similarity,
    basis: clip(
      `${kind} variant of ${protectedDomain}; visual similarity ${round2(visual)}; technique weight ${TECHNIQUE_PRIOR[kind]}`,
    ),
  };
}
export function generateLookalikes(apex, options = {}) {
  const protectedDomain = domain(apex);
  const labels = protectedDomain.split(".");
  if (labels.length !== 2) throw new Error("APEX_DOMAIN_REQUIRED");
  const brand = labels[0];
  const tld = labels[1];
  if (brand.length < 4 || brand.length > 32 || brand.includes("-"))
    throw new Error("BRAND_LABEL_UNSUPPORTED");
  const maxCandidates = options.maxCandidates ?? 20;
  const reject = options.reject ?? (() => false);
  const found = new Map();
  const add = (kind, host) => {
    const name = tryHost(host);
    if (!name || name === protectedDomain || reject(name)) return;
    const existing = found.get(name);
    if (!existing || priority(kind) < priority(existing.technique))
      found.set(name, { domain: name, technique: kind });
  };
  for (let index = 0; index < brand.length; index++) {
    const character = brand[index];
    const homoglyph = HOMOGLYPHS[character];
    if (homoglyph)
      add("homoglyph", replaceAt(brand, index, homoglyph) + "." + tld);
    const digit = DIGITS[character];
    if (digit) add("digit", `${replaceAt(brand, index, digit)}.${tld}`);
    add("omission", `${brand.slice(0, index)}${brand.slice(index + 1)}.${tld}`);
    add(
      "duplication",
      `${replaceAt(brand, index, character + character)}.${tld}`,
    );
    if (index + 1 < brand.length && brand[index] !== brand[index + 1])
      add(
        "transposition",
        `${brand.slice(0, index)}${brand[index + 1]}${character}${brand.slice(index + 2)}.${tld}`,
      );
    for (const neighbor of neighbors(character)) {
      if (neighbor !== character)
        add("adjacent", `${replaceAt(brand, index, neighbor)}.${tld}`);
    }
    if (index > 0)
      add(
        "hyphenation",
        `${brand.slice(0, index)}-${brand.slice(index)}.${tld}`,
      );
  }
  for (const suffix of TLDS) {
    if (suffix !== tld) add("tld_swap", `${brand}.${suffix}`);
  }
  for (const keyword of KEYWORDS) {
    add("keyword", `${keyword}-${brand}.${tld}`);
    add("keyword", `${brand}-${keyword}.${tld}`);
    add("keyword", `${keyword}${brand}.${tld}`);
    add("keyword", `${brand}${keyword}.${tld}`);
  }
  const ordered = [...found.values()].sort(
    (left, right) =>
      priority(left.technique) - priority(right.technique) ||
      left.domain.localeCompare(right.domain),
  );
  const selected = ordered.slice(0, maxCandidates).map((candidate) => ({
    ...candidate,
    ...scoreCandidate(protectedDomain, candidate.domain, candidate.technique),
  }));
  return {
    protected_domain: protectedDomain,
    candidates: selected,
    variant_count: ordered.length,
    truncated: ordered.length > selected.length,
  };
}

function signal(name, source, present, collected, basis, evidence = {}) {
  return {
    signal: name,
    present: Boolean(present),
    collected: Boolean(collected),
    basis: clip(basis),
    source,
    evidence,
  };
}
function enrichment(source, status, basis, requests = 0, evidence = {}) {
  return {
    source,
    status,
    basis: clip(basis),
    requests,
    evidence,
  };
}
function blankSignals(kindBasis) {
  return [
    signal("name_similarity", "lookalike", true, true, kindBasis, {}),
    signal(
      "recently_registered",
      "rdap",
      false,
      false,
      "Registration age was not queried.",
    ),
    signal("has_mx", "mx", false, false, "MX was not queried."),
    signal(
      "certificate_brand_terms",
      "crtsh",
      false,
      false,
      "Certificate names were not queried.",
    ),
    signal(
      "shares_infrastructure",
      "dns",
      false,
      false,
      "Addresses were not compared.",
    ),
  ];
}
function blankEnrichment(basis) {
  return ENRICHMENT_SOURCES.map((source) =>
    enrichment(source, "not_run", basis),
  );
}
function leadConfidence(similarity, signals) {
  let score = similarity * 0.55;
  if (
    signals.some(
      (item) => item.signal === "recently_registered" && item.present,
    )
  )
    score += 0.08;
  if (signals.some((item) => item.signal === "has_mx" && item.present))
    score += 0.08;
  if (
    signals.some(
      (item) => item.signal === "certificate_brand_terms" && item.present,
    )
  )
    score += 0.1;
  if (
    signals.some(
      (item) => item.signal === "shares_infrastructure" && item.present,
    )
  )
    score += 0.07;
  return round2(Math.min(0.85, score));
}
function leadBasis(candidate) {
  const fired = candidate.signals
    .filter((item) => item.present)
    .map((item) => item.signal);
  return clip(
    `Suspected lookalike (${candidate.technique}, similarity ${candidate.similarity}). Signals: ${fired.join(", ") || "none"}. Not confirmed phishing.`,
  );
}
function nextActions(mode) {
  return [
    {
      rank: 1,
      action:
        "Review suspected lookalikes in the review queue before any notification",
      reason:
        "The workflow records unverified leads and does not confirm phishing",
    },
    {
      rank: 2,
      action:
        mode === "execute"
          ? "Compare certificate, RDAP and DNS evidence on one candidate"
          : "Re-run phishing-scan with --execute to collect passive evidence",
      reason: "Name similarity alone is not infrastructure evidence",
    },
    {
      rank: 3,
      action:
        "Record accept, reject, or needs-more-evidence on the candidate entity",
      reason:
        "Escalation to takedown or brand notification requires an analyst decision",
    },
  ];
}
function candidateId(protectedDomain, name) {
  return hash(["phishing-candidate", protectedDomain, name]);
}
function entityId(name) {
  return hash(["domain", name]);
}
function latestDecision(store, id) {
  return (
    store.db
      .prepare(
        `SELECT decision FROM review_decisions
         WHERE subject_kind='entity' AND subject_id=?
         ORDER BY recorded_at DESC, rowid DESC LIMIT 1`,
      )
      .get(id)?.decision ?? null
  );
}
function queuedCount(store, ids) {
  let queued = 0;
  for (const id of ids) {
    const decision = latestDecision(store, id);
    if (!decision || decision === "needs-more-evidence") queued++;
  }
  return queued;
}
function materialize(protectedDomain, candidate, store, persisted) {
  const id = candidateId(protectedDomain, candidate.domain);
  const entity = persisted ? entityId(candidate.domain) : null;
  return {
    id,
    entity_id: entity,
    domain: candidate.domain,
    technique: candidate.technique,
    similarity: candidate.similarity,
    status: "suspected",
    confidence: leadConfidence(candidate.similarity, candidate.signals),
    basis: leadBasis(candidate),
    analyst_decision: entity ? latestDecision(store, entity) : null,
    signals: SIGNAL_NAMES.map((name) =>
      candidate.signals.find((item) => item.signal === name),
    ),
    enrichment: ENRICHMENT_SOURCES.map((source) =>
      candidate.enrichment.find((item) => item.source === source),
    ),
  };
}
function codeOf(error) {
  return /^[A-Z0-9_]+$/.test(error?.message ?? "")
    ? error.message
    : "SOURCE_FAILED";
}
function nowIso(engine) {
  const clock = engine.dependencies.now?.() ?? Date.now();
  return new Date(clock).toISOString();
}
function gate(engine, adapter, budget, activeAdapter = false, allowed) {
  if (!engine.config.network)
    return enrichment(
      adapter,
      "network_disabled",
      "Network is disabled. No query was sent.",
    );
  if (activeAdapter) {
    if (!engine.config.enabledAdapters.includes("mx"))
      return enrichment(
        adapter,
        "adapter_disabled",
        "DNS enrichment requires the mx adapter. No query was sent.",
      );
    if (!engine.config.active)
      return enrichment(
        adapter,
        "active_disabled",
        "DNS A/MX/NS requires active mode. No query was sent.",
      );
  } else if (!engine.config.enabledAdapters.includes(adapter))
    return enrichment(
      adapter,
      "adapter_disabled",
      `${adapter} is not enabled. No query was sent.`,
    );
  if (budget.calls >= budget.maxCalls)
    return enrichment(
      adapter,
      "budget_exhausted",
      "The logical call budget was reached before this source.",
    );
  // Optional caller allow-list. Existing checks above stay in front of it.
  if (allowed && !allowed.has(activeAdapter ? "mx" : adapter))
    return enrichment(
      adapter,
      "adapter_disabled",
      "This monitor does not include this source. No query was sent.",
    );
  return null;
}
async function readSource(url, engine, fetcher, headers = {}) {
  try {
    const text = await fetchText(url, engine.config.limits, headers, fetcher);
    return { ok: true, text, requests: 1 };
  } catch (error) {
    if (codeOf(error) === "HTTP_404")
      return { ok: true, text: "", notFound: true, requests: 1 };
    if (codeOf(error) === "CANCELLED") throw error;
    return { ok: false, code: codeOf(error), requests: 1 };
  }
}
function certificateNames(value) {
  const names = [];
  const push = (name) => {
    const cleaned = String(name ?? "")
      .trim()
      .replace(/^\*\./, "");
    if (cleaned) names.push(cleaned);
  };
  if (!Array.isArray(value)) return names;
  for (const row of value.slice(0, 50)) {
    if (!row || typeof row !== "object") continue;
    for (const part of String(row.name_value ?? row.common_name ?? "").split(
      /\n+/,
    ))
      push(part);
    for (const name of row.dns_names ?? []) push(name);
  }
  return names.slice(0, 40);
}
function matchingNames(names, brand) {
  return [...new Set(names.filter((name) => mentionsBrand(name, brand)))].slice(
    0,
    8,
  );
}
function validateBootstrapUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password) return null;
  if (url.port || url.search || url.hash || isIP(url.hostname)) return null;
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(url.hostname)) return null;
  if (url.hostname === "localhost" || url.hostname.endsWith(".local"))
    return null;
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return url;
}
export function rdapDomainUrl(bootstrap, apex) {
  const tld = apex.split(".").at(-1);
  for (const entry of bootstrap?.services ?? []) {
    if (!Array.isArray(entry) || entry.length < 2) continue;
    const tlds = Array.isArray(entry[0]) ? entry[0] : [];
    if (!tlds.map((item) => String(item).toLowerCase()).includes(tld)) continue;
    for (const value of entry[1] ?? []) {
      const base = validateBootstrapUrl(value);
      if (!base) continue;
      return new URL(`domain/${encodeURIComponent(apex)}`, base).href;
    }
  }
  return null;
}
function registration(events, nowMs) {
  const dates = [];
  for (const event of events ?? []) {
    const action = String(event?.eventAction ?? "").toLowerCase();
    if (!["registration", "registered"].includes(action)) continue;
    const parsed = Date.parse(event.eventDate ?? "");
    if (Number.isFinite(parsed)) dates.push(parsed);
  }
  if (!dates.length)
    return signal(
      "recently_registered",
      "rdap",
      false,
      true,
      "RDAP response included no registration date.",
    );
  const earliest = Math.min(...dates);
  const age = Math.floor((nowMs - earliest) / 86400000);
  const present = age >= 0 && age <= RECENT_REGISTRATION_DAYS;
  const registered = new Date(earliest).toISOString();
  return signal(
    "recently_registered",
    "rdap",
    present,
    true,
    present
      ? `RDAP registration ${registered} is ${age} days old, within ${RECENT_REGISTRATION_DAYS} days. Registration age is not attribution.`
      : `RDAP registration ${registered} is ${age} days old, outside the ${RECENT_REGISTRATION_DAYS}-day window.`,
    { registered, age_days: age, threshold_days: RECENT_REGISTRATION_DAYS },
  );
}
async function lookupDns(target, config, dependencies, signalAbort) {
  const resolver =
    dependencies.resolver ??
    new Resolver({ timeout: config.limits.timeoutMs, tries: 1 });
  const timer = setTimeout(() => resolver.cancel?.(), config.limits.timeoutMs);
  const abort = () => resolver.cancel?.();
  signalAbort?.addEventListener("abort", abort, { once: true });
  const read = async (method) => {
    if (typeof resolver[method] !== "function") return [];
    try {
      return await resolver[method](target);
    } catch (error) {
      if (signalAbort?.aborted)
        throw signalAbort.reason ?? new Error("CANCELLED");
      if (
        ["ENODATA", "ENOTFOUND", "ESERVFAIL", "EREFUSED", "ENOTIMP"].includes(
          error.code,
        )
      )
        return [];
      throw new Error("DNS_LOOKUP_FAILED");
    }
  };
  try {
    const [addresses, mail, nameservers] = await Promise.all([
      read("resolve4"),
      read("resolveMx"),
      read("resolveNs"),
    ]);
    return {
      a: addresses.filter((item) => isIP(item) === 4).slice(0, 10),
      mx: mail
        .slice(0, 10)
        .map((record) => ({
          priority: Number(record.priority) || 0,
          exchange: String(record.exchange ?? "")
            .replace(/\.$/, "")
            .toLowerCase(),
        }))
        .filter((record) => record.exchange && record.exchange !== "."),
      ns: nameservers
        .map((value) => String(value).replace(/\.$/, "").toLowerCase())
        .filter(Boolean)
        .slice(0, 10),
    };
  } finally {
    clearTimeout(timer);
    signalAbort?.removeEventListener("abort", abort);
  }
}
function replaceSignal(candidate, next) {
  candidate.signals = candidate.signals.map((item) =>
    item.signal === next.signal ? next : item,
  );
}
function replaceEnrichment(candidate, next) {
  candidate.enrichment = candidate.enrichment.map((item) =>
    item.source === next.source ? next : item,
  );
}
async function enrichCandidate(
  engine,
  candidate,
  brand,
  budget,
  fetcher,
  signalAbort,
  allowed,
) {
  signalAbort?.throwIfAborted();
  const passive = [
    ["crtsh", async () => collectCrt(engine, candidate, brand, fetcher)],
    [
      "certspotter",
      async () =>
        collectHistorical(
          engine,
          "certspotter",
          candidate,
          fetcher,
          signalAbort,
        ),
    ],
    [
      "wayback",
      async () =>
        collectHistorical(engine, "wayback", candidate, fetcher, signalAbort),
    ],
    ["rdap", async () => collectRdap(engine, candidate, fetcher)],
  ];
  for (const [source, run] of passive) {
    const blocked = gate(engine, source, budget, false, allowed);
    if (blocked) {
      replaceEnrichment(candidate, blocked);
      continue;
    }
    budget.calls++;
    const result = await run();
    replaceEnrichment(candidate, result.enrichment);
    if (result.signal) replaceSignal(candidate, result.signal);
    if (result.matched) candidate[result.matchedKey] = result.matched;
  }
  const dnsBlocked = gate(engine, "dns", budget, true, allowed);
  if (dnsBlocked) {
    replaceEnrichment(candidate, dnsBlocked);
    return;
  }
  budget.calls++;
  const dns = await collectDns(engine, candidate, signalAbort);
  replaceEnrichment(candidate, dns.enrichment);
  if (dns.signal) replaceSignal(candidate, dns.signal);
  candidate._addresses = dns.addresses;
}
async function collectCrt(engine, candidate, brand, fetcher) {
  const url = new URL("https://crt.sh/");
  url.searchParams.set("q", candidate.domain);
  url.searchParams.set("output", "json");
  const response = await readSource(url.href, engine, fetcher);
  if (!response.ok)
    return {
      enrichment: enrichment(
        "crtsh",
        "failed",
        `crt.sh query failed (${response.code}).`,
        response.requests,
      ),
    };
  if (response.notFound)
    return {
      enrichment: enrichment(
        "crtsh",
        "not_found",
        "crt.sh returned no certificate record.",
        response.requests,
      ),
      matched: [],
      matchedKey: "_crtMatches",
    };
  try {
    const names = certificateNames(JSON.parse(response.text || "[]"));
    return {
      enrichment: enrichment(
        "crtsh",
        "completed",
        names.length
          ? `crt.sh returned ${names.length} name(s). Certificate presence is not ownership or phishing.`
          : "crt.sh returned no certificate names.",
        response.requests,
        { names: names.slice(0, 8) },
      ),
      matched: matchingNames(names, brand),
      matchedKey: "_crtMatches",
    };
  } catch {
    return {
      enrichment: enrichment(
        "crtsh",
        "failed",
        "crt.sh returned a response that could not be parsed.",
        response.requests,
      ),
    };
  }
}
async function collectHistorical(
  engine,
  adapter,
  candidate,
  fetcher,
  signalAbort,
) {
  try {
    const text = await collectDiscovery(
      adapter,
      candidate.domain,
      engine.config,
      {
        fetcher,
        signal: signalAbort,
      },
    );
    const page = decodeDiscovery(adapter, text);
    if (adapter === "certspotter") {
      const names = certificateNames(page.records);
      return {
        enrichment: enrichment(
          adapter,
          "completed",
          `Cert Spotter returned one page with ${page.records.length} issuance(s). This is not a complete certificate history.`,
          1,
          { names: names.slice(0, 8) },
        ),
        matched: matchingNames(names, candidate._brand),
        matchedKey: "_spotterMatches",
      };
    }
    const urls = page.records
      .map((row) => (Array.isArray(row) ? String(row[1] ?? "") : ""))
      .filter((value) => value.startsWith("http"))
      .slice(0, 5);
    return {
      enrichment: enrichment(
        adapter,
        page.records.length ? "completed" : "not_found",
        urls.length
          ? "Wayback returned historical URLs. Archived pages were not downloaded and live status is unknown."
          : "Wayback returned no historical URL on this page.",
        1,
        { urls },
      ),
    };
  } catch (error) {
    if (codeOf(error) === "CANCELLED") throw error;
    if (codeOf(error) === "HTTP_404")
      return {
        enrichment: enrichment(
          adapter,
          "not_found",
          `${adapter} returned no records.`,
          1,
        ),
        matched: [],
        matchedKey: adapter === "certspotter" ? "_spotterMatches" : "_unused",
      };
    return {
      enrichment: enrichment(
        adapter,
        "failed",
        `${adapter} query failed (${codeOf(error)}).`,
        1,
      ),
    };
  }
}
async function collectRdap(engine, candidate, fetcher) {
  const bootstrap = await readSource(
    "https://data.iana.org/rdap/dns.json",
    engine,
    fetcher,
  );
  if (!bootstrap.ok)
    return {
      enrichment: enrichment(
        "rdap",
        "failed",
        `IANA RDAP bootstrap failed (${bootstrap.code}).`,
        bootstrap.requests,
      ),
    };
  let document;
  try {
    document = JSON.parse(bootstrap.text || "{}");
  } catch {
    return {
      enrichment: enrichment(
        "rdap",
        "failed",
        "IANA RDAP bootstrap could not be parsed.",
        bootstrap.requests,
      ),
    };
  }
  const url = rdapDomainUrl(document, candidate.domain);
  if (!url)
    return {
      enrichment: enrichment(
        "rdap",
        "failed",
        "IANA bootstrap has no HTTPS RDAP server for this final label.",
        bootstrap.requests,
      ),
    };
  const response = await readSource(url, engine, fetcher);
  const requests = bootstrap.requests + response.requests;
  if (response.notFound)
    return {
      enrichment: enrichment(
        "rdap",
        "not_found",
        "RDAP published no registration record for this candidate.",
        requests,
      ),
      signal: signal(
        "recently_registered",
        "rdap",
        false,
        true,
        "RDAP published no registration record for this candidate.",
      ),
    };
  if (!response.ok)
    return {
      enrichment: enrichment(
        "rdap",
        "failed",
        `RDAP query failed (${response.code}).`,
        requests,
      ),
    };
  try {
    const body = JSON.parse(response.text || "{}");
    const next = registration(
      body.events,
      engine.dependencies.now?.() ?? Date.now(),
    );
    return {
      enrichment: enrichment(
        "rdap",
        "completed",
        "RDAP registration events were read. Registry links were not followed, and registration is not attribution.",
        requests,
        next.evidence,
      ),
      signal: next,
    };
  } catch {
    return {
      enrichment: enrichment(
        "rdap",
        "failed",
        "RDAP response could not be parsed.",
        requests,
      ),
    };
  }
}
async function collectDns(engine, candidate, signalAbort) {
  try {
    await engine.providers.before("dns:system", signalAbort);
    const records = await lookupDns(
      candidate.domain,
      engine.config,
      engine.dependencies,
      signalAbort,
    );
    engine.providers.success("dns:system");
    const present = records.mx.length > 0;
    const exchanges = records.mx.map(
      (record) => `${record.priority} ${record.exchange}`,
    );
    return {
      addresses: records.a,
      enrichment: enrichment(
        "dns",
        "completed",
        present
          ? `DNS MX is present. A and NS records were recorded. Mailbox existence was not tested.`
          : "DNS returned no MX. A and NS were still recorded. Mailbox existence was not tested.",
        0,
        { a: records.a, mx: exchanges, ns: records.ns },
      ),
      signal: signal(
        "has_mx",
        "mx",
        present,
        true,
        present
          ? `DNS MX is present (${exchanges.join(", ")}). Mailbox existence and catch-all were not tested.`
          : "DNS returned no MX. Mailbox existence was not tested.",
        { mx: exchanges, ns: records.ns, a: records.a },
      ),
    };
  } catch (error) {
    if (codeOf(error) === "CANCELLED") throw error;
    if (!signalAbort?.aborted)
      engine.providers.failure("dns:system", codeOf(error));
    return {
      addresses: [],
      enrichment: enrichment(
        "dns",
        "failed",
        `DNS lookup failed (${codeOf(error)}).`,
      ),
    };
  }
}
function applySharedInfrastructure(candidates) {
  const owners = new Map();
  for (const candidate of candidates) {
    for (const ip of candidate._addresses ?? []) {
      const names = owners.get(ip) ?? [];
      names.push(candidate.domain);
      owners.set(ip, names);
    }
  }
  for (const candidate of candidates) {
    const dns = candidate.enrichment.find((item) => item.source === "dns");
    const attempted = dns?.status === "completed";
    if (!attempted) {
      replaceSignal(
        candidate,
        signal(
          "shares_infrastructure",
          "dns",
          false,
          false,
          dns?.basis ?? "Addresses were not compared.",
        ),
      );
      continue;
    }
    const matches = [];
    for (const ip of candidate._addresses ?? []) {
      const also = (owners.get(ip) ?? []).filter(
        (name) => name !== candidate.domain,
      );
      if (also.length) matches.push({ ip, also: also.slice(0, 10) });
    }
    replaceSignal(
      candidate,
      signal(
        "shares_infrastructure",
        "dns",
        matches.length > 0,
        true,
        matches.length
          ? `Address ${matches[0].ip} is also used by ${matches[0].also.join(", ")}. Shared hosting is not attribution.`
          : "No address from this run is shared with another enriched candidate.",
        matches.length
          ? { matches }
          : { addresses: candidate._addresses ?? [] },
      ),
    );
  }
}
function applyCertificates(candidates, brand) {
  for (const candidate of candidates) {
    const fromCrt = candidate._crtMatches ?? [];
    const fromSpotter = candidate._spotterMatches ?? [];
    const names = [...new Set([...fromCrt, ...fromSpotter])].slice(0, 8);
    const queried = candidate.enrichment.some(
      (item) =>
        ["crtsh", "certspotter"].includes(item.source) &&
        ["completed", "not_found"].includes(item.status),
    );
    if (!queried) continue;
    replaceSignal(
      candidate,
      signal(
        "certificate_brand_terms",
        fromCrt.length ? "crtsh" : "certspotter",
        names.length > 0,
        true,
        names.length
          ? `Certificate name(s) include the protected brand label ${brand}: ${names.join(", ")}. Issuance is not proof of phishing.`
          : "Queried certificate names do not include the protected brand label.",
        { names },
      ),
    );
  }
}
function observationsFor(protectedDomain, candidate, timestamp) {
  const rows = [
    {
      type: "domain",
      value: candidate.domain,
      source: "lookalike",
      confidence: candidate.confidence,
      timestamp,
      evidence: {
        reason: candidate.basis,
        verification: "suspected_impersonation_unconfirmed",
        inferred: true,
        name: candidate.technique,
        relation: "impersonates",
        relatedType: "domain",
        relatedValue: protectedDomain,
      },
    },
  ];
  for (const item of candidate.enrichment) {
    if (!["completed", "not_found", "failed"].includes(item.status)) continue;
    rows.push({
      type: "domain",
      value: candidate.domain,
      source: item.source === "dns" ? "mx" : item.source,
      confidence: Math.min(candidate.confidence, 0.35),
      timestamp,
      evidence: {
        reason: item.basis,
        verification: "passive_enrichment_unconfirmed",
        inferred: true,
        name: item.source,
        record: item.status,
      },
    });
  }
  return rows;
}
function persistCandidates(store, protectedDomain, candidates, timestamp) {
  const insertCandidate = store.db.prepare(
    `INSERT INTO phishing_candidates VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT(id) DO UPDATE SET
       technique=excluded.technique,
       similarity=excluded.similarity,
       confidence=excluded.confidence,
       basis=excluded.basis,
       enrichment=excluded.enrichment,
       updated_at=excluded.updated_at`,
  );
  const insertSignal = store.db.prepare(
    `INSERT INTO phishing_signals VALUES(?,?,?,?,?,?,?,?,?)
     ON CONFLICT(candidate_id, signal) DO UPDATE SET
       present=excluded.present,
       collected=excluded.collected,
       basis=excluded.basis,
       source=excluded.source,
       evidence=excluded.evidence,
       updated_at=excluded.updated_at`,
  );
  store.db.exec("BEGIN IMMEDIATE");
  try {
    for (const candidate of candidates) {
      insertCandidate.run(
        candidate.id,
        protectedDomain,
        candidate.domain,
        candidate.entity_id,
        candidate.technique,
        candidate.similarity,
        candidate.status,
        candidate.confidence,
        candidate.basis,
        JSON.stringify(candidate.enrichment),
        timestamp,
        timestamp,
      );
      for (const item of candidate.signals)
        insertSignal.run(
          hash([candidate.id, item.signal]),
          candidate.id,
          item.signal,
          Number(item.present),
          Number(item.collected),
          item.basis,
          item.source,
          JSON.stringify(item.evidence),
          timestamp,
        );
    }
    store.db.exec("COMMIT");
  } catch (error) {
    store.db.exec("ROLLBACK");
    throw error;
  }
}
function finishRun(store, runId, result) {
  const summary = {
    status: result.status,
    candidates: result.returned,
    calls: result.calls,
    http_requests: result.http_requests,
    truncated: result.truncated,
    coverage_complete: false,
  };
  store.finish(runId, result.status, summary);
  recordSource(store, runId, "phishing", result.protected_domain, {
    ...summary,
    collected_at: new Date().toISOString(),
    cached: false,
  });
}
export function initializePhishing(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS phishing_candidates(
      id TEXT PRIMARY KEY,
      protected_domain TEXT NOT NULL,
      candidate_domain TEXT NOT NULL,
      entity_id TEXT NOT NULL,
      technique TEXT NOT NULL,
      similarity REAL NOT NULL CHECK(similarity >= 0 AND similarity <= 0.95),
      status TEXT NOT NULL CHECK(status = 'suspected'),
      confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 0.85),
      basis TEXT NOT NULL,
      enrichment TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS phishing_candidates_pair
      ON phishing_candidates(protected_domain, candidate_domain);
    CREATE TABLE IF NOT EXISTS phishing_signals(
      id TEXT PRIMARY KEY,
      candidate_id TEXT NOT NULL,
      signal TEXT NOT NULL,
      present INTEGER NOT NULL CHECK(present IN (0, 1)),
      collected INTEGER NOT NULL CHECK(collected IN (0, 1)),
      basis TEXT NOT NULL,
      source TEXT NOT NULL,
      evidence TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(candidate_id, signal));
    CREATE INDEX IF NOT EXISTS phishing_signals_candidate
      ON phishing_signals(candidate_id);`);
}
function buildResult(engine, input, generated, candidates, extra) {
  const result = {
    workflow: "phishing",
    mode: extra.mode,
    status: extra.status,
    target: generated.protected_domain,
    protected_domain: generated.protected_domain,
    persisted: extra.persisted,
    network: engine.config.network,
    active: engine.config.active,
    run_id: extra.runId,
    candidates,
    returned: candidates.length,
    variant_count: generated.variant_count,
    truncated: generated.truncated,
    calls: extra.calls,
    http_requests: extra.httpRequests,
    coverage_complete: false,
    budget: {
      maxCandidates: input.maxCandidates,
      maxCalls: input.maxCalls,
    },
    review: {
      queued: extra.queued,
      note: extra.persisted ? REVIEW_NOTE_STORED : REVIEW_NOTE_PLAN,
    },
    limitations: PHISHING_LIMITATIONS,
    next_actions: nextActions(extra.mode),
  };
  const parsed = PhishingWorkflowResult.safeParse(result);
  if (!parsed.success) throw new Error("INTERNAL_OUTPUT_VALIDATION");
  return parsed.data;
}
export async function runPhishingWorkflow(
  engine,
  input,
  signalAbort,
  options = {},
) {
  const request = PhishingInput.parse(input ?? {});
  const allowed = options.sources ? new Set(options.sources) : undefined;
  signalAbort?.throwIfAborted();
  const protectedDomain = authorizeApex(engine.scope, request.target);
  const generated = generateLookalikes(protectedDomain, {
    maxCandidates: request.maxCandidates,
    reject: (name) => blockedCandidate(engine.scope, name),
  });
  const drafted = generated.candidates
    .map((candidate) => ({
      ...candidate,
      signals: blankSignals(candidate.basis),
      enrichment: blankEnrichment(
        request.execute
          ? "This source was not queried."
          : "Plan mode does not query this source.",
      ),
      _brand: protectedDomain.split(".")[0],
      _crtMatches: [],
      _spotterMatches: [],
      _addresses: [],
    }))
    .sort(
      (left, right) =>
        right.similarity - left.similarity ||
        left.domain.localeCompare(right.domain),
    );
  if (!request.execute) {
    return buildResult(
      engine,
      request,
      generated,
      drafted.map((candidate) =>
        materialize(protectedDomain, candidate, engine.store, false),
      ),
      {
        mode: "plan",
        status: "planned",
        persisted: false,
        runId: null,
        calls: 0,
        httpRequests: 0,
        queued: 0,
      },
    );
  }
  const budget = { calls: 0, maxCalls: request.maxCalls };
  let httpRequests = 0;
  const fetcher = (url, options) =>
    engine.providers.fetch(
      url,
      options,
      (nextUrl, nextOptions) => {
        httpRequests++;
        return (engine.dependencies.fetcher ?? fetch)(nextUrl, nextOptions);
      },
      signalAbort,
    );
  const runId = engine.store.start("phishing", protectedDomain);
  try {
    for (const candidate of drafted)
      await enrichCandidate(
        engine,
        candidate,
        protectedDomain.split(".")[0],
        budget,
        fetcher,
        signalAbort,
        allowed,
      );
    applyCertificates(drafted, protectedDomain.split(".")[0]);
    applySharedInfrastructure(drafted);
    const timestamp = nowIso(engine);
    const stored = drafted.map((candidate) =>
      materialize(protectedDomain, candidate, engine.store, true),
    );
    const observations = stored.flatMap((candidate) =>
      observationsFor(protectedDomain, candidate, timestamp),
    );
    if (observations.length)
      engine.store.ingest(observations, {
        runId,
        collector: "phishing",
        target: protectedDomain,
        collected_at: timestamp,
        configuration_digest: hash(engine.config),
        collector_version: "builtin-0.4.0",
        input_hash: hash(stored.map((candidate) => candidate.domain)),
      });
    persistCandidates(engine.store, protectedDomain, stored, timestamp);
    const failed = stored.some((candidate) =>
      candidate.enrichment.some((item) => item.status === "failed"),
    );
    const exhausted = stored.some((candidate) =>
      candidate.enrichment.some((item) => item.status === "budget_exhausted"),
    );
    const result = buildResult(engine, request, generated, stored, {
      mode: "execute",
      status: failed || exhausted ? "partial" : "completed",
      persisted: true,
      runId,
      calls: budget.calls,
      httpRequests,
      queued: queuedCount(
        engine.store,
        stored.map((candidate) => candidate.entity_id),
      ),
    });
    finishRun(engine.store, runId, result);
    return result;
  } catch (error) {
    const code = codeOf(error);
    engine.store.finish(runId, "failed", { code });
    throw new Error(code === "SOURCE_FAILED" ? "PHISHING_FAILED" : code);
  }
}
function loadCandidates(store, protectedDomain) {
  const rows = store.db
    .prepare(
      `SELECT * FROM phishing_candidates WHERE protected_domain=?
       ORDER BY confidence DESC, candidate_domain ASC LIMIT 101`,
    )
    .all(protectedDomain);
  const truncated = rows.length > 100;
  return {
    truncated,
    candidates: rows.slice(0, 100).map((row) => {
      const signals = store.db
        .prepare(
          "SELECT * FROM phishing_signals WHERE candidate_id=? ORDER BY signal",
        )
        .all(row.id)
        .map((item) => ({
          signal: item.signal,
          present: Boolean(item.present),
          collected: Boolean(item.collected),
          basis: item.basis,
          source: item.source,
          evidence: JSON.parse(item.evidence),
        }));
      return {
        id: row.id,
        entity_id: row.entity_id,
        domain: row.candidate_domain,
        technique: row.technique,
        similarity: row.similarity,
        status: row.status,
        confidence: row.confidence,
        basis: row.basis,
        analyst_decision: latestDecision(store, row.entity_id),
        signals: SIGNAL_NAMES.map((name) =>
          signals.find((item) => item.signal === name),
        ),
        enrichment: JSON.parse(row.enrichment),
      };
    }),
  };
}
function markdownReport(report) {
  const lines = [
    "# Phishing intelligence report",
    "",
    "**Unverified leads.** Nothing in this report is confirmed phishing. An analyst decision is required before notification or takedown.",
    "",
    `- Protected domain: \`${report.protected_domain}\``,
    `- Generated: ${report.generated_at}`,
    `- Candidates: ${report.returned}${report.truncated ? " (list truncated)" : ""}`,
    "",
  ];
  if (!report.candidates.length)
    lines.push("No suspected leads are stored for this domain.", "");
  for (const candidate of report.candidates) {
    lines.push(
      `## ${candidate.domain}`,
      "",
      `- Assessment: **suspected**`,
      `- Confidence: ${candidate.confidence}`,
      `- Similarity: ${candidate.similarity} (${candidate.technique})`,
      `- Analyst decision: ${candidate.analyst_decision ?? "none"}`,
      `- Entity: \`${candidate.entity_id}\``,
      "",
      candidate.basis,
      "",
      "### Signals",
      "",
    );
    for (const item of candidate.signals)
      lines.push(
        `- ${item.signal} (${item.source}): ${item.present ? "present" : "not present"}${item.collected ? "" : ", not collected"} — ${item.basis}`,
      );
    lines.push("", "### Enrichment", "");
    for (const item of candidate.enrichment)
      lines.push(`- ${item.source}: ${item.status} — ${item.basis}`);
    lines.push("");
  }
  lines.push("## Recommended actions", "");
  for (const action of report.recommended_actions) lines.push(`- ${action}`);
  lines.push("", "## Limitations", "");
  for (const limitation of report.limitations) lines.push(`- ${limitation}`);
  lines.push("");
  return lines.join("\n");
}
export function phishingReport(engine, input) {
  const request = PhishingReportInput.parse(input ?? {});
  const protectedDomain = authorizeApex(engine.scope, request.target);
  const loaded = loadCandidates(engine.store, protectedDomain);
  const report = {
    project: "OSINT_POWER",
    title: "Phishing intelligence report",
    classification: "unverified_leads",
    generated_at: nowIso(engine),
    protected_domain: protectedDomain,
    candidates: loaded.candidates,
    returned: loaded.candidates.length,
    truncated: loaded.truncated,
    recommended_actions: RECOMMENDED_ACTIONS,
    limitations: PHISHING_LIMITATIONS,
    markdown: "",
  };
  report.markdown = markdownReport(report);
  const parsed = PhishingReportResult.safeParse(report);
  if (!parsed.success) throw new Error("INTERNAL_OUTPUT_VALIDATION");
  return parsed.data;
}
export function phishingHTML(report) {
  const data = JSON.stringify(report).replace(
    /[<>&\u2028\u2029]/g,
    (character) =>
      "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"),
  );
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>OSINT POWER · Unverified phishing leads</title>
<style>
:root{color-scheme:dark;--bg:#07111d;--card:#101f30;--line:#223b50;--text:#e6f1fa;--muted:#9cb5c8;--accent:#32d2f4}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:32px 20px}h1{margin:4px 0 8px}p,li{color:var(--muted)}.banner{border:1px solid #8a5a20;background:#2a2112;color:#f2d7a2;border-radius:12px;padding:12px 14px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin:16px 0}code{color:var(--accent)}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);text-align:left;padding:8px;vertical-align:top}
</style></head><body><main>
<p>UNVERIFIED LEADS</p><h1>Phishing intelligence report</h1>
<p id="summary"></p><div class="banner" id="banner"></div><div id="candidates"></div>
<h2>Recommended actions</h2><ul id="actions"></ul>
<h2>Limitations</h2><ul id="limits"></ul>
</main>
<script type="application/json" id="report-data">${data}</script>
<script>
'use strict';
const report=JSON.parse(document.getElementById('report-data').textContent);
const text=(id,value)=>{document.getElementById(id).textContent=value;};
text('summary',report.protected_domain+' · '+report.generated_at+' · '+report.returned+' candidate(s)');
text('banner','These leads are suspected only. Nothing here is confirmed phishing. Do not notify or request takedown until an analyst records a decision.');
const root=document.getElementById('candidates');
for(const candidate of report.candidates){
  const card=document.createElement('section');
  card.className='card';
  const title=document.createElement('h2');
  title.textContent=candidate.domain+' · suspected';
  const meta=document.createElement('p');
  meta.textContent='Confidence '+candidate.confidence+' · similarity '+candidate.similarity+' · '+candidate.technique+' · analyst '+(candidate.analyst_decision||'none');
  const basis=document.createElement('p');
  basis.textContent=candidate.basis;
  const table=document.createElement('table');
  for(const signal of candidate.signals){
    const row=document.createElement('tr');
    for(const value of [signal.signal, signal.present?'present':'not present', signal.source, signal.basis]){
      const cell=document.createElement('td');
      cell.textContent=value;
      row.append(cell);
    }
    table.append(row);
  }
  card.append(title, meta, basis, table);
  root.append(card);
}
for(const action of report.recommended_actions){
  const item=document.createElement('li');
  item.textContent=action;
  document.getElementById('actions').append(item);
}
for(const limitation of report.limitations){
  const item=document.createElement('li');
  item.textContent=limitation;
  document.getElementById('limits').append(item);
}
</script></body></html>`;
}
