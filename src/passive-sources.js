import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { gapReason } from "./adapter-kinds.js";
import { fetchText } from "./transport.js";
import { domain } from "./scope.js";

export const PASSIVE_API_ADAPTERS = new Set([
  "domain-rdap",
  "doh",
  "otx",
  "hackertarget",
  "urlscan",
  "shodan-internetdb",
  "securitytrails",
  "virustotal",
  "github-keys",
  "github-events",
  "gravatar",
  "keybase",
  "emailrep",
]);

const DOH_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CAA"];
const BLOCKED_RDAP_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal)$/i;

export function githubHeaders() {
  const headers = { Accept: "application/vnd.github+json" };
  const token = process.env.GITHUB_TOKEN;
  if (typeof token === "string" && /^[A-Za-z0-9_]+$/.test(token))
    headers.Authorization = `Bearer ${token}`;
  return headers;
}

export function domainRdapBase(name, bootstrap) {
  const host = domain(name);
  let best = null;
  for (const [suffixes, urls] of bootstrap?.services ?? []) {
    for (const suffix of suffixes ?? []) {
      const normalized = String(suffix).toLowerCase().replace(/\.$/, "");
      if (host !== normalized && !host.endsWith(`.${normalized}`)) continue;
      if (!best || normalized.length > best.suffix.length)
        best = { suffix: normalized, urls };
    }
  }
  if (!best) throw new Error("RDAP_PROVIDER_NOT_FOUND");
  for (const value of best.urls ?? []) {
    try {
      const url = new URL(value);
      if (
        url.protocol === "https:" &&
        !url.username &&
        !url.password &&
        !url.port &&
        !isIP(url.hostname) &&
        url.hostname.includes(".") &&
        !BLOCKED_RDAP_HOST.test(url.hostname)
      )
        return url.href.endsWith("/") ? url.href : `${url.href}/`;
    } catch {
      /* Ignore bootstrap entries that are not HTTPS registry URLs. */
    }
  }
  throw new Error("RDAP_PROVIDER_NOT_FOUND");
}

function gap(source, target, site, error) {
  return {
    source,
    target,
    site,
    reason: gapReason(error?.code || error?.message),
  };
}

function gravatarHash(email) {
  return createHash("md5")
    .update(String(email).trim().toLowerCase())
    .digest("hex");
}

async function collectDomainRdap(target, limits, fetcher) {
  const bootstrap = JSON.parse(
    await fetchText(
      "https://data.iana.org/rdap/dns.json",
      limits,
      { accept: "application/json" },
      fetcher,
    ),
  );
  const base = domainRdapBase(target, bootstrap);
  return fetchText(
    new URL(`domain/${encodeURIComponent(target)}`, base).href,
    limits,
    { accept: "application/rdap+json" },
    fetcher,
  );
}

async function collectDoh(target, limits, fetcher) {
  const answers = [];
  const gaps = [];
  for (const type of DOH_TYPES) {
    const url = new URL("https://cloudflare-dns.com/dns-query");
    url.searchParams.set("name", target);
    url.searchParams.set("type", type);
    try {
      answers.push({
        type,
        response: JSON.parse(
          await fetchText(
            url.href,
            limits,
            { accept: "application/dns-json" },
            fetcher,
          ),
        ),
      });
    } catch (error) {
      gaps.push(gap("doh", target, type, error));
    }
  }
  return JSON.stringify({ answers, gaps });
}

async function collectOtx(target, limits, fetcher) {
  const headers = {};
  if (process.env.OTX_API_KEY)
    headers["X-OTX-API-KEY"] = process.env.OTX_API_KEY;
  return fetchText(
    `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(target)}/passive_dns`,
    limits,
    headers,
    fetcher,
  );
}

async function collectHackerTarget(target, limits, fetcher) {
  const text = await fetchText(
    `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(target)}`,
    limits,
    {},
    fetcher,
  );
  const trimmed = text.trim();
  if (!trimmed.includes(",") && /error|limit|exceeded|quota/i.test(trimmed))
    throw new Error(
      /limit|quota|exceeded/i.test(trimmed)
        ? "RATE_LIMITED"
        : "HACKERTARGET_ERROR",
    );
  return text;
}

async function collectUrlscan(target, limits, fetcher) {
  const headers = {};
  if (process.env.URLSCAN_API_KEY)
    headers["API-Key"] = process.env.URLSCAN_API_KEY;
  return fetchText(
    `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`domain:${target}`)}&size=20`,
    limits,
    headers,
    fetcher,
  );
}

async function collectShodan(target, limits, fetcher) {
  try {
    return await fetchText(
      `https://internetdb.shodan.io/${encodeURIComponent(target)}`,
      limits,
      {},
      fetcher,
    );
  } catch (error) {
    if (error.code === "HTTP_404")
      return JSON.stringify({
        ip: target,
        ports: [],
        hostnames: [],
        cpes: [],
        vulns: [],
        tags: [],
      });
    throw error;
  }
}

async function collectSecurityTrails(target, limits, fetcher) {
  if (!process.env.SECURITYTRAILS_API_KEY)
    throw new Error("SECURITYTRAILS_API_KEY_MISSING");
  return fetchText(
    `https://api.securitytrails.com/v1/domain/${encodeURIComponent(target)}/subdomains`,
    limits,
    { APIKEY: process.env.SECURITYTRAILS_API_KEY },
    fetcher,
  );
}

async function collectVirusTotal(target, limits, fetcher) {
  if (!process.env.VIRUSTOTAL_API_KEY)
    throw new Error("VIRUSTOTAL_API_KEY_MISSING");
  const kind = isIP(target) ? "ip_addresses" : "domains";
  return fetchText(
    `https://www.virustotal.com/api/v3/${kind}/${encodeURIComponent(target)}`,
    limits,
    { "x-apikey": process.env.VIRUSTOTAL_API_KEY },
    fetcher,
  );
}

async function collectGithub(path, limits, fetcher) {
  return fetchText(
    `https://api.github.com${path}`,
    limits,
    githubHeaders(),
    fetcher,
  );
}

async function collectGravatar(target, limits, fetcher) {
  try {
    return await fetchText(
      `https://en.gravatar.com/${gravatarHash(target)}.json`,
      limits,
      {},
      fetcher,
    );
  } catch (error) {
    if (error.code === "HTTP_404") return JSON.stringify({ entry: [] });
    throw error;
  }
}

async function collectKeybase(target, limits, fetcher) {
  return fetchText(
    `https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(target)}`,
    limits,
    {},
    fetcher,
  );
}

async function collectEmailRep(target, limits, fetcher) {
  const headers = {};
  if (process.env.EMAILREP_API_KEY) headers.Key = process.env.EMAILREP_API_KEY;
  return fetchText(
    `https://emailrep.io/${encodeURIComponent(target)}`,
    limits,
    headers,
    fetcher,
  );
}

const COLLECTORS = {
  "domain-rdap": collectDomainRdap,
  doh: collectDoh,
  otx: collectOtx,
  hackertarget: collectHackerTarget,
  urlscan: collectUrlscan,
  "shodan-internetdb": collectShodan,
  securitytrails: collectSecurityTrails,
  virustotal: collectVirusTotal,
  "github-keys": (target, limits, fetcher) =>
    collectGithub(`/users/${encodeURIComponent(target)}/keys`, limits, fetcher),
  "github-events": (target, limits, fetcher) =>
    collectGithub(
      `/users/${encodeURIComponent(target)}/events/public?per_page=10`,
      limits,
      fetcher,
    ),
  gravatar: collectGravatar,
  keybase: collectKeybase,
  emailrep: collectEmailRep,
};

export function collectPassiveApi(adapter, target, config, dependencies = {}) {
  const collect = COLLECTORS[adapter];
  if (!collect) throw new Error("UNKNOWN_COLLECTOR");
  return collect(
    target,
    config.limits,
    dependencies.fetcher ?? fetch,
    dependencies,
  );
}

function emptyStats() {
  return { skipped: 0, invalid: 0, coverage_gaps: [] };
}

function registrarName(rdap) {
  for (const entity of rdap.entities ?? []) {
    if (!Array.isArray(entity?.roles) || !entity.roles.includes("registrar"))
      continue;
    const card = entity.vcardArray?.[1];
    if (!Array.isArray(card)) continue;
    for (const item of card) {
      if (item?.[0] === "fn" && typeof item[3] === "string")
        return item[3].slice(0, 200);
    }
  }
  return "";
}

function parseDomainRdap(text, _scope, context, emit) {
  const stats = emptyStats();
  const rdap = JSON.parse(text);
  const registered = String(rdap.ldhName || context.target || "");
  const date = (rdap.events ?? []).find(
    (event) => event?.eventAction === "registration",
  )?.eventDate;
  emit(
    "domain",
    registered,
    {
      provider: "domain-rdap",
      handle: registrarName(rdap),
      ...(typeof date === "string" ? { date: date.slice(0, 40) } : {}),
      verification: "registration_data_not_ownership",
    },
    0.7,
    "domain-rdap",
  );
  for (const server of (rdap.nameservers ?? []).slice(0, 10)) {
    const name = server?.ldhName;
    if (typeof name === "string")
      emit(
        "domain",
        name,
        {
          provider: "domain-rdap",
          dns_type: "NS",
          verification: "registration_data_not_ownership",
        },
        0.6,
        "domain-rdap",
      );
  }
  return stats;
}

function parseDoh(text, _scope, context, emit) {
  const data = JSON.parse(text);
  const stats = emptyStats();
  stats.coverage_gaps = Array.isArray(data.gaps) ? data.gaps : [];
  const mx = [];
  for (const item of data.answers ?? []) {
    for (const answer of item.response?.Answer ?? []) {
      const value = String(answer.data ?? "")
        .replace(/\.$/, "")
        .replace(/^"|"$/g, "");
      if (!value) continue;
      if (item.type === "A" || item.type === "AAAA") {
        if (!isIP(value)) {
          stats.invalid++;
          continue;
        }
        emit(
          "ip",
          value,
          {
            host: context.target,
            dns_type: item.type,
            provider: "cloudflare-dns.com",
            verification: "doh_record_not_ownership",
          },
          0.8,
          "doh",
        );
      } else if (item.type === "MX") {
        const parts = value.split(/\s+/);
        const exchange = parts.at(-1);
        const priority = parts.length > 1 ? parts[0] : "0";
        if (exchange) mx.push(`${priority} ${exchange}`.slice(0, 200));
      } else if (item.type === "TXT" && /PRIVATE KEY/.test(value)) {
        stats.skipped++;
      } else {
        emit(
          "domain",
          context.target,
          {
            host: context.target,
            dns_type: item.type,
            record: value.slice(0, 200),
            provider: "cloudflare-dns.com",
            verification: "doh_record_not_ownership",
          },
          0.65,
          "doh",
        );
      }
    }
  }
  if (mx.length)
    emit(
      "mail_domain",
      context.target,
      {
        host: context.target,
        mx: mx.slice(0, 20),
        status: "mx_present",
        mailbox: "unknown",
        catch_all: "unknown",
        dns_type: "MX",
        provider: "cloudflare-dns.com",
      },
      0.7,
      "doh",
    );
  return stats;
}

function parseOtx(text, _scope, _context, emit) {
  const stats = emptyStats();
  const data = JSON.parse(text);
  for (const row of (data.passive_dns ?? []).slice(0, 100)) {
    const hostname = String(row.hostname ?? "");
    const address = String(row.address ?? "");
    if (hostname)
      emit(
        "domain",
        hostname,
        {
          provider: "otx",
          dns_type: String(row.record_type ?? "").slice(0, 20),
          verification: "passive_dns_not_ownership",
        },
        0.6,
        "otx",
      );
    if (hostname && isIP(address))
      emit(
        "ip",
        address,
        {
          host: hostname,
          provider: "otx",
          verification: "passive_dns_not_ownership",
        },
        0.55,
        "otx",
      );
  }
  return stats;
}

function parseHackerTarget(text, _scope, _context, emit) {
  const stats = emptyStats();
  for (const line of text.split(/\r?\n/).filter(Boolean)) {
    const [host, ip] = line.split(",");
    if (!host || !ip) {
      stats.invalid++;
      continue;
    }
    emit(
      "domain",
      host.trim(),
      { provider: "hackertarget", verification: "passive_dns_not_ownership" },
      0.55,
      "hackertarget",
    );
    if (isIP(ip.trim()))
      emit(
        "ip",
        ip.trim(),
        {
          host: host.trim(),
          provider: "hackertarget",
          verification: "passive_dns_not_ownership",
        },
        0.55,
        "hackertarget",
      );
  }
  return stats;
}

function parseUrlscan(text, _scope, _context, emit) {
  const stats = emptyStats();
  const data = JSON.parse(text);
  for (const row of (data.results ?? []).slice(0, 20)) {
    const page = row?.page ?? {};
    if (typeof page.domain === "string")
      emit(
        "domain",
        page.domain,
        {
          provider: "urlscan",
          verification: "third_party_scan_live_status_unknown",
        },
        0.5,
        "urlscan",
      );
    if (typeof page.url === "string")
      emit(
        "url",
        page.url,
        {
          title: String(page.title ?? "").slice(0, 200),
          provider: "urlscan",
          verification: "third_party_scan_live_status_unknown",
        },
        0.5,
        "urlscan",
      );
  }
  return stats;
}

function parseShodan(text, scope, context, emit) {
  const stats = emptyStats();
  const data = JSON.parse(text);
  const ip = String(data.ip || context.target || "");
  if (!isIP(ip)) {
    stats.invalid++;
    return stats;
  }
  const cves = (Array.isArray(data.vulns) ? data.vulns : [])
    .map(String)
    .filter((value) => /^CVE-\d{4}-\d{4,7}$/.test(value))
    .slice(0, 20);
  const technology = (Array.isArray(data.cpes) ? data.cpes : [])
    .map(String)
    .slice(0, 20);
  const evidence = {
    technology,
    cves,
    provider: "shodan-internetdb",
    verification: "internetdb_not_a_vulnerability_confirmation",
  };
  if (context.relatedHost) evidence.host = context.relatedHost;
  emit("ip", ip, evidence, 0.5, "shodan-internetdb");
  const serviceHost = context.relatedHost || (scope.host(ip) ? ip : "");
  for (const port of (Array.isArray(data.ports) ? data.ports : []).slice(
    0,
    20,
  )) {
    const number = Number(port);
    if (!Number.isInteger(number) || number < 1 || number > 65535) {
      stats.invalid++;
      continue;
    }
    if (!serviceHost) {
      stats.skipped++;
      continue;
    }
    emit(
      "service",
      `${serviceHost}:${number}`,
      {
        host: serviceHost,
        port: number,
        provider: "shodan-internetdb",
        verification: "internetdb_not_a_vulnerability_confirmation",
      },
      0.5,
      "shodan-internetdb",
    );
  }
  for (const hostname of (data.hostnames ?? []).slice(0, 20))
    if (typeof hostname === "string")
      emit(
        "domain",
        hostname,
        {
          provider: "shodan-internetdb",
          verification: "internetdb_hostname_not_ownership",
        },
        0.5,
        "shodan-internetdb",
      );
  return stats;
}

function parseSecurityTrails(text, _scope, context, emit) {
  const stats = emptyStats();
  const data = JSON.parse(text);
  if (!Array.isArray(data.subdomains)) {
    stats.invalid++;
    return stats;
  }
  for (const label of data.subdomains.slice(0, 100)) {
    if (typeof label !== "string" || !/^[a-z0-9-]{1,63}$/i.test(label)) {
      stats.invalid++;
      continue;
    }
    emit(
      "domain",
      `${label}.${context.target}`,
      {
        provider: "securitytrails",
        verification: "passive_dns_not_ownership",
      },
      0.6,
      "securitytrails",
    );
  }
  return stats;
}

function parseVirusTotal(text, _scope, context, emit) {
  const stats = emptyStats();
  const data = JSON.parse(text);
  const attributes = data.data?.attributes ?? {};
  if (isIP(context.target)) {
    if (typeof attributes.network === "string")
      emit(
        "network",
        attributes.network,
        {
          ip: context.target,
          ...(context.relatedHost ? { host: context.relatedHost } : {}),
          prefix: attributes.network.slice(0, 80),
          country: String(attributes.country ?? "").slice(0, 8),
          handle: String(attributes.as_owner ?? "").slice(0, 200),
          provider: "virustotal",
          verification: "vendor_report_not_ownership",
        },
        0.5,
        "virustotal",
      );
    return stats;
  }
  for (const record of (attributes.last_dns_records ?? []).slice(0, 40)) {
    const type = String(record.type ?? "");
    const value = String(record.value ?? "");
    if (!type || !value) continue;
    if ((type === "A" || type === "AAAA") && isIP(value))
      emit(
        "ip",
        value,
        {
          host: context.target,
          dns_type: type,
          provider: "virustotal",
          verification: "vendor_dns_not_ownership",
        },
        0.55,
        "virustotal",
      );
    else
      emit(
        "domain",
        context.target,
        {
          host: context.target,
          dns_type: type.slice(0, 20),
          record: value.slice(0, 200),
          provider: "virustotal",
          verification: "vendor_dns_not_ownership",
        },
        0.5,
        "virustotal",
      );
  }
  return stats;
}

function parseGithubKeys(text, _scope, context, emit) {
  const stats = emptyStats();
  const keys = JSON.parse(text);
  if (!Array.isArray(keys)) {
    stats.invalid++;
    return stats;
  }
  for (const key of keys.slice(0, 20)) {
    if (!key || typeof key.key !== "string" || !Number.isInteger(key.id)) {
      stats.invalid++;
      continue;
    }
    emit(
      "profile",
      `https://github.com/${encodeURIComponent(context.target)}`,
      {
        username: context.target,
        key_id: String(key.id),
        fingerprint: createHash("sha256").update(key.key).digest("hex"),
        provider: "github",
        verification: "public_key_identity_unverified",
        inferred: true,
      },
      0.5,
      "github-keys",
    );
  }
  return stats;
}

function parseGithubEvents(text, _scope, context, emit) {
  const stats = emptyStats();
  const events = JSON.parse(text);
  if (!Array.isArray(events)) {
    stats.invalid++;
    return stats;
  }
  for (const event of events.slice(0, 30)) {
    if (event?.type !== "PushEvent" || !Array.isArray(event.payload?.commits))
      continue;
    for (const commit of event.payload.commits.slice(0, 20)) {
      for (const role of ["author", "committer"]) {
        const email = commit?.[role]?.email;
        if (typeof email !== "string") continue;
        emit(
          "email",
          email,
          {
            username: context.target,
            provider: "github",
            verification: "public_event_email_mailbox_unknown",
          },
          0.55,
          "github-events",
        );
      }
    }
  }
  return stats;
}

function parseGravatar(text, _scope, context, emit) {
  const stats = emptyStats();
  const entry = JSON.parse(text).entry?.[0];
  if (!entry || typeof entry.profileUrl !== "string") return stats;
  const evidence = {
    account: context.target,
    provider: "gravatar",
    verification: "profile_claim_identity_unverified",
    inferred: true,
  };
  if (typeof entry.displayName === "string" && entry.displayName.trim())
    evidence.name = entry.displayName.trim().slice(0, 160);
  emit("profile", entry.profileUrl, evidence, 0.45, "gravatar");
  return stats;
}

function parseKeybase(text, _scope, context, emit) {
  const stats = emptyStats();
  const person = JSON.parse(text).them?.[0];
  const username = person?.basics?.username;
  if (!person) return stats;
  if (String(username).toLowerCase() !== String(context.target).toLowerCase()) {
    stats.invalid++;
    return stats;
  }
  emit(
    "profile",
    `https://keybase.io/${encodeURIComponent(username)}`,
    {
      username,
      site_name: "Keybase",
      provider: "keybase",
      verification: "account_exists_identity_unverified",
      inferred: true,
    },
    0.5,
    "keybase",
  );
  for (const proof of (person.proofs_summary?.all ?? []).slice(0, 20)) {
    if (typeof proof?.service_url !== "string") continue;
    emit(
      "profile",
      proof.service_url,
      {
        username,
        site_name: String(proof.proof_type ?? "proof").slice(0, 80),
        provider: "keybase",
        verification: "keybase_proof_identity_unverified",
        inferred: true,
      },
      0.45,
      "keybase",
    );
  }
  return stats;
}

function parseEmailRep(text, _scope, context, emit) {
  const stats = emptyStats();
  const data = JSON.parse(text);
  const profiles = Array.isArray(data.details?.profiles)
    ? data.details.profiles.map(String).slice(0, 20)
    : [];
  if (!profiles.length) return stats;
  emit(
    "email",
    context.target,
    {
      account: context.target,
      profiles,
      provider: "emailrep",
      status: "profiles_reported",
      verification: "vendor_profile_list_not_identity",
    },
    0.45,
    "emailrep",
  );
  return stats;
}

const PARSERS = {
  "domain-rdap": parseDomainRdap,
  doh: parseDoh,
  otx: parseOtx,
  hackertarget: parseHackerTarget,
  urlscan: parseUrlscan,
  "shodan-internetdb": parseShodan,
  securitytrails: parseSecurityTrails,
  virustotal: parseVirusTotal,
  "github-keys": parseGithubKeys,
  "github-events": parseGithubEvents,
  gravatar: parseGravatar,
  keybase: parseKeybase,
  emailrep: parseEmailRep,
};

export function parsePassiveApi(adapter, text, scope, context, emit) {
  const parse = PARSERS[adapter];
  if (!parse) throw new Error("UNKNOWN_PARSER");
  return parse(text, scope, context, emit);
}
