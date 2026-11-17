import { ADAPTERS } from "./adapters.js";
import { PASSIVE_ADAPTERS } from "./adapter-kinds.js";
import { HISTORICAL_ADAPTERS } from "./discovery.js";
import { z } from "zod";

// Names only. Values stay in the environment and are never copied into results.
const DETAILS = {
  crtsh: { applies_to: ["domain"], host: "crt.sh" },
  certspotter: {
    applies_to: ["domain"],
    host: "api.certspotter.com",
    optional: ["CERTSPOTTER_API_KEY"],
  },
  wayback: { applies_to: ["domain"], host: "web.archive.org" },
  subfinder: { applies_to: ["domain"] },
  amass: { applies_to: ["domain"] },
  theharvester: { applies_to: ["domain"] },
  "domain-rdap": { applies_to: ["domain"], host: "data.iana.org" },
  doh: { applies_to: ["domain"], host: "cloudflare-dns.com" },
  otx: {
    applies_to: ["domain"],
    host: "otx.alienvault.com",
    optional: ["OTX_API_KEY"],
  },
  hackertarget: { applies_to: ["domain"], host: "api.hackertarget.com" },
  urlscan: {
    applies_to: ["domain"],
    host: "urlscan.io",
    optional: ["URLSCAN_API_KEY"],
  },
  securitytrails: {
    applies_to: ["domain"],
    host: "api.securitytrails.com",
    required: ["SECURITYTRAILS_API_KEY"],
  },
  virustotal: {
    applies_to: ["domain", "ip"],
    host: "www.virustotal.com",
    required: ["VIRUSTOTAL_API_KEY"],
  },
  rdap: { applies_to: ["ip"], host: "data.iana.org" },
  routing: { applies_to: ["ip"], host: "stat.ripe.net" },
  "shodan-internetdb": { applies_to: ["ip"], host: "internetdb.shodan.io" },
  gravatar: { applies_to: ["email"], host: "en.gravatar.com" },
  emailrep: {
    applies_to: ["email"],
    host: "emailrep.io",
    optional: ["EMAILREP_API_KEY"],
  },
  hibp: {
    applies_to: ["email"],
    host: "haveibeenpwned.com",
    required: ["HIBP_API_KEY"],
  },
  sherlock: { applies_to: ["username"] },
  "github-profile": {
    applies_to: ["username"],
    host: "api.github.com",
    optional: ["GITHUB_TOKEN"],
  },
  "github-keys": {
    applies_to: ["username"],
    host: "api.github.com",
    optional: ["GITHUB_TOKEN"],
  },
  "github-events": {
    applies_to: ["username"],
    host: "api.github.com",
    optional: ["GITHUB_TOKEN"],
  },
  keybase: { applies_to: ["username"], host: "keybase.io" },
  mx: { applies_to: ["domain"] },
  dnsx: { applies_to: ["domain"] },
  httpx: { applies_to: ["domain"] },
  naabu: { applies_to: ["domain"] },
};

const keyStatus = z.enum([
  "missing",
  "present",
  "optional_missing",
  "optional_present",
  "not_required",
]);
const rateLimit = z
  .object({
    host: z.string(),
    max_requests: z.number().int().positive(),
    window_ms: z.number().int().positive(),
    min_interval_ms: z.number().int().nonnegative(),
  })
  .strict();
const sourceRow = z
  .object({
    name: z.string(),
    mode: z.enum(["passive", "active"]),
    kind: z.enum(["api", "binary", "dns"]),
    description: z.string().max(300),
    enabled: z.boolean(),
    applies_to: z.array(z.enum(["domain", "email", "username", "ip"])).max(4),
    active_only: z.boolean(),
    required_env: z.array(z.string()).max(4),
    optional_env: z.array(z.string()).max(4),
    missing_required_env: z.array(z.string()).max(4),
    missing_optional_env: z.array(z.string()).max(4),
    key_status: keyStatus,
    cached_when_completed: z.boolean(),
    historical: z.boolean(),
    rate_limit: rateLimit.nullable(),
  })
  .strict();

export const SourceListResult = z
  .object({
    status: z.literal("completed"),
    network: z.literal(false),
    mutation: z.literal(false),
    cache_ttl_seconds: z.number().int().nonnegative(),
    native_request_rate: z.number().int().positive(),
    retry: z
      .object({
        attempts: z.number().int().positive(),
        min_interval_ms: z.number().int().nonnegative(),
        backoff: z.string().min(1).max(300),
      })
      .strict(),
    adapters: z.array(sourceRow).max(40),
    missing_keys: z
      .array(
        z
          .object({
            adapter: z.string(),
            env: z.array(z.string()).min(1).max(4),
          })
          .strict(),
      )
      .max(20),
    limitations: z.array(z.string()).max(8),
  })
  .strict();

export const SOURCE_LIMITATIONS = [
  "Key presence is not proof the key is valid. Key values are not shown.",
  "Optional keys are listed apart from required keys. A missing optional key does not disable the adapter.",
  "Completed collections use the workspace TTL cache. Certificate and archive cursors are not served from that cache.",
  "HTTP 429 and 5xx retry with backoff and Retry-After. A wait over 60000 milliseconds ends the run.",
  "Active adapters still require active mode. This list does not enable them.",
];

const BACKOFF =
  "max(min_interval_ms, 500 * 2^(attempt-1), Retry-After). A wait over 60000ms ends the run.";

export function keyInfo(name) {
  const detail = DETAILS[name] ?? {};
  const required_env = [...(detail.required ?? [])];
  const optional_env = [...(detail.optional ?? [])];
  const missing_required_env = required_env.filter(
    (item) => !process.env[item],
  );
  const missing_optional_env = optional_env.filter(
    (item) => !process.env[item],
  );
  const key_status = missing_required_env.length
    ? "missing"
    : required_env.length
      ? "present"
      : optional_env.length
        ? missing_optional_env.length
          ? "optional_missing"
          : "optional_present"
        : "not_required";
  return {
    required_env,
    optional_env,
    missing_required_env,
    missing_optional_env,
    key_status,
  };
}

function appliesTo(name) {
  const listed = DETAILS[name]?.applies_to;
  if (listed) return [...listed];
  return ["domain", "email", "username", "ip"].filter((kind) =>
    (PASSIVE_ADAPTERS[kind] ?? []).includes(name),
  );
}

function rateFor(config, host) {
  if (!host) return null;
  const defaults = config.limits.providers.defaults;
  const override = config.limits.providers.overrides[host] ?? {};
  return {
    host,
    max_requests: override.maxRequests ?? defaults.maxRequests,
    window_ms: override.windowMs ?? defaults.windowMs,
    min_interval_ms: override.minIntervalMs ?? defaults.minIntervalMs,
  };
}

export function listSources(engine) {
  const enabled = new Set(engine.config.enabledAdapters);
  const adapters = Object.keys(ADAPTERS)
    .sort()
    .map((name) => {
      const spec = ADAPTERS[name];
      const keys = keyInfo(name);
      const host = DETAILS[name]?.host ?? null;
      return {
        name,
        mode: spec.mode,
        kind: spec.kind,
        description: String(spec.description).slice(0, 300),
        enabled: enabled.has(name),
        applies_to: appliesTo(name),
        active_only: spec.mode === "active",
        ...keys,
        cached_when_completed: !HISTORICAL_ADAPTERS.includes(name),
        historical: HISTORICAL_ADAPTERS.includes(name),
        rate_limit: rateFor(engine.config, host),
      };
    });
  return SourceListResult.parse({
    status: "completed",
    network: false,
    mutation: false,
    cache_ttl_seconds: engine.config.limits.cacheTtlSeconds,
    native_request_rate: engine.config.limits.requestRate,
    retry: {
      attempts: engine.config.limits.attempts,
      min_interval_ms: engine.config.limits.minIntervalMs,
      backoff: BACKOFF,
    },
    adapters,
    missing_keys: adapters
      .filter((item) => item.enabled && item.missing_required_env.length)
      .map((item) => ({ adapter: item.name, env: item.missing_required_env })),
    limitations: SOURCE_LIMITATIONS,
  });
}
