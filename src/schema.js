import { z } from "zod";

export const EntityType = z.enum([
  "domain",
  "ip",
  "url",
  "email",
  "username",
  "profile",
  "document",
  "metadata",
  "breach",
  "secret",
  "service",
  "unresolved",
  "company",
  "employee",
  "role",
  "technology",
  "place",
  "job",
  "mail_domain",
  "network",
  "asn",
]);
export const Observation = z
  .object({
    type: EntityType,
    value: z.string().min(1).max(2048),
    source: z.string().min(1).max(80),
    confidence: z.number().min(0).max(1),
    timestamp: z.iso.datetime(),
    evidence: z.record(z.string(), z.json()),
  })
  .strict();
export const RunInput = z
  .object({
    adapter: z.enum([
      "crtsh",
      "certspotter",
      "wayback",
      "subfinder",
      "amass",
      "dnsx",
      "httpx",
      "naabu",
      "hibp",
      "sherlock",
      "theharvester",
      "mx",
      "rdap",
      "routing",
      "github-profile",
    ]),
    target: z.string().min(1).max(253),
    restart: z.boolean().default(false),
  })
  .strict();
export const QueryInput = z
  .object({
    type: EntityType.optional(),
    limit: z.number().int().min(1).max(100).default(25),
    cursor: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
  })
  .strict();
export const ImportInput = z
  .object({
    adapter: z.enum([
      "certspotter",
      "wayback",
      "subfinder",
      "amass",
      "dnsx",
      "httpx",
      "naabu",
      "sherlock",
      "theharvester",
      "exiftool",
      "gitleaks",
      "recon-ng",
      "spiderfoot",
      "jsonl",
      "whatsmyname",
      "business-context",
      "breach-summary",
      "trufflehog",
    ]),
    data: z.string().min(1).max(2_000_000),
  })
  .strict();
const ProviderPolicyBase = z
  .object({
    maxRequests: z.number().int().min(1).max(100000),
    windowMs: z.number().int().min(1000).max(86400000),
    minIntervalMs: z.number().int().min(0).max(60000),
    failureThreshold: z.number().int().min(1).max(10),
    cooldownMs: z.number().int().min(100).max(86400000),
  })
  .strict();
export const Config = z
  .object({
    version: z.literal(1),
    scope: z
      .object({
        domains: z.array(z.string()).max(100).default([]),
        excludeDomains: z.array(z.string()).max(100).default([]),
        ips: z.array(z.string()).max(100).default([]),
        emails: z.array(z.string().email()).max(100).default([]),
        usernames: z
          .array(z.string().regex(/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/))
          .max(100)
          .default([]),
        documents: z.array(z.string().min(1).max(500)).max(100).default([]),
        people: z
          .array(
            z
              .object({
                name: z.string().min(1).max(160),
                companyDomain: z.string(),
                aliases: z
                  .array(z.string().regex(/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/))
                  .max(20)
                  .default([]),
              })
              .strict(),
          )
          .max(50)
          .default([]),
      })
      .strict(),
    network: z.boolean().default(false),
    active: z.boolean().default(false),
    enabledAdapters: z.array(RunInput.shape.adapter).default(["crtsh"]),
    collectors: z
      .object({
        sherlockSites: z
          .array(z.enum(["GitHub", "GitLab", "Keybase"]))
          .min(1)
          .max(3)
          .default(["GitHub"]),
        harvesterSources: z
          .array(z.enum(["crtsh", "certspotter"]))
          .min(1)
          .max(2)
          .default(["crtsh"]),
        usernameSuffixes: z
          .array(z.string().regex(/^\d{1,2}$/))
          .max(3)
          .default(["1", "01"]),
      })
      .strict()
      .prefault({}),
    limits: z
      .object({
        timeoutMs: z.number().int().min(100).max(120_000).default(20_000),
        maxBytes: z.number().int().min(100).max(10_000_000).default(2_000_000),
        maxRecords: z.number().int().min(1).max(10_000).default(2000),
        minIntervalMs: z.number().int().min(0).max(60_000).default(1500),
        attempts: z.number().int().min(1).max(3).default(3),
        cacheTtlSeconds: z.number().int().min(0).max(86_400).default(3600),
        ports: z
          .array(z.number().int().min(1).max(65535))
          .min(1)
          .max(20)
          .default([80, 443]),
        requestRate: z.number().int().min(1).max(20).default(2),
        providers: z
          .object({
            defaults: ProviderPolicyBase.prefault({
              maxRequests: 60,
              windowMs: 60000,
              minIntervalMs: 0,
              failureThreshold: 3,
              cooldownMs: 30000,
            }),
            overrides: z
              .record(
                z.string().regex(/^[a-z0-9.:-]{1,100}$/),
                ProviderPolicyBase.partial(),
              )
              .default({
                "api.github.com": { maxRequests: 60, windowMs: 3600000 },
                "haveibeenpwned.com": { maxRequests: 10, windowMs: 60000 },
              }),
            maxWaitMs: z.number().int().min(0).max(60000).default(5000),
          })
          .strict()
          .prefault({}),
      })
      .strict()
      .prefault({}),
  })
  .strict();

export const JobInput = z.object({ id: z.uuid() }).strict();
export const ResumeInput = JobInput.extend({
  maxCalls: z.number().int().min(1).max(30).optional(),
});
export const JobListInput = z
  .object({
    limit: z.number().int().min(1).max(100).default(20),
    offset: z.number().int().min(0).default(0),
  })
  .strict();

export const WORKFLOW_NAMES = [
  "people",
  "company",
  "places",
  "users",
  "emails",
  "exposures",
  "correlation",
];
export const WORKFLOW_ALIASES = {
  personas: "people",
  empresa: "company",
  lugares: "places",
  usuarios: "users",
  correos: "emails",
  filtraciones: "exposures",
  correlacion: "correlation",
};
export const WorkflowInput = z
  .object({
    workflow: z.enum([...WORKFLOW_NAMES, ...Object.keys(WORKFLOW_ALIASES)]),
    target: z.string().min(1).max(253),
    execute: z.boolean().default(false),
    maxTargets: z.number().int().min(1).max(10).default(3),
    maxCalls: z.number().int().min(1).max(30).default(10),
  })
  .strict();
