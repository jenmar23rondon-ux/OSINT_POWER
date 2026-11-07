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
      "subfinder",
      "amass",
      "dnsx",
      "httpx",
      "naabu",
      "hibp",
    ]),
    target: z.string().min(1).max(253),
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
    ]),
    data: z.string().min(1).max(2_000_000),
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
          .array(z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/))
          .max(100)
          .default([]),
        documents: z.array(z.string().min(1).max(500)).max(100).default([]),
      })
      .strict(),
    network: z.boolean().default(false),
    active: z.boolean().default(false),
    enabledAdapters: z.array(RunInput.shape.adapter).default(["crtsh"]),
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
      })
      .strict()
      .prefault({}),
  })
  .strict();
