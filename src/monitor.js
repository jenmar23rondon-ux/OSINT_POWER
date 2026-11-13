import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { domainToUnicode } from "node:url";
import { z } from "zod";
import { ADAPTERS } from "./adapters.js";
import {
  authorizeApex,
  mentionsBrand,
  runPhishingWorkflow,
} from "./phishing.js";
import { WORKFLOW_NAMES } from "./schema.js";
import { domain } from "./scope.js";
import { SCHEMA_VERSION } from "./review.js";
import { mirrorRun } from "./state.js";
import { hash } from "./store.js";
import { allowedWebhook, postWebhook } from "./webhook.js";

export const ASSET_TYPES = [
  "subdomain",
  "host",
  "certificate",
  "dns",
  "lookalike",
  "exposure",
];
const RULE_IDS = [
  "new_certificate_brand_term",
  "new_lookalike_with_mx",
  "new_exposed_service",
  "new_exposure_record",
  "new_asset",
  "attribute_changed",
  "removed_asset",
  "coverage_gap",
];
const RANK = { suppressed: 0, info: 1, notable: 2, alert: 3 };
const PHISHING_SOURCES = new Set([
  "crtsh",
  "certspotter",
  "wayback",
  "rdap",
  "mx",
]);
const PRODUCERS = {
  subdomain: [
    "crtsh",
    "certspotter",
    "subfinder",
    "amass",
    "theharvester",
    "wayback",
    "dnsx",
  ],
  host: ["dnsx"],
  certificate: ["crtsh", "certspotter", "httpx"],
  dns: ["dnsx", "mx"],
  lookalike: ["phishing"],
  exposure: ["naabu", "httpx", "hibp"],
};
const CERTIFICATE_SOURCES = new Set(["crtsh", "certspotter"]);
const RECORD_STATUSES = new Set([
  "completed",
  "not_found",
  "failed",
  "budget_exhausted",
  "not_run",
  "network_disabled",
  "active_disabled",
  "adapter_disabled",
]);
const MAX_ASSETS = 2000;
const MAX_RETURNED_ALERTS = 50;
const REVIEW_NOTE =
  "New entities from this run stay unreviewed. No analyst decision is recorded and nothing is auto-confirmed.";

export const MONITOR_LIMITATIONS = [
  "There is no built-in scheduler. interval_hint is stored for the operator's cron or CI and is not enforced.",
  "Each run re-checks scope and skips sources the current configuration does not allow. Disabled, inactive, or network-off sources are not queried.",
  "Removed means absent from this run's comparable observations. It is not proof the asset was deleted. Skipped, failed, or truncated sources produce coverage gaps instead.",
  "Asset types that were not collected are carried forward and are not treated as changes.",
  "Significance rules are heuristics. A brand term on a certificate is not ownership or confirmed phishing. An MX record is not a mailbox. An exposed service is not a confirmed vulnerability.",
  "New entities remain unreviewed. This tool does not record an analyst decision or confirm a lead.",
  "Alerts are local records. A webhook is contacted only when one is configured and network access is already enabled. Delivery is best-effort.",
  "Snapshots are bounded and are not a complete census of the monitored organization.",
];

const text = z.string();
const count = z.number().int().nonnegative();
const id64 = z.string().regex(/^[a-f0-9]{64}$/);
const json = z.record(z.string(), z.json());
const assetType = z.enum(ASSET_TYPES);
const ruleId = z.enum(RULE_IDS);
const adapterName = z.enum(Object.keys(ADAPTERS));
const row = (shape) => z.object(shape).strict();

const thresholdSchema = row({
  minimum: z.enum(["info", "notable", "alert"]),
  asset_types: z.array(assetType).min(1).max(ASSET_TYPES.length),
  rules: row({
    new_certificate_brand_term: z.boolean(),
    new_lookalike_with_mx: z.boolean(),
    new_exposed_service: z.boolean(),
    new_exposure_record: z.boolean(),
    new_asset: z.boolean(),
    attribute_changed: z.boolean(),
    removed_asset: z.boolean(),
    coverage_gap: z.boolean(),
  }),
  brand_terms: z.array(text).max(20),
  include_apex_label: z.boolean(),
});
const sourceRow = row({
  source: text,
  status: text,
  invoked: z.boolean(),
  run_id: z.uuid().nullable(),
  code: text.nullable(),
  truncated: z.boolean(),
});
const changeRow = row({
  id: id64,
  change: z.enum(["added", "removed", "changed", "coverage_gap"]),
  asset_type: assetType,
  asset_key: text,
  value: text,
  significance: z.enum(["alert", "notable", "info", "suppressed"]),
  rule: ruleId,
  basis: text,
  before_attributes: json.nullable(),
  after_attributes: json.nullable(),
  observation_ids: z.array(id64),
  entity_ids: z.array(id64),
  alert: z.boolean(),
});
const monitorHead = row({
  id: z.uuid(),
  name: text,
  investigation: text,
  target: text,
  sources: z.array(text),
  interval_hint: text,
  thresholds: thresholdSchema,
  webhook_enabled: z.boolean(),
  scheduler: z.literal("external"),
  created_at: text,
});
export const MonitorCreated = monitorHead;
export const MonitorRunResult = row({
  monitor_id: z.uuid(),
  run_id: z.uuid(),
  mode: z.literal("execute"),
  status: z.enum(["completed", "partial", "deferred", "failed"]),
  target: text,
  previous_run_id: z.uuid().nullable(),
  sources: z.array(sourceRow),
  counts: row({
    assets: count,
    added: count,
    removed: count,
    changed: count,
    coverage_gaps: count,
    alerts: count,
  }),
  alerts: z.array(changeRow),
  returned: count,
  truncated: z.boolean(),
  coverage_complete: z.literal(false),
  review: row({
    queued_entities: count,
    auto_confirmed: z.literal(false),
    note: text,
  }),
  webhook: row({
    enabled: z.boolean(),
    attempted: z.boolean(),
    status: z.enum([
      "disabled",
      "not_sent",
      "hook_skipped",
      "hook_sent",
      "hook_failed",
    ]),
  }),
  limitations: z.array(text),
  scheduler: z.literal("external"),
});
export const MonitorChangesResult = row({
  monitor_id: z.uuid(),
  run_id: z.uuid(),
  status: text,
  items: z.array(changeRow),
  returned: count,
  limit: count,
  next_cursor: id64.nullable(),
  total: count,
  alert_count: count,
  coverage_complete: z.literal(false),
  limitations: z.array(text),
  scheduler: z.literal("external"),
});
export const MonitorListResult = row({
  items: z.array(
    monitorHead.extend({
      last_run_id: z.uuid().nullable(),
      last_status: text.nullable(),
    }),
  ),
  returned: count,
  total: count,
  limit: count,
  next_offset: count.nullable(),
});

const ThresholdInput = z
  .object({
    minimum: z.enum(["info", "notable", "alert"]).optional(),
    asset_types: z.array(assetType).min(1).max(ASSET_TYPES.length).optional(),
    rules: z
      .object({
        new_certificate_brand_term: z.boolean().optional(),
        new_lookalike_with_mx: z.boolean().optional(),
        new_exposed_service: z.boolean().optional(),
        new_exposure_record: z.boolean().optional(),
        new_asset: z.boolean().optional(),
        attribute_changed: z.boolean().optional(),
        removed_asset: z.boolean().optional(),
        coverage_gap: z.boolean().optional(),
      })
      .strict()
      .optional(),
    brand_terms: z.array(z.string().min(4).max(40)).max(20).optional(),
    include_apex_label: z.boolean().optional(),
  })
  .strict();
export const MonitorCreateInput = z
  .object({
    name: z.string().min(1).max(80),
    investigation: z.enum([...WORKFLOW_NAMES, "phishing", "collectors"]),
    target: z.string().min(1).max(253),
    sources: z.array(adapterName).min(1).max(14),
    interval_hint: z.string().min(1).max(40).default("24h"),
    thresholds: ThresholdInput.optional(),
    webhook_url: z.string().min(1).max(500).nullable().optional(),
    max_candidates: z.number().int().min(1).max(40).default(20),
  })
  .strict();
export const MonitorRunInput = z
  .object({
    id: z.uuid(),
    max_calls: z.number().int().min(1).max(30).default(10),
  })
  .strict();
export const MonitorChangesInput = z
  .object({
    id: z.uuid(),
    run_id: z.uuid().optional(),
    limit: z.number().int().min(1).max(100).default(25),
    cursor: id64.optional(),
  })
  .strict();
export const MonitorListInput = z
  .object({
    limit: z.number().int().min(1).max(100).default(25),
    offset: z.number().int().min(0).default(0),
  })
  .strict();

function parseInput(schema, input) {
  const result = schema.safeParse(input);
  if (!result.success) throw new Error("INVALID_INPUT");
  return result.data;
}
function checked(schema, value) {
  const result = schema.safeParse(value);
  if (!result.success) throw new Error("INTERNAL_OUTPUT_VALIDATION");
  return result.data;
}
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stable(value[key])]),
    );
  return value;
}
function same(left, right) {
  return JSON.stringify(stable(left)) === JSON.stringify(stable(right));
}
function unique(values) {
  return [...new Set(values)];
}
function clip(value, max = 300) {
  const textValue = String(value ?? "");
  return textValue.length > max ? `${textValue.slice(0, max - 1)}…` : textValue;
}
function defaultThresholds(input = {}) {
  const rules = Object.fromEntries(RULE_IDS.map((rule) => [rule, true]));
  return thresholdSchema.parse({
    minimum: input.minimum ?? "notable",
    asset_types: input.asset_types ?? [...ASSET_TYPES],
    rules: { ...rules, ...(input.rules ?? {}) },
    brand_terms: unique(
      (input.brand_terms ?? []).map((term) => term.trim().toLowerCase()),
    ),
    include_apex_label: input.include_apex_label ?? true,
  });
}
function brandTerms(target, thresholds) {
  const terms = [...thresholds.brand_terms];
  if (thresholds.include_apex_label) {
    try {
      const label = domainToUnicode(domain(target)).split(".")[0];
      if (label.length >= 4) terms.push(label.toLowerCase());
    } catch {
      // The target was already authorized. A label that cannot be read adds no term.
    }
  }
  return unique(terms);
}
function authorizeTarget(engine, monitor) {
  if (monitor.investigation === "phishing")
    return authorizeApex(engine.scope, monitor.target);
  let authorized = null;
  for (const source of monitor.sources)
    authorized = engine.scope.target(source, monitor.target);
  return authorized;
}
function sourceDecision(engine, adapter) {
  if (!ADAPTERS[adapter] || !engine.config.enabledAdapters.includes(adapter))
    return "adapter_disabled";
  if (!engine.config.network) return "network_disabled";
  if (ADAPTERS[adapter].mode === "active" && !engine.config.active)
    return "active_disabled";
  return "allowed";
}
function sourceResult(source, status, extra = {}) {
  return {
    source,
    status,
    invoked: Boolean(extra.invoked),
    run_id: extra.run_id ?? null,
    code: extra.code ?? null,
    truncated: Boolean(extra.truncated),
  };
}
function underApex(value, apex) {
  return value === apex || String(value).endsWith(`.${apex}`);
}
function pushAsset(map, asset) {
  const current = map.get(asset.asset_key);
  if (!current) {
    map.set(asset.asset_key, {
      ...asset,
      observation_ids: unique(asset.observation_ids).sort(),
      entity_ids: unique(asset.entity_ids).sort(),
    });
    return;
  }
  current.observation_ids = unique([
    ...current.observation_ids,
    ...asset.observation_ids,
  ]).sort();
  current.entity_ids = unique([
    ...current.entity_ids,
    ...asset.entity_ids,
  ]).sort();
  if (current.asset_type === "subdomain")
    current.attributes = {
      ...current.attributes,
      historical: current.attributes.historical && asset.attributes.historical,
    };
  if (
    Array.isArray(current.attributes.names) ||
    Array.isArray(asset.attributes.names)
  )
    current.attributes = {
      ...current.attributes,
      names: unique([
        ...(current.attributes.names ?? []),
        ...(asset.attributes.names ?? []),
      ]).sort(),
    };
}
function certificateRecord(evidence) {
  const record = String(evidence.record ?? "");
  if (!record || RECORD_STATUSES.has(record)) return null;
  if (
    evidence.verification &&
    evidence.verification !== "certificate_name_only"
  )
    return null;
  return record;
}
export function assetsFromObservations(
  observations,
  apex,
  phishingCandidates = [],
) {
  const map = new Map();
  for (const obs of observations) {
    const evidence = obs.evidence ?? {};
    if (
      obs.type === "domain" &&
      underApex(obs.value, apex) &&
      evidence.verification !== "suspected_impersonation_unconfirmed" &&
      evidence.verification !== "passive_enrichment_unconfirmed"
    ) {
      pushAsset(map, {
        asset_key: `subdomain:${obs.value}`,
        asset_type: "subdomain",
        value: obs.value,
        attributes: {
          name: obs.value,
          historical: Boolean(evidence.historical),
        },
        observation_ids: [obs.observation_id],
        entity_ids: [obs.entity_id],
      });
    }
    if (
      CERTIFICATE_SOURCES.has(obs.source) &&
      obs.type === "domain" &&
      certificateRecord(evidence)
    ) {
      const record = certificateRecord(evidence);
      pushAsset(map, {
        asset_key: `certificate:${obs.source}:${record}`,
        asset_type: "certificate",
        value: obs.value,
        attributes: {
          source: obs.source,
          record,
          names: [obs.value],
          ...(evidence.valid_from ? { valid_from: evidence.valid_from } : {}),
          ...(evidence.valid_until
            ? { valid_until: evidence.valid_until }
            : {}),
        },
        observation_ids: [obs.observation_id],
        entity_ids: [obs.entity_id],
      });
    }
    if (
      obs.source === "httpx" &&
      obs.type === "url" &&
      evidence.certificate_cn
    ) {
      const cn = String(evidence.certificate_cn);
      const issuer = String(evidence.certificate_issuer ?? "");
      pushAsset(map, {
        asset_key: `certificate:httpx:${cn}:${issuer}`,
        asset_type: "certificate",
        value: cn,
        attributes: {
          source: "httpx",
          cn,
          issuer,
          hosts: evidence.host ? [evidence.host] : [],
        },
        observation_ids: [obs.observation_id],
        entity_ids: [obs.entity_id],
      });
    }
    if (obs.source === "dnsx" && obs.type === "ip") {
      const family = isIP(obs.value) === 6 ? "AAAA" : "A";
      const host = String(evidence.host ?? "");
      pushAsset(map, {
        asset_key: `host:${obs.value}`,
        asset_type: "host",
        value: obs.value,
        attributes: { address: obs.value, names: host ? [host] : [] },
        observation_ids: [obs.observation_id],
        entity_ids: [obs.entity_id],
      });
      if (host)
        pushAsset(map, {
          asset_key: `dns:${family}:${host}:${obs.value}`,
          asset_type: "dns",
          value: `${host} ${family} ${obs.value}`,
          attributes: { type: family, host, value: obs.value },
          observation_ids: [obs.observation_id],
          entity_ids: [obs.entity_id],
        });
    }
    if (obs.source === "mx" && obs.type === "mail_domain") {
      for (const record of evidence.mx ?? []) {
        const [priority, exchange] = String(record).split(" ");
        if (!exchange) continue;
        pushAsset(map, {
          asset_key: `dns:MX:${obs.value}:${exchange}`,
          asset_type: "dns",
          value: `${obs.value} MX ${exchange}`,
          attributes: {
            type: "MX",
            host: obs.value,
            value: exchange,
            priority: priority ?? "",
          },
          observation_ids: [obs.observation_id],
          entity_ids: [obs.entity_id],
        });
      }
    }
    if (obs.type === "service") {
      pushAsset(map, {
        asset_key: `exposure:service:${obs.value}`,
        asset_type: "exposure",
        value: obs.value,
        attributes: {
          kind: "service",
          host: String(evidence.host ?? ""),
          port: Number(evidence.port ?? 0),
        },
        observation_ids: [obs.observation_id],
        entity_ids: [obs.entity_id],
      });
    }
    if (obs.source === "httpx" && obs.type === "url") {
      pushAsset(map, {
        asset_key: `exposure:http:${obs.value}`,
        asset_type: "exposure",
        value: obs.value,
        attributes: {
          kind: "service",
          url: obs.value,
          status: Number(evidence.status ?? 0),
          technology: [...(evidence.technology ?? [])].map(String).sort(),
        },
        observation_ids: [obs.observation_id],
        entity_ids: [obs.entity_id],
      });
    }
    if (obs.type === "breach" || obs.type === "secret") {
      pushAsset(map, {
        asset_key: `exposure:${obs.type}:${obs.value}`,
        asset_type: "exposure",
        value: obs.value,
        attributes: {
          kind: obs.type,
          ...(evidence.account ? { account: evidence.account } : {}),
          ...(evidence.document ? { document: evidence.document } : {}),
          ...(evidence.rule ? { rule: evidence.rule } : {}),
        },
        observation_ids: [obs.observation_id],
        entity_ids: [obs.entity_id],
      });
    }
  }
  for (const candidate of phishingCandidates) {
    const mx = (candidate.signals ?? []).find(
      (item) => item.signal === "has_mx",
    );
    const related = observations.filter(
      (obs) => obs.entity_id && obs.entity_id === candidate.entity_id,
    );
    pushAsset(map, {
      asset_key: `lookalike:${candidate.domain}`,
      asset_type: "lookalike",
      value: candidate.domain,
      attributes: {
        technique: candidate.technique,
        similarity: candidate.similarity,
        has_mx: Boolean(mx?.present),
        mx_collected: Boolean(mx?.collected),
        status: "suspected",
      },
      observation_ids: related.map((obs) => obs.observation_id),
      entity_ids: candidate.entity_id ? [candidate.entity_id] : [],
    });
  }
  return [...map.values()].sort((left, right) =>
    left.asset_key.localeCompare(right.asset_key),
  );
}
function changedFields(before, after) {
  const keys = unique([
    ...Object.keys(before ?? {}),
    ...Object.keys(after ?? {}),
  ]);
  return keys.filter((key) => !same(before?.[key], after?.[key])).sort();
}
function certificateTerm(asset, terms) {
  const attributes = asset.after_attributes ?? asset.attributes ?? {};
  const names = [
    ...(attributes.names ?? []),
    attributes.cn,
    ...(attributes.hosts ?? []),
    asset.value,
  ].filter(Boolean);
  for (const name of names)
    for (const term of terms)
      if (mentionsBrand(String(name), term))
        return { term, name: String(name) };
  return null;
}
function classify(change, thresholds, target) {
  const terms = brandTerms(target, thresholds);
  if (change.change === "coverage_gap")
    return {
      significance: "suppressed",
      rule: "coverage_gap",
      basis: `This ${change.asset_type} is absent from the current observations, but its sources did not all complete. Absence is a coverage gap, not a removal.`,
    };
  if (change.change === "removed")
    return {
      significance: "info",
      rule: "removed_asset",
      basis: `Present in the previous snapshot and absent from this comparable collection of ${change.asset_type} assets. Absence is not proof of deletion.`,
    };
  const lookalikeMx =
    change.asset_type === "lookalike" &&
    change.after_attributes?.has_mx === true &&
    change.after_attributes?.mx_collected === true &&
    (change.change === "added" || change.before_attributes?.has_mx !== true);
  if (lookalikeMx)
    return {
      significance: "alert",
      rule: "new_lookalike_with_mx",
      basis: `Lookalike ${change.value} has an MX record${change.change === "added" ? "" : " that was not in the previous snapshot"}. An MX record does not prove a mailbox. The lead stays suspected.`,
    };
  if (change.change === "added" && change.asset_type === "certificate") {
    const match = certificateTerm(change, terms);
    if (match)
      return {
        significance: "alert",
        rule: "new_certificate_brand_term",
        basis: `New certificate ${clip(change.value, 180)} includes brand term "${match.term}" on ${clip(match.name, 180)}. Certificate presence is not ownership or confirmed phishing.`,
      };
  }
  if (
    change.change === "added" &&
    change.asset_type === "exposure" &&
    change.after_attributes?.kind === "service"
  )
    return {
      significance: "alert",
      rule: "new_exposed_service",
      basis: `New exposed service ${clip(change.value, 180)} was observed. An open port or HTTP response is not a confirmed vulnerability.`,
    };
  if (
    change.change === "added" &&
    change.asset_type === "exposure" &&
    ["breach", "secret"].includes(change.after_attributes?.kind)
  )
    return {
      significance: "notable",
      rule: "new_exposure_record",
      basis: `New exposure ${clip(change.value, 180)} was observed. Breach associations and secret locations are not proof of a valid credential.`,
    };
  if (change.change === "changed") {
    const fields = changedFields(
      change.before_attributes,
      change.after_attributes,
    );
    return {
      significance: "info",
      rule: "attribute_changed",
      basis: `Observed attributes differ (${fields.join(", ") || "value"}). A changed evidence set is not proof the real-world asset changed.`,
    };
  }
  return {
    significance: "info",
    rule: "new_asset",
    basis:
      "First appearance in this monitor snapshot. No higher significance rule matched.",
  };
}
function isAlert(change, thresholds) {
  if (!thresholds.asset_types.includes(change.asset_type)) return false;
  if (thresholds.rules[change.rule] === false) return false;
  return RANK[change.significance] >= RANK[thresholds.minimum];
}
export function diffAssets(
  previous,
  current,
  thresholdsInput = {},
  coverage = {},
  target = "",
) {
  const thresholds = defaultThresholds(thresholdsInput);
  const before = new Map(previous.map((asset) => [asset.asset_key, asset]));
  const after = new Map(current.map((asset) => [asset.asset_key, asset]));
  const changes = [];
  for (const key of unique([...before.keys(), ...after.keys()]).sort()) {
    const left = before.get(key);
    const right = after.get(key);
    const assetTypeName = (right ?? left).asset_type;
    const mode = coverage[assetTypeName] ?? "comparable";
    if (mode === "not_collected") continue;
    let draft = null;
    if (right && !left)
      draft = {
        change: "added",
        before_attributes: null,
        after_attributes: right.attributes,
        observation_ids: right.observation_ids,
        entity_ids: right.entity_ids,
        asset: right,
      };
    else if (left && !right)
      draft = {
        change: mode === "comparable" ? "removed" : "coverage_gap",
        before_attributes: left.attributes,
        after_attributes: null,
        observation_ids: left.observation_ids,
        entity_ids: left.entity_ids,
        asset: left,
      };
    else if (left && right && !same(left.attributes, right.attributes))
      draft = {
        change: "changed",
        before_attributes: left.attributes,
        after_attributes: right.attributes,
        observation_ids: right.observation_ids,
        entity_ids: right.entity_ids,
        asset: right,
      };
    if (!draft) continue;
    const classified = classify(
      {
        ...draft,
        asset_type: assetTypeName,
        asset_key: key,
        value: draft.asset.value,
      },
      thresholds,
      target,
    );
    changes.push({
      asset_key: key,
      asset_type: assetTypeName,
      value: draft.asset.value,
      change: draft.change,
      before_attributes: draft.before_attributes,
      after_attributes: draft.after_attributes,
      observation_ids: draft.observation_ids ?? [],
      entity_ids: draft.entity_ids ?? [],
      ...classified,
    });
  }
  const visible = changes.filter(
    (change) =>
      thresholds.asset_types.includes(change.asset_type) &&
      thresholds.rules[change.rule] !== false,
  );
  const alerts = visible.filter((change) => isAlert(change, thresholds));
  return { thresholds, changes: visible, alerts };
}
function coverageFor(type, monitorSources, invocations) {
  if (type === "lookalike") {
    const run = invocations.find((item) => item.source === "phishing");
    if (!run?.invoked) return "not_collected";
    if (run.status !== "completed" || run.truncated) return "partial";
    return "comparable";
  }
  const producers = PRODUCERS[type].filter((source) =>
    monitorSources.includes(source),
  );
  if (!producers.length) return "not_collected";
  const relevant = invocations.filter((item) =>
    producers.includes(item.source),
  );
  if (!relevant.some((item) => item.invoked)) return "not_collected";
  const incomplete = producers.some((source) => {
    const item = relevant.find((candidate) => candidate.source === source);
    return !item?.invoked || item.status !== "completed" || item.truncated;
  });
  return incomplete ? "partial" : "comparable";
}
function snapshotAssets(current, previous, coverage) {
  const byKey = new Map(current.map((asset) => [asset.asset_key, asset]));
  for (const asset of previous) {
    const mode = coverage[asset.asset_type] ?? "not_collected";
    if (mode !== "comparable" && !byKey.has(asset.asset_key))
      byKey.set(asset.asset_key, asset);
  }
  return [...byKey.values()].sort((left, right) =>
    left.asset_key.localeCompare(right.asset_key),
  );
}
function loadObservations(store, runId) {
  return store.db
    .prepare(
      `SELECT observation_id, entity_id, payload FROM run_observations
       WHERE run_id=? ORDER BY observation_id`,
    )
    .all(runId)
    .map((rowItem) => {
      const payload = JSON.parse(rowItem.payload);
      return {
        observation_id: rowItem.observation_id,
        entity_id: rowItem.entity_id,
        type: payload.type,
        value: payload.value,
        source: payload.source,
        evidence: payload.evidence ?? {},
      };
    });
}
function loadAssets(store, runId) {
  return store.db
    .prepare(
      `SELECT asset_key, asset_type, value, attributes, observation_ids, entity_ids
       FROM monitor_assets WHERE run_id=? ORDER BY asset_key`,
    )
    .all(runId)
    .map((rowItem) => ({
      asset_key: rowItem.asset_key,
      asset_type: rowItem.asset_type,
      value: rowItem.value,
      attributes: JSON.parse(rowItem.attributes),
      observation_ids: JSON.parse(rowItem.observation_ids),
      entity_ids: JSON.parse(rowItem.entity_ids),
    }));
}
function previousSnapshot(store, monitorId) {
  return (
    store.db
      .prepare(
        `SELECT id FROM monitor_runs
         WHERE monitor_id=? AND snapshot=1
         ORDER BY started_at DESC, id DESC LIMIT 1`,
      )
      .get(monitorId)?.id ?? null
  );
}
function countUnreviewed(store, ids) {
  const decided = store.db.prepare(
    `SELECT 1 FROM review_decisions
     WHERE subject_kind='entity' AND subject_id=? AND decision IN ('accept','reject')
     LIMIT 1`,
  );
  const present = store.db.prepare("SELECT 1 FROM entities WHERE id=?");
  let queued = 0;
  for (const entityId of unique(ids)) {
    if (!/^[a-f0-9]{64}$/.test(entityId)) continue;
    if (present.get(entityId) && !decided.get(entityId)) queued++;
  }
  return queued;
}
function phishingSourceRows(result, sources) {
  return sources.map((source) => {
    const enrichmentName = source === "mx" ? "dns" : source;
    const items = (result?.candidates ?? []).flatMap((candidate) =>
      (candidate.enrichment ?? []).filter(
        (item) => item.source === enrichmentName,
      ),
    );
    if (!result || !items.length) return sourceResult(source, "not_run");
    const invoked = items.some((item) =>
      ["completed", "not_found", "failed"].includes(item.status),
    );
    const status = items.some((item) => item.status === "failed")
      ? "failed"
      : items.some((item) => item.status === "budget_exhausted")
        ? "budget_exhausted"
        : items.every((item) =>
              ["completed", "not_found"].includes(item.status),
            )
          ? "completed"
          : items[0].status;
    return sourceResult(source, status, {
      invoked,
      run_id: result.run_id,
      truncated: Boolean(result.truncated) || status === "budget_exhausted",
    });
  });
}
function overallStatus(invocations) {
  const invoked = invocations.filter((item) => item.invoked);
  if (!invoked.length) return "deferred";
  if (
    invocations.every(
      (item) => item.invoked && item.status === "completed" && !item.truncated,
    )
  )
    return "completed";
  return "partial";
}
export function webhookPlan(networkEnabled, webhookEnabled, alertCount) {
  if (!webhookEnabled)
    return { enabled: false, attempted: false, status: "disabled" };
  if (!alertCount)
    return { enabled: true, attempted: false, status: "not_sent" };
  if (!networkEnabled)
    return { enabled: true, attempted: false, status: "hook_skipped" };
  return { enabled: true, attempted: true, status: "hook_sent" };
}
async function deliverWebhook(engine, monitor, runId, alerts, signal) {
  const plan = webhookPlan(
    engine.config.network,
    Boolean(monitor.webhook_url),
    alerts.length,
  );
  if (plan.status !== "hook_sent") return plan;
  const payload = JSON.stringify({
    monitor_id: monitor.id,
    run_id: runId,
    scheduler: "external",
    truncated: alerts.length > MAX_RETURNED_ALERTS,
    alerts: alerts.slice(0, MAX_RETURNED_ALERTS).map((alert) => ({
      rule: alert.rule,
      significance: alert.significance,
      change: alert.change,
      asset_type: alert.asset_type,
      value: alert.value,
      basis: alert.basis,
      entity_ids: alert.entity_ids,
      observation_ids: alert.observation_ids,
    })),
  });
  try {
    const destination = allowedWebhook(
      monitor.webhook_url,
      engine.config.webhookAllowedUrls,
    );
    const response = await engine.providers.fetch(
      destination.href,
      {
        method: "POST",
        redirect: "error",
        headers: {
          "content-type": "application/json",
          "user-agent":
            "OSINT_POWER/0.4 (+https://github.com/jenmar23rondon-ux/OSINT_POWER)",
        },
        body: payload,
        signal: AbortSignal.timeout(engine.config.limits.timeoutMs),
      },
      (_url, options) => postWebhook(destination, options, engine.dependencies),
      signal,
    );
    await response.body?.cancel?.();
    return response.ok
      ? plan
      : { enabled: true, attempted: true, status: "hook_failed" };
  } catch {
    return { enabled: true, attempted: true, status: "hook_failed" };
  }
}
function alertChannel(status) {
  if (status === "disabled" || status === "not_sent") return "local";
  return "webhook";
}
function alertStatus(webhookStatus) {
  if (webhookStatus === "hook_sent") return "hook_sent";
  if (webhookStatus === "hook_failed") return "hook_failed";
  if (webhookStatus === "hook_skipped") return "hook_skipped";
  return "recorded";
}
function persistDiff(
  store,
  monitor,
  runId,
  previousRunId,
  snapshot,
  diff,
  webhook,
) {
  const now = new Date().toISOString();
  const insertAsset = store.db.prepare(
    `INSERT INTO monitor_assets VALUES(?,?,?,?,?,?,?)`,
  );
  const insertChange = store.db.prepare(
    `INSERT INTO monitor_changes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  );
  const insertAlert = store.db.prepare(
    `INSERT INTO monitor_alerts VALUES(?,?,?,?,?,?,?,?)`,
  );
  const changes = diff.changes.map((change) => {
    const alerting = diff.alerts.some(
      (alert) =>
        alert.asset_key === change.asset_key && alert.change === change.change,
    );
    return {
      ...change,
      id: hash(["monitor-change", runId, change.change, change.asset_key]),
      alert: alerting,
    };
  });
  store.db.exec("BEGIN IMMEDIATE");
  try {
    for (const asset of snapshot.slice(0, MAX_ASSETS))
      insertAsset.run(
        runId,
        asset.asset_key,
        asset.asset_type,
        asset.value,
        JSON.stringify(stable(asset.attributes)),
        JSON.stringify(asset.observation_ids),
        JSON.stringify(asset.entity_ids),
      );
    for (const change of changes) {
      insertChange.run(
        change.id,
        runId,
        monitor.id,
        change.change,
        change.asset_type,
        change.asset_key,
        change.value,
        change.before_attributes
          ? JSON.stringify(stable(change.before_attributes))
          : null,
        change.after_attributes
          ? JSON.stringify(stable(change.after_attributes))
          : null,
        JSON.stringify(change.observation_ids),
        JSON.stringify(change.entity_ids),
        change.significance,
        change.rule,
        change.basis,
        Number(change.alert),
      );
      if (!change.alert) continue;
      insertAlert.run(
        hash(["monitor-alert", change.id]),
        runId,
        change.id,
        monitor.id,
        alertStatus(webhook.status),
        alertChannel(webhook.status),
        JSON.stringify({
          rule: change.rule,
          basis: change.basis,
          value: change.value,
          entity_ids: change.entity_ids,
          observation_ids: change.observation_ids,
        }),
        now,
      );
    }
    store.db
      .prepare(
        `UPDATE monitor_runs
         SET finished_at=?, status=?, previous_run_id=?, snapshot=1, summary=?
         WHERE id=?`,
      )
      .run(
        now,
        "running",
        previousRunId,
        JSON.stringify({
          webhook,
          assets: Math.min(snapshot.length, MAX_ASSETS),
        }),
        runId,
      );
    store.db.exec("COMMIT");
  } catch (error) {
    store.db.exec("ROLLBACK");
    throw error;
  }
  return changes;
}
function publicChange(change) {
  return {
    id: change.id,
    change: change.change,
    asset_type: change.asset_type,
    asset_key: change.asset_key,
    value: change.value,
    significance: change.significance,
    rule: change.rule,
    basis: change.basis,
    before_attributes: change.before_attributes,
    after_attributes: change.after_attributes,
    observation_ids: change.observation_ids,
    entity_ids: change.entity_ids,
    alert: Boolean(change.alert),
  };
}
function countsOf(changes, assets) {
  return {
    assets,
    added: changes.filter((change) => change.change === "added").length,
    removed: changes.filter((change) => change.change === "removed").length,
    changed: changes.filter((change) => change.change === "changed").length,
    coverage_gaps: changes.filter((change) => change.change === "coverage_gap")
      .length,
    alerts: changes.filter((change) => change.alert).length,
  };
}
function finishMonitor(store, runId, status, summary) {
  store.finish(runId, status, summary);
  store.db
    .prepare(
      `UPDATE monitor_runs SET finished_at=?, status=?, summary=? WHERE id=?`,
    )
    .run(new Date().toISOString(), status, JSON.stringify(summary), runId);
}
function loadMonitor(store, id) {
  const rowItem = store.db.prepare("SELECT * FROM monitors WHERE id=?").get(id);
  if (!rowItem) return null;
  return {
    ...rowItem,
    sources: JSON.parse(rowItem.sources),
    thresholds: JSON.parse(rowItem.thresholds),
    webhook_enabled: Boolean(rowItem.webhook_url),
  };
}
function head(rowItem, last) {
  return {
    id: rowItem.id,
    name: rowItem.name,
    investigation: rowItem.investigation,
    target: rowItem.target,
    sources: JSON.parse(rowItem.sources),
    interval_hint: rowItem.interval_hint,
    thresholds: JSON.parse(rowItem.thresholds),
    webhook_enabled: Boolean(rowItem.webhook_url),
    scheduler: "external",
    created_at: rowItem.created_at,
    last_run_id: last?.id ?? null,
    last_status: last?.status ?? null,
  };
}
export function initializeMonitor(db) {
  const version = db.prepare("PRAGMA user_version").get().user_version;
  if (version > SCHEMA_VERSION) throw new Error("DATABASE_VERSION_TOO_NEW");
  db.exec(`
    CREATE TABLE IF NOT EXISTS monitors(
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      investigation TEXT NOT NULL,
      target TEXT NOT NULL,
      sources TEXT NOT NULL,
      interval_hint TEXT NOT NULL,
      thresholds TEXT NOT NULL,
      webhook_url TEXT,
      max_candidates INTEGER NOT NULL,
      created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS monitor_runs(
      id TEXT PRIMARY KEY,
      monitor_id TEXT NOT NULL REFERENCES monitors(id),
      started_at TEXT NOT NULL,
      finished_at TEXT,
      status TEXT NOT NULL,
      previous_run_id TEXT,
      snapshot INTEGER NOT NULL DEFAULT 0,
      summary TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS monitor_runs_monitor
      ON monitor_runs(monitor_id, started_at);
    CREATE TABLE IF NOT EXISTS monitor_assets(
      run_id TEXT NOT NULL REFERENCES monitor_runs(id),
      asset_key TEXT NOT NULL,
      asset_type TEXT NOT NULL,
      value TEXT NOT NULL,
      attributes TEXT NOT NULL,
      observation_ids TEXT NOT NULL,
      entity_ids TEXT NOT NULL,
      PRIMARY KEY(run_id, asset_key));
    CREATE TABLE IF NOT EXISTS monitor_changes(
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL REFERENCES monitor_runs(id),
      monitor_id TEXT NOT NULL REFERENCES monitors(id),
      change TEXT NOT NULL,
      asset_type TEXT NOT NULL,
      asset_key TEXT NOT NULL,
      value TEXT NOT NULL,
      before_attributes TEXT,
      after_attributes TEXT,
      observation_ids TEXT NOT NULL,
      entity_ids TEXT NOT NULL,
      significance TEXT NOT NULL,
      rule TEXT NOT NULL,
      basis TEXT NOT NULL,
      alert INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS monitor_changes_run ON monitor_changes(run_id, id);
    CREATE TABLE IF NOT EXISTS monitor_alerts(
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL REFERENCES monitor_runs(id),
      change_id TEXT NOT NULL REFERENCES monitor_changes(id),
      monitor_id TEXT NOT NULL,
      status TEXT NOT NULL,
      channel TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at TEXT NOT NULL);`);
}
export function createMonitor(engine, input) {
  const source = input && typeof input === "object" ? { ...input } : input;
  if (source && typeof source === "object") {
    if (typeof source.name === "string") source.name = source.name.trim();
    if (typeof source.target === "string") source.target = source.target.trim();
    if (typeof source.interval_hint === "string")
      source.interval_hint = source.interval_hint.trim();
    if (Array.isArray(source.sources))
      source.sources = unique(
        source.sources.map((item) => String(item).trim()),
      );
  }
  const data = parseInput(MonitorCreateInput, source);
  if (!/^[A-Za-z0-9][A-Za-z0-9 _.:-]{0,79}$/.test(data.name))
    throw new Error("INVALID_INPUT");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,39}$/.test(data.interval_hint))
    throw new Error("INVALID_INPUT");
  if (
    data.investigation === "phishing" &&
    data.sources.some((item) => !PHISHING_SOURCES.has(item))
  )
    throw new Error("SOURCE_NOT_SUPPORTED");
  const thresholds = defaultThresholds(data.thresholds);
  const webhook = data.webhook_url
    ? allowedWebhook(data.webhook_url, engine.config.webhookAllowedUrls).href
    : null;
  const draft = {
    id: randomUUID(),
    investigation: data.investigation,
    target: data.target,
    sources: data.sources,
  };
  const target = authorizeTarget(engine, draft);
  const created = new Date().toISOString();
  engine.store.db
    .prepare("INSERT INTO monitors VALUES(?,?,?,?,?,?,?,?,?,?)")
    .run(
      draft.id,
      data.name,
      data.investigation,
      target,
      JSON.stringify(data.sources),
      data.interval_hint,
      JSON.stringify(thresholds),
      webhook,
      data.max_candidates,
      created,
    );
  return checked(MonitorCreated, {
    id: draft.id,
    name: data.name,
    investigation: data.investigation,
    target,
    sources: data.sources,
    interval_hint: data.interval_hint,
    thresholds,
    webhook_enabled: Boolean(webhook),
    scheduler: "external",
    created_at: created,
  });
}
export function listMonitors(store, input = {}) {
  const { limit, offset } = parseInput(MonitorListInput, input);
  const total = store.db.prepare("SELECT COUNT(*) AS n FROM monitors").get().n;
  const rows = store.db
    .prepare(
      `SELECT * FROM monitors ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?`,
    )
    .all(limit, offset);
  const last = store.db.prepare(
    `SELECT id, status FROM monitor_runs WHERE monitor_id=?
     ORDER BY started_at DESC, id DESC LIMIT 1`,
  );
  return checked(MonitorListResult, {
    items: rows.map((item) => head(item, last.get(item.id))),
    returned: rows.length,
    total,
    limit,
    next_offset: offset + rows.length < total ? offset + rows.length : null,
  });
}
function readChanges(store, runId) {
  return store.db
    .prepare(`SELECT * FROM monitor_changes WHERE run_id=? ORDER BY id ASC`)
    .all(runId)
    .map((item) =>
      publicChange({
        ...item,
        before_attributes: item.before_attributes
          ? JSON.parse(item.before_attributes)
          : null,
        after_attributes: item.after_attributes
          ? JSON.parse(item.after_attributes)
          : null,
        observation_ids: JSON.parse(item.observation_ids),
        entity_ids: JSON.parse(item.entity_ids),
        alert: Boolean(item.alert),
      }),
    );
}
export function monitorChanges(store, input = {}) {
  const data = parseInput(MonitorChangesInput, input);
  if (!store.db.prepare("SELECT 1 FROM monitors WHERE id=?").get(data.id))
    throw new Error("MONITOR_NOT_FOUND");
  const run = data.run_id
    ? store.db
        .prepare("SELECT * FROM monitor_runs WHERE id=? AND monitor_id=?")
        .get(data.run_id, data.id)
    : store.db
        .prepare(
          `SELECT * FROM monitor_runs WHERE monitor_id=?
           ORDER BY started_at DESC, id DESC LIMIT 1`,
        )
        .get(data.id);
  if (!run) throw new Error("MONITOR_RUN_NOT_FOUND");
  const items = readChanges(store, run.id);
  const pageStart = data.cursor
    ? items.filter((item) => item.id > data.cursor)
    : items;
  const page = pageStart.slice(0, data.limit);
  return checked(MonitorChangesResult, {
    monitor_id: data.id,
    run_id: run.id,
    status: run.status,
    items: page,
    returned: page.length,
    limit: data.limit,
    next_cursor: pageStart.length > data.limit ? page.at(-1).id : null,
    total: items.length,
    alert_count: items.filter((item) => item.alert).length,
    coverage_complete: false,
    limitations: MONITOR_LIMITATIONS,
    scheduler: "external",
  });
}
export function monitorMarkdown(report) {
  const lines = [
    "# Monitor changes",
    "",
    "Local diff only. This file was not sent anywhere by the report command.",
    "",
    `- Monitor: \`${report.monitor_id}\``,
    `- Run: \`${report.run_id}\``,
    `- Status: ${report.status}`,
    "- Scheduler: external. Nothing in this project runs the monitor on a timer.",
    "",
    `Changes: ${report.total}. Alerts: ${report.alert_count}.`,
    "",
  ];
  if (!report.items.length) lines.push("No changes in this page.", "");
  for (const item of report.items) {
    const value = String(item.value).replaceAll("`", "'");
    lines.push(
      `## ${item.change}: ${value}`,
      "",
      `- Asset: ${item.asset_type} \`${item.asset_key}\``,
      `- Significance: ${item.significance} (${item.rule})`,
      `- Alert: ${item.alert ? "yes" : "no"}`,
      `- Entities: ${item.entity_ids.length ? item.entity_ids.map((entity) => `\`${entity}\``).join(", ") : "none"}`,
      `- Observations: ${item.observation_ids.length ? item.observation_ids.map((observation) => `\`${observation}\``).join(", ") : "none"}`,
      "",
      item.basis,
      "",
    );
  }
  lines.push("## Limitations", "");
  for (const limitation of report.limitations) lines.push(`- ${limitation}`);
  lines.push("");
  return lines.join("\n");
}
async function collect(engine, monitor, runId, maxCalls, signal) {
  const invocations = [];
  let calls = 0;
  for (const source of monitor.sources) {
    signal?.throwIfAborted();
    const decision = sourceDecision(engine, source);
    if (decision !== "allowed") {
      invocations.push(sourceResult(source, decision));
      continue;
    }
    if (calls >= maxCalls) {
      invocations.push(sourceResult(source, "budget_exhausted"));
      continue;
    }
    calls++;
    const result = await engine.run(
      { adapter: source, target: monitor.target },
      {
        signal,
        parentRunId: runId,
      },
    );
    invocations.push(
      sourceResult(source, result.status, {
        invoked: true,
        run_id: result.run_id,
        code: result.code ?? null,
        truncated: result.truncated,
      }),
    );
    if (result.status === "cancelled") throw new Error("CANCELLED");
  }
  return invocations;
}
export async function runMonitor(engine, input, signal) {
  const request = parseInput(MonitorRunInput, input ?? {});
  const monitor = loadMonitor(engine.store, request.id);
  if (!monitor) throw new Error("MONITOR_NOT_FOUND");
  signal?.throwIfAborted();
  const target = authorizeTarget(engine, monitor);
  const runId = engine.store.start(`monitor:${monitor.investigation}`, target);
  const started = new Date().toISOString();
  engine.store.db
    .prepare("INSERT INTO monitor_runs VALUES(?,?,?,?,?,?,?,?)")
    .run(runId, monitor.id, started, null, "running", null, 0, "{}");
  try {
    let invocations;
    let phishingResult = null;
    if (monitor.investigation === "phishing") {
      const allowed = monitor.sources.filter(
        (source) => sourceDecision(engine, source) === "allowed",
      );
      if (!allowed.length)
        invocations = monitor.sources.map((source) =>
          sourceResult(source, sourceDecision(engine, source)),
        );
      else {
        phishingResult = await runPhishingWorkflow(
          engine,
          {
            target,
            execute: true,
            maxCandidates: monitor.max_candidates,
            maxCalls: request.max_calls,
          },
          signal,
          { sources: allowed },
        );
        if (phishingResult.run_id)
          mirrorRun(engine.store, phishingResult.run_id, runId);
        invocations = [
          ...phishingSourceRows(phishingResult, monitor.sources),
          sourceResult("phishing", phishingResult.status, {
            invoked: true,
            run_id: phishingResult.run_id,
            truncated: phishingResult.truncated,
          }),
        ];
      }
    } else
      invocations = await collect(
        engine,
        monitor,
        runId,
        request.max_calls,
        signal,
      );
    const status = overallStatus(invocations);
    const previousRunId =
      status === "deferred" ? null : previousSnapshot(engine.store, monitor.id);
    let changes = [];
    let webhook = webhookPlan(
      engine.config.network,
      Boolean(monitor.webhook_url),
      0,
    );
    if (status !== "deferred") {
      const current = assetsFromObservations(
        loadObservations(engine.store, runId),
        target,
        phishingResult?.candidates ?? [],
      );
      const truncatedAssets = current.length > MAX_ASSETS;
      const bounded = current.slice(0, MAX_ASSETS);
      const previous = previousRunId
        ? loadAssets(engine.store, previousRunId)
        : [];
      const coverage = Object.fromEntries(
        ASSET_TYPES.map((type) => [
          type,
          truncatedAssets
            ? "partial"
            : coverageFor(type, monitor.sources, invocations),
        ]),
      );
      const diff = diffAssets(
        previous,
        bounded,
        monitor.thresholds,
        coverage,
        target,
      );
      webhook = await deliverWebhook(
        engine,
        monitor,
        runId,
        diff.alerts,
        signal,
      );
      const snapshot = snapshotAssets(bounded, previous, coverage).slice(
        0,
        MAX_ASSETS,
      );
      changes = persistDiff(
        engine.store,
        monitor,
        runId,
        previousRunId,
        snapshot,
        diff,
        webhook,
      );
    }
    const assetCount =
      status === "deferred"
        ? 0
        : engine.store.db
            .prepare("SELECT COUNT(*) AS n FROM monitor_assets WHERE run_id=?")
            .get(runId).n;
    const counts = countsOf(changes, assetCount);
    const alerts = changes.filter((change) => change.alert);
    const queued = countUnreviewed(
      engine.store,
      changes
        .filter((change) => change.change === "added")
        .flatMap((change) => change.entity_ids),
    );
    const result = {
      monitor_id: monitor.id,
      run_id: runId,
      mode: "execute",
      status,
      target,
      previous_run_id: previousRunId,
      sources: invocations,
      counts,
      alerts: alerts.slice(0, MAX_RETURNED_ALERTS).map(publicChange),
      returned: Math.min(alerts.length, MAX_RETURNED_ALERTS),
      truncated: alerts.length > MAX_RETURNED_ALERTS,
      coverage_complete: false,
      review: {
        queued_entities: queued,
        auto_confirmed: false,
        note: REVIEW_NOTE,
      },
      webhook,
      limitations: MONITOR_LIMITATIONS,
      scheduler: "external",
    };
    const summary = {
      status,
      counts,
      webhook,
      coverage_complete: false,
    };
    finishMonitor(engine.store, runId, status, summary);
    return checked(MonitorRunResult, result);
  } catch (error) {
    const code = /^[A-Z_0-9]+$/.test(error.message ?? "")
      ? error.message
      : "MONITOR_FAILED";
    try {
      finishMonitor(engine.store, runId, "failed", { code });
    } catch {
      // The run row is best-effort once collection has already failed.
    }
    throw new Error(code);
  }
}
