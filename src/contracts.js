import { z } from "zod";
import { Config, EntityType, Observation, WorkflowInput } from "./schema.js";

const text = z.string(),
  count = z.number().int().nonnegative(),
  id = z.string().regex(/^[a-f0-9]{64}$/);
const json = z.record(z.string(), z.json());
const row = (shape) => z.object(shape).strict();
const extensible = (shape) => z.object(shape).catchall(z.json());
const action = extensible({ rank: count, action: text, reason: text });
const actions = z.array(action);
const errorResult = row({ code: text });
const entity = row({
  id,
  type: EntityType,
  value: text,
  first_seen: text,
  last_seen: text,
});
const finding = entity.extend({
  sources: z.array(text),
  sources_total: count,
  sources_truncated: z.boolean(),
  evidence_count: count,
  confidence: z.number().min(0).max(1),
  confidence_basis: text,
});
const page = row({
  items: z.array(finding),
  returned: count,
  truncated: z.boolean(),
  next_cursor: id.nullable(),
  limit: count,
  total: count,
});
const evidence = row({
  items: z.array(
    row({
      id,
      entity_id: id,
      source: text,
      confidence: z.number(),
      timestamp: text,
      evidence: json,
      first_seen: text,
      last_seen: text,
      untrusted: z.literal(true),
    }),
  ),
  next_offset: count.nullable(),
});
const edge = row({
  id,
  from_id: id,
  to_id: id,
  relation: text,
  observation_id: id,
  from_value: text,
  to_value: text,
});
const graph = row({
  items: z.array(edge),
  next_offset: count.nullable(),
  note: text,
});
const source = row({
  run_id: text,
  collector: text,
  target: text,
  status: text,
  cached: z.boolean(),
  truncated: z.boolean(),
  collected_at: text,
  summary: json,
});
const sources = z.array(source);
const run = row({
  id: text,
  adapter: text,
  target: text,
  started: text,
  finished: text.nullable(),
  status: text,
  summary: json.nullable(),
});
const request = WorkflowInput;
const status = z.enum([
  "completed",
  "partial",
  "failed",
  "deferred",
  "cancelled",
  "interrupted",
]);
const collection = row({
  run_id: text,
  status,
  adapter: text.optional(),
  target: text.optional(),
  cached: z.boolean().optional(),
  attempts: count.optional(),
  observations: count.optional(),
  inserted: count.optional(),
  entities_inserted: count.optional(),
  repeated: count.optional(),
  http_requests: count.optional(),
  skipped: count.optional(),
  invalid: count.optional(),
  truncated: z.boolean().optional(),
  collected_at: text.optional(),
  input_hash: id.optional(),
  configuration_digest: id.optional(),
  collector_version: text.optional(),
  coverage_complete: z.boolean().optional(),
  discovery: row({
    next_cursor: text.nullable().optional(),
    exhausted: z.boolean(),
    records: count,
    coverage_mode: z.literal("incremental_page"),
    coverage_complete: z.literal(false),
    has_more: z.boolean(),
    cursor_hash: id.nullable(),
    cursor_advanced: z.boolean().optional(),
  }).optional(),
  code: text.optional(),
  retry_after_ms: count.optional(),
  next_actions: actions,
});
const jobHead = row({ id: text, status: text, request });
const jobList = row({
  items: z.array(
    row({
      id: text,
      status: text,
      calls: count,
      cancel_requested: z.boolean(),
      lease_until: count,
      created_at: text,
      updated_at: text,
      lease_active: z.boolean(),
    }),
  ),
  returned: count,
  total: count,
  next_offset: count.nullable(),
});
const job = row({
  id: text,
  status: text,
  request,
  calls: count,
  cancel_requested: z.boolean(),
  lease_active: z.boolean(),
  lease_expires_at: text.nullable(),
  created_at: text,
  updated_at: text,
  result: json.nullable(),
  steps: z.array(
    extensible({
      job_id: text,
      step_key: text,
      stage: text,
      kind: text,
      input: json,
      status: text,
      attempts: count,
      child_run_id: text.nullable(),
      result: json.nullable(),
      updated_at: text,
    }),
  ),
  total_steps: count,
});
const health = row({
  providers: z.array(
    extensible({
      provider: text,
      status: text,
      used: count,
      requests: count,
      failures: count,
      remaining: count,
      policy: Config.shape.limits.unwrap().shape.providers.unwrap().shape
        .defaults,
      retry_at: text,
    }),
  ),
  coordination: text,
});
const correlation = row({
  company: text,
  counts: row({
    domains: count,
    ips: count,
    emails: count,
    breach_associations: count,
    observed_services: count,
  }),
  samples: row({
    domains: count,
    ips: count,
    emails: count,
    breach_associations: count,
    observed_services: count,
  }),
  truncated: z.boolean(),
  bounded: z.literal(true),
  summary_limits: row({
    entities_per_type: count,
    observations_per_review: count,
  }),
  professional_coverage: z.array(
    row({
      name: text,
      employee: text,
      observations: count,
      identity_verified: z.literal(false),
    }),
  ),
  defensive_review: z.array(row({ entity_id: id, type: text, reason: text })),
  conclusions: row({
    probable_entry_point: text,
    employee_risk_ranking: text,
    physical_location_from_ip: text,
  }),
  next_actions: actions,
});
const workflow = row({
  workflow: text,
  target: text,
  person: text.nullable(),
  mode: text,
  status: text,
  run_id: text.nullable(),
  calls: count,
  maxCalls: count,
  maxTargets: count,
  steps: z.array(extensible({ stage: text, status: text })),
  correlation,
  username_candidates: z.array(text),
  findings: row({
    items: z.array(
      extensible({
        id,
        type: EntityType,
        value: text,
        source: text,
        confidence: z.number(),
        timestamp: text,
        evidence: json,
        untrusted: z.literal(true),
      }),
    ),
    limit: count,
    bounded: z.literal(true),
  }),
  next_actions: actions,
  snapshot_id: text.optional(),
  code: text.optional(),
});
const cancel = row({ id: text, status: text });
const planAction = row({
  tool: z.literal("collect"),
  arguments: row({ adapter: text, target: text }),
  eligibility: text,
  score: z.number(),
  reasons: z.array(text),
  cached: z.boolean(),
  estimated_logical_calls: count,
  provider: text.nullable(),
  retry_at: text.nullable(),
  rank: count.optional(),
  source_metrics: json.optional(),
});
const provenance = json;
export const BundleResult = row({
  format: z.literal("osint-power-evidence"),
  schema_version: z.literal("0.4"),
  manifest: row({
    run: row({
      id: text,
      adapter: text,
      target: text,
      started: text,
      finished: text,
      status: text,
    }),
    capture_count: count,
    capture_digest: id,
    source_summaries: z.array(
      row({
        collector: text,
        target: text,
        status: text,
        cached: z.boolean(),
        truncated: z.boolean(),
        collected_at: text,
        coverage_complete: z.boolean(),
        input_hash: id.nullable(),
        configuration_digest: id.nullable(),
        collector_version: text,
      }),
    ),
    excerpt_policy: text,
    authenticity: text,
  }),
  captures: z.array(
    row({
      observation_id: id,
      entity_id: id,
      collector: text,
      target: text,
      payload: Observation,
      provenance,
    }),
  ),
  page: row({
    limit: count,
    total: count,
    returned: count,
    next_cursor: text.nullable(),
    complete: z.boolean(),
  }),
  integrity: row({
    algorithm: z.literal("sha256-canonical-json-v1"),
    manifest_sha256: id,
    page_sha256: id,
  }),
});
const analystDecision = row({
  id: text,
  subject_kind: z.enum(["entity", "finding"]),
  subject_id: id,
  decision: z.enum(["accept", "reject", "needs-more-evidence"]),
  reason: text,
  analyst_id: text,
  recorded_at: text,
});
const resolutionLink = row({
  id,
  status: z.enum(["candidate", "confirmed"]),
  basis: text,
  confidence: z.number().min(0).max(1),
  confidence_basis: text,
  other: row({ id, type: EntityType, value: text }),
  shared_names: z.array(text),
  shared_handles: z.array(text),
  shared_identifiers: z.array(text),
  independent_corroboration: count,
  blocked_reason: text.nullable(),
  evidence: z.array(
    row({
      observation_id: id,
      entity_id: id,
      source: text,
      attribute: text,
      value: text,
      role: text,
    }),
  ),
});
const reviewContradiction = row({
  scope: z.enum(["entity", "linked_entity"]),
  attribute: text,
  entity_ids: z.array(id),
  values: z.array(
    row({
      value: text,
      sources: z.array(text),
      observation_ids: z.array(id),
    }),
  ),
  independent_disagreement: z.boolean(),
});

export const RESULT_SCHEMAS = {
  capabilities: row({
    version: text,
    durable_jobs: z.literal(true),
    workflows: z.array(text),
    network: z.boolean(),
    active: z.boolean(),
    adapters: z.array(
      row({
        name: text,
        mode: z.enum(["passive", "active"]),
        kind: text,
        description: text,
        enabled: z.boolean(),
      }),
    ),
    imports: z.array(text),
    scope: Config.shape.scope,
    limits: Config.shape.limits,
    collectors: Config.shape.collectors,
  }),
  collect: collection,
  passive_pipeline: row({
    status: text,
    results: z.array(
      z.union([collection, row({ adapter: text, status: text, code: text })]),
    ),
    next_actions: actions,
  }),
  import_findings: collection,
  query_findings: page,
  get_evidence: evidence,
  get_graph: graph,
  workflow,
  start_workflow: jobHead,
  resume_run: z.union([
    workflow,
    job,
    row({
      run_id: text,
      status,
      code: text.optional(),
      snapshot_id: text.optional(),
      next_actions: actions.optional(),
    }),
  ]),
  cancel_run: cancel,
  get_job: job,
  list_jobs: jobList,
  source_health: health,
  doctor: row({
    version: text,
    status: text,
    network_probe: z.literal(false),
    database: row({
      schema_version: count,
      resumable_jobs: count,
      expired_leases: count,
    }),
    binaries: z.array(
      row({
        adapter: text,
        path: text.nullable(),
        installed: z.boolean(),
        version: text.nullable(),
        compatibility: text,
        missing_flags: z.array(text),
      }),
    ),
    credentials: row({
      hibp_api_key_configured: z.boolean(),
      certspotter_api_key_configured: z.boolean(),
    }),
    providers: health,
    note: text,
  }),
  compare_runs: row({
    before: text,
    after: text,
    counts: z.partialRecord(
      z.enum([
        "added",
        "evidence_changed",
        "not_observed",
        "coverage_gap",
        "unchanged",
      ]),
      count,
    ),
    total: count,
    returned: count,
    items: z.array(
      row({ entity_id: id, change: text, type: EntityType, value: text }),
    ),
    limit: count,
    next_cursor: id.nullable(),
    sources: row({ before: sources, after: sources }),
    interpretation: text,
  }),
  explain_entity: row({
    entity,
    evidence,
    assessment: row({
      existence: text,
      ownership: text,
      identity: text,
      review_status: text,
      freshness: row({
        window_days: z.number(),
        current: count,
        stale: count,
        future_dated: count,
      }),
      source_families: z.array(text),
      conflicting_assertions: z.array(
        row({
          predicate: text,
          value: text,
          supporting_sources: z.array(text),
          observed_at: z.array(text),
          interpretation: text,
        }),
      ),
      calibration: text,
    }),
    assessment_sampled: z.boolean(),
    source_families: z.array(
      row({ family: text, observations: count, independence: text }),
    ),
    history: z.array(
      row({ run_id: text, collector: text, target: text, provenance }),
    ),
    qualifications: z.array(text),
    possible_changes: count,
  }),
  plan_investigation: row({
    workflow: text,
    target: text,
    status: z.literal("planned"),
    actions: z.array(planAction),
    next_actions: z.array(planAction),
    pending_dependencies: z.array(json),
    budget: row({ maxCalls: count, maxTargets: count }),
    scoring: text,
    mutation: z.literal(false),
    network: z.literal(false),
  }),
  get_report: row({
    project: z.literal("OSINT_POWER"),
    version: text,
    generated_at: text,
    findings: page,
    graph,
    runs: z.array(run),
    jobs: jobList,
    source_health: health,
    next_actions: actions,
    limitations: z.array(text),
  }),
  export_evidence: BundleResult,
  list_review_queue: row({
    items: z.array(
      row({
        entity_id: id,
        type: EntityType,
        value: text,
        current_decision: analystDecision.nullable(),
        candidate_links: count,
        confirmed_links: count,
        contradictions: count,
        queue_reasons: z.array(text),
      }),
    ),
    returned: count,
    limit: count,
    next_cursor: id.nullable(),
    total: count,
    rules: z.array(text),
  }),
  record_decision: row({
    current: analystDecision,
    history: z.array(analystDecision),
    appended: z.literal(true),
  }),
  show_entity: row({
    entity,
    current_decision: analystDecision.nullable(),
    decision_history: z.array(analystDecision),
    finding_decisions: z.array(
      row({
        observation_id: id,
        current_decision: analystDecision,
        history_count: count,
      }),
    ),
    candidates: z.array(resolutionLink),
    confirmed_links: z.array(resolutionLink),
    contradictions: z.array(reviewContradiction),
    independence: row({
      observations: count,
      independent_groups: count,
      note: text,
    }),
    rules: z.array(text),
  }),
};

const transient =
  /^(NETWORK_ERROR|BODY_READ_ERROR|HTTP_(429|5\d\d)|RETRY_LATER|PROVIDER_(COOLDOWN|QUOTA_EXHAUSTED|WAIT_REQUIRED)|DISCOVERY_CURSOR_CONFLICT)$/;
export function outputSchema(name) {
  if (!RESULT_SCHEMAS[name]) throw new Error("UNKNOWN_OUTPUT_CONTRACT");
  return row({
    schema_version: z.literal("0.4"),
    ok: z.boolean(),
    execution_status: z.enum(["succeeded", "failed"]),
    collection_status: z.enum([
      "completed",
      "partial",
      "failed",
      "deferred",
      "cancelled",
      "not_applicable",
    ]),
    coverage: row({ complete: z.boolean().nullable(), truncated: z.boolean() }),
    retry: row({ retryable: z.boolean(), retry_after_ms: count }),
    result: z.union([RESULT_SCHEMAS[name], errorResult]),
  });
}
export function toolResponse(name, result, thrown = false) {
  if (!thrown && !RESULT_SCHEMAS[name].safeParse(result).success)
    return toolResponse(name, { code: "INTERNAL_OUTPUT_VALIDATION" }, true);
  const collecting =
    ["collect", "passive_pipeline", "import_findings", "resume_run"].includes(
      name,
    ) ||
    (name === "workflow" && result.mode === "execute");
  const failed =
    thrown ||
    (collecting &&
      ["failed", "cancelled", "interrupted"].includes(result.status));
  const collectionStatus = thrown
    ? "failed"
    : !collecting
      ? "not_applicable"
      : result.status === "failed"
        ? "failed"
        : ["cancelled", "interrupted"].includes(result.status)
          ? "cancelled"
          : collecting
            ? (result.status ?? "completed")
            : "not_applicable";
  const raw = {
    schema_version: "0.4",
    ok: !failed,
    execution_status: failed ? "failed" : "succeeded",
    collection_status: collectionStatus,
    coverage: {
      complete: collecting
        ? (result.coverage_complete ??
          (result.status === "completed" && !result.truncated))
        : null,
      truncated: Boolean(result.truncated),
    },
    retry: {
      retryable: transient.test(result.code ?? ""),
      retry_after_ms: Math.max(0, result.retry_after_ms ?? 0),
    },
    result,
  };
  return outputSchema(name).parse(JSON.parse(JSON.stringify(raw)));
}
