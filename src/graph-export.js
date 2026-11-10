import { z } from "zod";
import { readHypothesisAssessment } from "./cases.js";
import { inspectResolution } from "./review.js";
import { hash } from "./store.js";
import { investigationCoverage } from "./stix.js";

// Read-only graph of one case or one investigation. Nothing here collects,
// writes a review decision, or promotes a candidate to confirmed.
const MAX_NODES = 300;
const MAX_EDGES = 600;
const text = z.string();
const nodeStatus = z.enum([
  "observed",
  "candidate",
  "confirmed",
  "contradicted",
  "open",
  "supported-pending-review",
  "weakened",
  "rejected",
  "analyst-confirmed",
  "accept",
  "reject",
  "needs-more-evidence",
]);
const edgeStatus = z.enum([
  "observation",
  "candidate",
  "confirmed",
  "contradicted",
  "support",
  "decision",
]);
const graphNode = z
  .object({
    id: text,
    kind: z.enum(["entity", "evidence", "hypothesis", "decision"]),
    ref: text,
    label: text,
    detail: text,
    status: nodeStatus,
    confirmed: z.boolean(),
    finding: z.literal(false),
  })
  .strict();
const graphEdge = z
  .object({
    id: text,
    kind: z.enum([
      "observation",
      "candidate-link",
      "confirmed-link",
      "contradiction",
      "supports",
      "contradicts",
      "decision",
    ]),
    from: text,
    to: text,
    label: text,
    status: edgeStatus,
    confirmed: z.boolean(),
    finding: z.literal(false),
  })
  .strict();
const counts = z
  .object({
    nodes: z.number().int().nonnegative(),
    edges: z.number().int().nonnegative(),
    entities: z.number().int().nonnegative(),
    evidence: z.number().int().nonnegative(),
    hypotheses: z.number().int().nonnegative(),
    decisions: z.number().int().nonnegative(),
    candidate_links: z.number().int().nonnegative(),
    confirmed_links: z.number().int().nonnegative(),
    contradictions: z.number().int().nonnegative(),
    omitted_out_of_scope: z.number().int().nonnegative(),
  })
  .strict();
export const GRAPH_LIMITATIONS = [
  "This export reads stored rows. It does not collect, scan, or contact a network.",
  "A candidate link is not a confirmed identity. A shared name or handle stays a candidate.",
  "supported-pending-review is not analyst-confirmed and is not a finding.",
  "analyst-confirmed is an explicit analyst close. It is still not proof of identity, ownership, or phishing.",
  "A resolver-confirmed link requires a non-name identifier with independent corroboration. It is not an analyst finding.",
  "Contradictions are disagreements in stored attributes, not proof of deception.",
  "Out-of-scope entities are omitted.",
  "The HTML file is offline. It loads no remote script, font, or image.",
];
const graphDocument = z
  .object({
    nodes: z.array(graphNode).max(MAX_NODES),
    edges: z.array(graphEdge).max(MAX_EDGES),
    counts,
    limitations: z.array(text),
  })
  .strict();
export const InvestigationGraphInput = z
  .object({
    case_id: z.uuid().optional(),
    investigation: z.string().min(1).max(80).optional(),
    format: z.enum(["json", "html"]).default("json"),
  })
  .strict()
  .superRefine((value, ctx) => {
    const selected =
      Number(Boolean(value.case_id)) + Number(Boolean(value.investigation));
    if (selected !== 1)
      ctx.addIssue({
        code: "custom",
        message: "Choose a case or an investigation.",
      });
  });
export const InvestigationGraphResult = z
  .object({
    format: z.enum(["json", "html"]),
    case_id: z.uuid().nullable(),
    investigation: text.nullable(),
    read_only: z.literal(true),
    executes: z.literal(false),
    network: z.literal(false),
    collection: z.literal(false),
    truncated: z.boolean(),
    graph: graphDocument,
    html: text.nullable(),
    limitations: z.array(text),
  })
  .strict();

const SAFE_EVIDENCE = [
  "host",
  "document",
  "line",
  "rule",
  "credential_kind",
  "verification",
  "relation",
  "historical",
  "status",
  "record",
  "archive_timestamp",
];

export function presentationClass(record) {
  if (record.kind === "candidate-link" || record.status === "candidate")
    return "candidate";
  if (
    record.kind === "contradiction" ||
    record.kind === "contradicts" ||
    record.status === "contradicted"
  )
    return "contradicted";
  if (
    record.kind === "confirmed-link" &&
    record.status === "confirmed" &&
    record.confirmed === true
  )
    return "confirmed";
  if (
    record.kind === "hypothesis" &&
    record.status === "analyst-confirmed" &&
    record.confirmed === true
  )
    return "confirmed";
  return "other";
}

function clip(value, max = 180) {
  const raw = String(value ?? "");
  return raw.length > max ? `${raw.slice(0, max - 1)}…` : raw;
}
function nodeId(kind, ref) {
  return `${kind}:${ref}`;
}
function edgeId(parts) {
  return `edge:${hash(parts)}`;
}
function parseInput(input) {
  const parsed = InvestigationGraphInput.safeParse(input ?? {});
  if (!parsed.success) throw new Error("INVALID_INPUT");
  return parsed.data;
}
function readJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
function entityInScope(scope, entity, observations) {
  const mine = observations.filter((obs) => obs.entity_id === entity.id);
  if (
    mine.some((obs) =>
      scope.allows(entity.type, entity.value, obs.evidence ?? {}),
    )
  )
    return true;
  return scope.allows(entity.type, entity.value, {});
}
function evidenceDetail(evidence) {
  const parts = [];
  for (const key of SAFE_EVIDENCE) {
    if (evidence?.[key] === undefined || evidence[key] === null) continue;
    parts.push(`${key}=${clip(evidence[key], 80)}`);
  }
  return parts.join(" · ");
}
function loadRows(store) {
  const entities = store.db
    .prepare(
      "SELECT id, type, value, first_seen, last_seen FROM entities ORDER BY id",
    )
    .all();
  const observations = store.db
    .prepare(
      "SELECT id, entity_id, source, timestamp, evidence FROM observations ORDER BY id",
    )
    .all()
    .map((row) => ({ ...row, evidence: readJson(row.evidence, {}) }));
  const edges = store.db
    .prepare(
      "SELECT id, from_id, to_id, relation, observation_id FROM edges ORDER BY id",
    )
    .all();
  const hypotheses = store.db
    .prepare("SELECT * FROM hypotheses ORDER BY id")
    .all();
  const decisions = store.db
    .prepare(
      `SELECT id, subject_kind, subject_id, decision, reason, analyst_id, recorded_at
       FROM review_decisions ORDER BY recorded_at, id`,
    )
    .all();
  return { entities, observations, edges, hypotheses, decisions };
}
function caseSelection(store, caseId) {
  const row = store.db.prepare("SELECT * FROM cases WHERE id=?").get(caseId);
  if (!row) throw new Error("CASE_NOT_FOUND");
  const members = store.db
    .prepare(
      "SELECT kind, ref FROM case_members WHERE case_id=? ORDER BY created_at, id",
    )
    .all(caseId);
  const investigations = members
    .filter((item) => item.kind === "investigation")
    .map((item) => item.ref);
  const targets = members
    .filter((item) => item.kind === "target")
    .map((item) => item.ref);
  const decisionIds = new Set(
    members.filter((item) => item.kind === "decision").map((item) => item.ref),
  );
  const hypotheses = store.db
    .prepare("SELECT id FROM hypotheses WHERE case_id=? ORDER BY id")
    .all(caseId)
    .map((item) => item.id);
  return { row, investigations, targets, decisionIds, hypotheses };
}
function matchesTarget(entity, observations, target) {
  if (entity.value === target) return true;
  if (entity.type === "domain" && entity.value.endsWith(`.${target}`))
    return true;
  if (entity.type === "email" && entity.value.endsWith(`@${target}`))
    return true;
  if (entity.type === "url") {
    try {
      return new URL(entity.value).hostname.replace(/^\[|\]$/g, "") === target;
    } catch {
      return false;
    }
  }
  return observations.some(
    (obs) =>
      obs.entity_id === entity.id &&
      (obs.evidence?.host === target ||
        obs.evidence?.account === target ||
        obs.evidence?.ip === target),
  );
}
function sealEdge(edge) {
  if (edge.kind === "candidate-link" || edge.status === "candidate")
    return {
      ...edge,
      kind: "candidate-link",
      status: "candidate",
      confirmed: false,
      finding: false,
    };
  if (
    edge.kind === "confirmed-link" &&
    edge.status === "confirmed" &&
    edge.confirmed === true
  )
    return { ...edge, finding: false, confirmed: true };
  return { ...edge, confirmed: false, finding: false };
}
function sealNode(node) {
  const confirmed =
    node.kind === "hypothesis" &&
    node.status === "analyst-confirmed" &&
    node.confirmed === true;
  return { ...node, confirmed, finding: false };
}

export function investigationGraph(store, scope, gates = {}, input = {}) {
  if (!scope?.allows) throw new Error("INVALID_INPUT");
  const request = parseInput(input);
  const rows = loadRows(store);
  const byId = new Map(rows.entities.map((entity) => [entity.id, entity]));
  const observationsByEntity = new Map();
  for (const obs of rows.observations) {
    const list = observationsByEntity.get(obs.entity_id) ?? [];
    list.push(obs);
    observationsByEntity.set(obs.entity_id, list);
  }
  const omittedIds = new Set();
  const selected = new Set();
  const keepEntity = (id) => {
    if (selected.has(id)) return true;
    const entity = byId.get(id);
    if (!entity || omittedIds.has(id)) return false;
    if (!entityInScope(scope, entity, observationsByEntity.get(id) ?? [])) {
      omittedIds.add(id);
      return false;
    }
    selected.add(id);
    return true;
  };
  let hypothesisIds = [];
  let decisionIds = null;
  let caseId = null;
  let investigation = null;
  if (request.case_id) {
    const selectedCase = caseSelection(store, request.case_id);
    caseId = selectedCase.row.id;
    hypothesisIds = selectedCase.hypotheses;
    decisionIds = selectedCase.decisionIds;
    for (const target of selectedCase.targets)
      for (const entity of rows.entities)
        if (matchesTarget(entity, rows.observations, target))
          keepEntity(entity.id);
    investigation = selectedCase.investigations.join(", ") || null;
    for (const name of selectedCase.investigations)
      for (const id of investigationCoverage(store, name).entity_ids)
        keepEntity(id);
  } else {
    investigation = request.investigation;
    for (const id of investigationCoverage(store, request.investigation)
      .entity_ids)
      keepEntity(id);
    hypothesisIds = rows.hypotheses
      .filter((row) =>
        readJson(row.entity_ids, []).some((id) => selected.has(id)),
      )
      .map((row) => row.id);
  }
  const hypothesisRows = [];
  for (const id of hypothesisIds) {
    const row = rows.hypotheses.find((item) => item.id === id);
    if (!row) continue;
    const entityIds = readJson(row.entity_ids, []);
    if (
      !entityIds.length ||
      entityIds.some((entityId) => !keepEntity(entityId))
    )
      continue;
    hypothesisRows.push(row);
  }
  const seed = [...selected];
  for (const edge of rows.edges) {
    if (!seed.includes(edge.from_id) && !seed.includes(edge.to_id)) continue;
    if (seed.includes(edge.from_id)) keepEntity(edge.to_id);
    if (seed.includes(edge.to_id)) keepEntity(edge.from_id);
  }
  const resolution = inspectResolution(store);
  for (const link of resolution.links) {
    if (!selected.has(link.left_id) && !selected.has(link.right_id)) continue;
    keepEntity(link.left_id);
    keepEntity(link.right_id);
  }
  const contradictedEntities = new Set();
  const contradictedEvidence = new Set();
  for (const items of resolution.contradictions.values()) {
    for (const item of items) {
      if (!item.entity_ids.every((id) => selected.has(id))) continue;
      for (const id of item.entity_ids) contradictedEntities.add(id);
      for (const value of item.values)
        for (const obsId of value.observation_ids)
          contradictedEvidence.add(obsId);
    }
  }
  const nodes = [];
  const edges = [];
  const addNode = (node) => {
    if (nodes.some((item) => item.id === node.id)) return;
    nodes.push(sealNode(node));
  };
  const addEdge = (edge) => {
    const sealed = sealEdge(edge);
    if (presentationClass(sealed) === "candidate") {
      sealed.kind = "candidate-link";
      sealed.status = "candidate";
      sealed.confirmed = false;
    }
    if (edges.some((item) => item.id === sealed.id)) return;
    edges.push(sealed);
  };
  for (const id of [...selected].sort()) {
    const entity = byId.get(id);
    addNode({
      id: nodeId("entity", id),
      kind: "entity",
      ref: id,
      label: clip(`${entity.type}: ${entity.value}`),
      detail: entity.type,
      status: contradictedEntities.has(id) ? "contradicted" : "observed",
      confirmed: false,
      finding: false,
    });
    for (const obs of (observationsByEntity.get(id) ?? []).slice(0, 40)) {
      addNode({
        id: nodeId("evidence", obs.id),
        kind: "evidence",
        ref: obs.id,
        label: clip(`${obs.source}`),
        detail: clip(evidenceDetail(obs.evidence)),
        status: contradictedEvidence.has(obs.id) ? "contradicted" : "observed",
        confirmed: false,
        finding: false,
      });
      addEdge({
        id: edgeId(["observation", obs.id, id]),
        kind: "observation",
        from: nodeId("evidence", obs.id),
        to: nodeId("entity", id),
        label: "observation",
        status: "observation",
        confirmed: false,
        finding: false,
      });
    }
  }
  for (const edge of rows.edges) {
    if (!selected.has(edge.from_id) || !selected.has(edge.to_id)) continue;
    addEdge({
      id: edgeId(["relation", edge.id]),
      kind: "observation",
      from: nodeId("entity", edge.from_id),
      to: nodeId("entity", edge.to_id),
      label: clip(edge.relation),
      status: "observation",
      confirmed: false,
      finding: false,
    });
  }
  for (const link of resolution.links) {
    if (!selected.has(link.left_id) || !selected.has(link.right_id)) continue;
    const confirmed = link.status === "confirmed";
    addEdge({
      id: edgeId(["link", link.left_id, link.right_id, link.status]),
      kind: confirmed ? "confirmed-link" : "candidate-link",
      from: nodeId("entity", link.left_id),
      to: nodeId("entity", link.right_id),
      label: confirmed
        ? "Resolver-confirmed identifier link. Not an analyst finding."
        : "Candidate link. A shared name or handle is not a confirmed identity.",
      status: confirmed ? "confirmed" : "candidate",
      confirmed,
      finding: false,
    });
  }
  for (const items of resolution.contradictions.values()) {
    for (const item of items) {
      if (!item.entity_ids.every((id) => selected.has(id))) continue;
      if (item.entity_ids.length >= 2) {
        addEdge({
          id: edgeId(["contradiction", item.entity_ids, item.attribute]),
          kind: "contradiction",
          from: nodeId("entity", item.entity_ids[0]),
          to: nodeId("entity", item.entity_ids[1]),
          label: clip(`Contradiction: ${item.attribute}`),
          status: "contradicted",
          confirmed: false,
          finding: false,
        });
      }
    }
  }
  for (const row of hypothesisRows) {
    let assessment = null;
    try {
      assessment = readHypothesisAssessment(store, scope, gates, row.id);
    } catch (error) {
      if (
        ![
          "OUT_OF_SCOPE",
          "ENTITY_NOT_FOUND",
          "EVIDENCE_NOT_FOUND",
          "ASSET_NOT_IN_SCOPE",
        ].includes(error.message)
      )
        throw error;
      omittedIds.add(row.id);
      continue;
    }
    const stored = assessment.hypothesis?.status ?? row.status;
    const confirmed = stored === "analyst-confirmed";
    addNode({
      id: nodeId("hypothesis", row.id),
      kind: "hypothesis",
      ref: row.id,
      label: clip(row.statement),
      detail: clip(
        `${stored} · ${row.claim} · not a finding · not confirmed by this export`,
      ),
      status: stored,
      confirmed,
      finding: false,
    });
    const attach = (items, kind, status, prefix) => {
      for (const hit of items) {
        const target = hit.evidence_id
          ? nodeId("evidence", hit.evidence_id)
          : hit.entity_id
            ? nodeId("entity", hit.entity_id)
            : null;
        if (!target || !nodes.some((node) => node.id === target)) continue;
        addEdge({
          id: edgeId([kind, row.id, target, hit.reason]),
          kind,
          from: nodeId("hypothesis", row.id),
          to: target,
          label: clip(`${prefix}. ${hit.reason}`),
          status,
          confirmed: false,
          finding: false,
        });
      }
    };
    attach(
      assessment.supporting,
      "supports",
      "support",
      "Supports the hypothesis; this is not analyst-confirmed",
    );
    attach(
      assessment.contradicting,
      "contradicts",
      "contradicted",
      "Contradicts the hypothesis",
    );
  }
  for (const decision of rows.decisions) {
    if (decisionIds && !decisionIds.has(decision.id)) {
      const tied =
        decision.subject_kind === "entity"
          ? selected.has(decision.subject_id)
          : rows.observations.some(
              (obs) =>
                obs.id === decision.subject_id && selected.has(obs.entity_id),
            );
      if (!tied) continue;
    }
    const target =
      decision.subject_kind === "entity"
        ? nodeId("entity", decision.subject_id)
        : nodeId("evidence", decision.subject_id);
    if (!nodes.some((node) => node.id === target)) continue;
    addNode({
      id: nodeId("decision", decision.id),
      kind: "decision",
      ref: decision.id,
      label: clip(`${decision.decision} by ${decision.analyst_id}`),
      detail: clip(decision.reason),
      status: decision.decision,
      confirmed: false,
      finding: false,
    });
    addEdge({
      id: edgeId(["decision", decision.id, target]),
      kind: "decision",
      from: nodeId("decision", decision.id),
      to: target,
      label: clip(
        `Analyst ${decision.decision}. This decision does not confirm identity or ownership.`,
      ),
      status: "decision",
      confirmed: false,
      finding: false,
    });
  }
  const capped = capGraph(nodes, edges);
  const omitted = omittedIds.size;
  const graph = {
    nodes: capped.nodes,
    edges: capped.edges,
    counts: countGraph(capped.nodes, capped.edges, omitted),
    limitations: GRAPH_LIMITATIONS,
  };
  const result = {
    format: request.format,
    case_id: caseId,
    investigation,
    read_only: true,
    executes: false,
    network: false,
    collection: false,
    truncated: capped.truncated,
    graph,
    html: request.format === "html" ? graphHTML(graph) : null,
    limitations: GRAPH_LIMITATIONS,
  };
  if (!InvestigationGraphResult.safeParse(result).success)
    throw new Error("GRAPH_EXPORT_INVALID");
  return result;
}

function capGraph(nodes, edges) {
  const rank = { hypothesis: 0, decision: 1, entity: 2, evidence: 3 };
  let truncated = nodes.length > MAX_NODES || edges.length > MAX_EDGES;
  const keptNodes = [...nodes]
    .sort((a, b) => rank[a.kind] - rank[b.kind] || a.id.localeCompare(b.id))
    .slice(0, MAX_NODES)
    .sort((a, b) => a.id.localeCompare(b.id));
  const ids = new Set(keptNodes.map((node) => node.id));
  const keptEdges = edges
    .filter((edge) => ids.has(edge.from) && ids.has(edge.to))
    .sort((a, b) => a.id.localeCompare(b.id))
    .slice(0, MAX_EDGES);
  if (keptNodes.length !== nodes.length || keptEdges.length !== edges.length)
    truncated = true;
  return { nodes: keptNodes, edges: keptEdges, truncated };
}
function countGraph(nodes, edges, omitted) {
  const kind = (name) => nodes.filter((node) => node.kind === name).length;
  return {
    nodes: nodes.length,
    edges: edges.length,
    entities: kind("entity"),
    evidence: kind("evidence"),
    hypotheses: kind("hypothesis"),
    decisions: kind("decision"),
    candidate_links: edges.filter((edge) => edge.kind === "candidate-link")
      .length,
    confirmed_links: edges.filter((edge) => edge.kind === "confirmed-link")
      .length,
    contradictions: edges.filter((edge) =>
      ["contradiction", "contradicts"].includes(edge.kind),
    ).length,
    omitted_out_of_scope: omitted,
  };
}

export function graphHTML(graph) {
  const data = JSON.stringify(graph).replace(
    /[<>&\u2028\u2029]/g,
    (character) =>
      "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"),
  );
  const paint = presentationClass.toString();
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>OSINT POWER · Investigation graph</title>
<style>
:root{color-scheme:dark;--bg:#07111d;--card:#101f30;--line:#223b50;--text:#e6f1fa;--muted:#9cb5c8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
main{max-width:1180px;margin:auto;padding:28px 18px}h1{font-size:28px;margin:4px 0}p,small{color:var(--muted)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}select,input{background:#091826;color:var(--text);border:1px solid #36526a;border-radius:8px;padding:8px;font:inherit}
.layout{display:grid;grid-template-columns:1.3fr .7fr;gap:16px}section{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
svg{width:100%;height:420px;background:#091826;border-radius:10px}svg text{fill:#d5e8f4;font:11px system-ui}
.confirmed{stroke:#3dd68c;fill:#3dd68c}.candidate{stroke:#e6b35a;fill:#e6b35a;stroke-dasharray:5 3}.contradicted{stroke:#f07178;fill:#f07178;stroke-dasharray:2 3}.other{stroke:#7f9eb3;fill:#7f9eb3}
line{stroke-width:1.6;fill:none}circle{stroke-width:2}ul{list-style:none;padding:0;margin:0;max-height:420px;overflow:auto}li{padding:8px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
.swatch{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}.swatch.candidate{background:#e6b35a}.swatch.confirmed{background:#3dd68c}.swatch.contradicted{background:#f07178}
@media(max-width:800px){.layout{grid-template-columns:1fr}}
</style></head><body><main>
<h1>Investigation graph</h1>
<p>Offline view of stored entities, evidence, hypotheses and decisions. A candidate is not confirmed. supported-pending-review is not analyst-confirmed.</p>
<div class="toolbar">
<label>Kind <select id="kind"><option value="all">All</option><option value="entity">Entities</option><option value="evidence">Evidence</option><option value="hypothesis">Hypotheses</option><option value="decision">Decisions</option></select></label>
<label>Status <select id="status"><option value="all">All</option><option value="confirmed">Confirmed</option><option value="candidate">Candidate</option><option value="contradicted">Contradicted</option></select></label>
<label>Search <input id="search" type="search"></label>
</div>
<p><span class="swatch confirmed"></span>Confirmed <span class="swatch candidate"></span>Candidate <span class="swatch contradicted"></span>Contradicted</p>
<div class="layout"><section><svg id="graph" viewBox="0 0 800 420" role="img" aria-label="Investigation graph"></svg></section>
<section><h2>Visible records</h2><ul id="list"></ul></section></div>
<small id="limits"></small>
</main>
<script type="application/json" id="graph-data">${data}</script>
<script>
"use strict";
${paint}
const graph=JSON.parse(document.getElementById("graph-data").textContent);
const el=(id)=>document.getElementById(id);
const nodeById=new Map(graph.nodes.map((node)=>[node.id,node]));
function matchesQuery(record){const query=el("search").value.toLowerCase();return !query||(record.label+" "+(record.detail||"")).toLowerCase().includes(query);}
function render(){
  const svg=el("graph");while(svg.firstChild)svg.removeChild(svg.firstChild);
  const ns="http://www.w3.org/2000/svg";
  const kind=el("kind").value,status=el("status").value;
  const edges=graph.edges.filter((edge)=>{const paintClass=presentationClass(edge);if(status!=="all"&&paintClass!==status)return false;const from=nodeById.get(edge.from),to=nodeById.get(edge.to);if(!from||!to)return false;if(kind!=="all"&&from.kind!==kind&&to.kind!==kind&&edge.kind!==kind)return false;return matchesQuery(edge)||matchesQuery(from)||matchesQuery(to);});
  const visible=new Set(edges.flatMap((edge)=>[edge.from,edge.to]));
  for(const node of graph.nodes){const paintClass=presentationClass(node);if(status!=="all"&&paintClass!==status&&!visible.has(node.id))continue;if(kind!=="all"&&node.kind!==kind&&!visible.has(node.id))continue;if(!matchesQuery(node)&&!visible.has(node.id))continue;visible.add(node.id);}
  const nodes=graph.nodes.filter((node)=>visible.has(node.id));
  const pos=new Map(nodes.map((node,index)=>[node.id,{x:400+300*Math.cos((index*2*Math.PI)/Math.max(1,nodes.length)),y:210+150*Math.sin((index*2*Math.PI)/Math.max(1,nodes.length))}]));
  for(const edge of edges){const a=pos.get(edge.from),b=pos.get(edge.to);if(!a||!b)continue;const line=document.createElementNS(ns,"line");line.setAttribute("x1",a.x);line.setAttribute("y1",a.y);line.setAttribute("x2",b.x);line.setAttribute("y2",b.y);const paintClass=presentationClass(edge);line.setAttribute("class",paintClass);line.dataset.kind=edge.kind;line.dataset.status=paintClass;line.dataset.confirmed=paintClass==="confirmed"?"true":"false";const title=document.createElementNS(ns,"title");title.textContent=edge.label;line.append(title);svg.append(line);}
  for(const node of nodes){const p=pos.get(node.id);const paintClass=presentationClass(node);const circle=document.createElementNS(ns,"circle");circle.setAttribute("cx",p.x);circle.setAttribute("cy",p.y);circle.setAttribute("r",node.kind==="entity"?7:5);circle.setAttribute("class",paintClass);circle.dataset.kind=node.kind;circle.dataset.status=paintClass;const title=document.createElementNS(ns,"title");title.textContent=node.label;circle.append(title);const label=document.createElementNS(ns,"text");label.setAttribute("x",p.x+8);label.setAttribute("y",p.y-8);label.textContent=node.label.length>42?node.label.slice(0,39)+"…":node.label;svg.append(circle,label);}
  const list=el("list");list.replaceChildren();
  for(const node of nodes){const item=document.createElement("li");const strong=document.createElement("strong");strong.textContent=node.kind+" · "+node.label;const small=document.createElement("small");small.textContent=" "+presentationClass(node)+" · "+node.detail;item.append(strong,small);list.append(item);}
  for(const edge of edges){const item=document.createElement("li");item.textContent=presentationClass(edge)+" · "+edge.kind+" · "+edge.label;list.append(item);}
}
for(const id of ["kind","status","search"])el(id).addEventListener("input",render);
el("kind").addEventListener("change",render);el("status").addEventListener("change",render);
el("limits").textContent=graph.limitations.join(" ");
render();
</script></body></html>`;
}
