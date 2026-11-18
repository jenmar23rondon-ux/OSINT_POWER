import { z } from "zod";
import { locateBinary } from "./doctor.js";
import { runProcess } from "./transport.js";
import { domain } from "./scope.js";

export const ProbeHttpInput = z
  .object({
    target: z.string().min(1).max(253),
    probe_http: z.literal(true),
    authorized: z.literal(true),
    maxTargets: z.number().int().min(1).max(10).default(3),
  })
  .strict();

const PROJECT_DISCOVERY_FLAGS = ["-json", "-tech-detect", "-tls-grab", "-duc"];

export function probeHosts(engine, target, maxTargets) {
  const apex = domain(target);
  if (!engine.scope.host(apex)) throw new Error("OUT_OF_SCOPE");
  const discovered = engine.store
    .domainEntities("domain", apex, 100)
    .map((row) => row.value)
    .filter((value) => {
      try {
        return engine.scope.host(value);
      } catch {
        return false;
      }
    });
  return [...new Set([apex, ...discovered])].slice(0, maxTargets);
}

export async function assertProjectDiscoveryHttpx(engine) {
  const path = (engine.dependencies.locateBinary ?? locateBinary)("httpx");
  if (!path) throw new Error("TOOL_NOT_INSTALLED");
  const runner = engine.dependencies.diagnosticRunner ?? runProcess;
  const limits = { timeoutMs: 3000, maxBytes: 65536 };
  let version = "";
  let help = "";
  try {
    version = await runner(path, ["-version", "-duc"], limits, "", {
      captureStderr: true,
    });
    help = await runner(path, ["-h"], limits, "", { captureStderr: true });
  } catch (error) {
    if (error.code === "TOOL_NOT_INSTALLED") throw error;
    throw new Error("HTTPX_NOT_PROJECTDISCOVERY");
  }
  const blob = `${version}\n${help}`;
  const python =
    /python httpx|encode\/httpx|usage: httpx/i.test(blob) &&
    !blob.includes("-tech-detect");
  if (python || PROJECT_DISCOVERY_FLAGS.some((flag) => !help.includes(flag)))
    throw new Error("HTTPX_NOT_PROJECTDISCOVERY");
  return path;
}

function gap(result, target) {
  const code = result.code ?? "ADAPTER_ERROR";
  const reason =
    code === "HTTP_429" || code.startsWith("PROVIDER_")
      ? "rate_limited"
      : code === "TOOL_NOT_INSTALLED"
        ? "failed"
        : "error";
  return { source: "httpx", target: result.target ?? target, site: "", reason };
}

export async function probeDiscoveredHosts(engine, input, signal) {
  const request = ProbeHttpInput.parse(input);
  if (!engine.config.network) throw new Error("NETWORK_DISABLED");
  if (!engine.config.active) throw new Error("ACTIVE_DISABLED");
  if (!engine.config.enabledAdapters.includes("httpx"))
    throw new Error("ADAPTER_DISABLED");
  await assertProjectDiscoveryHttpx(engine);
  const hosts = probeHosts(engine, request.target, request.maxTargets);
  const results = [];
  for (const host of hosts) {
    signal?.throwIfAborted();
    results.push(
      await engine.run({ adapter: "httpx", target: host }, { signal }),
    );
  }
  const coverage_gaps = results
    .filter((result) => ["failed", "deferred"].includes(result.status))
    .map((result) => gap(result, request.target));
  return {
    status: coverage_gaps.length ? "partial" : "completed",
    target: domain(request.target),
    probe_http: true,
    authorized: true,
    hosts,
    results,
    coverage_gaps,
    next_actions: engine.next(),
  };
}
