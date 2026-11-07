import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import {
  Config,
  ImportInput,
  Observation,
  RunInput,
  WorkflowInput,
} from "./schema.js";
import { Scope } from "./scope.js";
import { Store, hash } from "./store.js";
import { parse } from "./parsers.js";
import { collect, ADAPTERS } from "./adapters.js";
import { retry, runProcess } from "./transport.js";
import { z } from "zod";
import { isIP } from "node:net";
import { runWorkflow, WORKFLOWS } from "./workflows.js";
import { ProviderGate } from "./providers.js";
import { Jobs } from "./jobs.js";
import { capture, recordSource, mirrorRun } from "./state.js";

export class Engine {
  constructor(config, store, dependencies = {}) {
    this.config = Config.parse(config);
    this.scope = new Scope(this.config);
    this.store = store;
    const { people, ...legacyScope } = this.config.scope;
    this.store.bindScope(people.length ? this.config.scope : legacyScope);
    this.dependencies = dependencies;
    this.tail = Promise.resolve();
    this.providers = new ProviderGate(store, this.config.limits, dependencies);
    this.jobs = new Jobs(this);
  }
  queue(operation) {
    const next = this.tail.then(operation);
    this.tail = next.catch(() => {});
    return next;
  }
  import(input) {
    const { adapter, data } = ImportInput.parse(input);
    if (Buffer.byteLength(data) > this.config.limits.maxBytes)
      throw new Error("IMPORT_TOO_LARGE");
    const id = this.store.start(`import:${adapter}`, hash(data));
    try {
      const result = parse(
        adapter,
        data,
        this.scope,
        this.config.limits.maxRecords,
      );
      const { items, ...stats } = result;
      const summary = {
        run_id: id,
        status: stats.invalid || stats.truncated ? "partial" : "completed",
        ...this.store.ingest(items, {
          runId: id,
          collector: "import:" + adapter,
          target: "workspace_import",
          input_hash: hash(data),
        }),
        ...stats,
        input_hash: hash(data),
        next_actions: this.next(),
      };
      this.store.finish(id, summary.status, summary);
      recordSource(
        this.store,
        id,
        "import:" + adapter,
        "workspace_import",
        summary,
      );
      return summary;
    } catch {
      this.store.finish(id, "failed", { code: "IMPORT_PARSE_ERROR" });
      recordSource(this.store, id, "import:" + adapter, "workspace_import", {
        status: "failed",
        code: "IMPORT_PARSE_ERROR",
      });
      return {
        run_id: id,
        status: "failed",
        code: "IMPORT_PARSE_ERROR",
        next_actions: this.next(),
      };
    }
  }
  run(input, context = {}) {
    return this.queue(() => this.execute(input, context));
  }
  async execute(input, context = {}) {
    context.signal?.throwIfAborted();
    const { adapter, target: raw } = RunInput.parse(input);
    const relatedHost =
      ["rdap", "routing"].includes(adapter) && isIP(raw)
        ? this.store.ipHost(raw, this.scope)
        : null;
    const target = relatedHost ? raw : this.scope.target(adapter, raw);
    if (!this.config.network) throw new Error("NETWORK_DISABLED");
    if (!this.config.enabledAdapters.includes(adapter))
      throw new Error("ADAPTER_DISABLED");
    if (ADAPTERS[adapter].mode === "active" && !this.config.active)
      throw new Error("ACTIVE_DISABLED");
    const runId = this.store.start(adapter, target);
    context.onStarted?.(runId);
    const finish = (summary) => {
      this.store.finish(runId, summary.status, summary);
      recordSource(this.store, runId, adapter, target, summary);
      if (!context.isOwner || context.isOwner())
        mirrorRun(this.store, runId, context.parentRunId);
      return summary;
    };
    const cacheKey = hash(["v0.3", adapter, target, this.config]);
    const cached = this.store.cached(cacheKey);
    if (cached?.items) {
      const result = {
        ...cached.summary,
        run_id: runId,
        cached: true,
        inserted: 0,
        repeated: cached.items.length,
        next_actions: this.next(),
      };
      capture(this.store, runId, cached.items, {
        collector: adapter,
        target,
        cached: true,
        collected_at: cached.summary.collected_at,
        origin_run_id: cached.summary.run_id,
        input_hash: cached.summary.input_hash,
      });
      return finish(result);
    }
    try {
      let attempts = 0;
      const raw = await retry(
        async () => {
          attempts++;
          const signal = context.signal;
          const dependencies = {
            ...this.dependencies,
            signal,
            fetcher: (url, options) =>
              this.providers.fetch(
                url,
                options,
                this.dependencies.fetcher ?? fetch,
                signal,
              ),
            runner: (command, args, limits, stdin = "") =>
              this.providers.process(
                adapter,
                this.dependencies.runner ?? runProcess,
                [command, args, limits, stdin],
                signal,
              ),
          };
          if (adapter === "mx")
            await this.providers.before("dns:system", signal);
          try {
            const value = await collect(
              adapter,
              target,
              this.config,
              dependencies,
            );
            if (adapter === "mx") this.providers.success("dns:system");
            return value;
          } catch (error) {
            if (adapter === "mx" && !signal?.aborted)
              this.providers.failure(
                "dns:system",
                error.code ?? "DNS_LOOKUP_FAILED",
              );
            throw error;
          }
        },
        this.config.limits,
        undefined,
        context.signal,
      );
      let parsed;
      if (adapter === "hibp") {
        const data = z
          .array(
            z.object({
              Name: z.string().min(1).max(200),
              BreachDate: z
                .string()
                .regex(/^\d{4}-\d{2}-\d{2}$/)
                .optional(),
            }),
          )
          .parse(JSON.parse(raw));
        parsed = {
          items: data.slice(0, this.config.limits.maxRecords).map((r) =>
            Observation.parse({
              type: "breach",
              value: `${target}:${r.Name}`,
              source: "hibp",
              confidence: 0.85,
              timestamp: new Date().toISOString(),
              evidence: {
                account: target,
                name: String(r.Name).slice(0, 200),
                ...(r.BreachDate ? { date: r.BreachDate } : {}),
                verification: "breach_association_only",
                reason: "Breach association; no passwords retrieved",
              },
            }),
          ),
          skipped: 0,
          invalid: 0,
          truncated: data.length > this.config.limits.maxRecords,
        };
      } else
        parsed = parse(
          adapter,
          raw,
          this.scope,
          this.config.limits.maxRecords,
          { target, relatedHost },
        );
      const { items, ...stats } = parsed;
      const collected_at = new Date().toISOString();
      context.signal?.throwIfAborted();
      const summary = {
        run_id: runId,
        adapter,
        target,
        status: stats.invalid || stats.truncated ? "partial" : "completed",
        cached: false,
        attempts,
        collected_at,
        input_hash: hash(raw),
        ...this.store.ingest(items, {
          runId,
          collector: adapter,
          target,
          collected_at,
          input_hash: hash(raw),
        }),
        ...stats,
        next_actions: this.next(),
      };
      finish(summary);
      if (summary.status === "completed")
        this.store.cache(
          cacheKey,
          { summary, items },
          this.config.limits.cacheTtlSeconds,
        );
      return summary;
    } catch (error) {
      const code = /^[A-Z_0-9]+$/.test(error.message)
        ? error.message
        : "ADAPTER_ERROR";
      const summary = {
        run_id: runId,
        adapter,
        status:
          code === "CANCELLED"
            ? "cancelled"
            : code.startsWith("PROVIDER_")
              ? "deferred"
              : "failed",
        code,
        retry_after_ms: error.retryAfterMs ?? 0,
        next_actions: this.next(),
      };
      return finish(summary);
    }
  }
  async pipeline(target) {
    const results = [];
    for (const adapter of ["crtsh", "subfinder", "amass"].filter((a) =>
      this.config.enabledAdapters.includes(a),
    )) {
      try {
        results.push(await this.run({ adapter, target }));
      } catch (error) {
        results.push({ adapter, status: "failed", code: error.message });
      }
    }
    return {
      status:
        results.length &&
        results.every((r) => ["completed", "cached"].includes(r.status))
          ? "completed"
          : "partial",
      results,
      next_actions: this.next(),
    };
  }
  next() {
    const domains = this.store.query({ type: "domain", limit: 1 }).total;
    const canResolve =
      this.config.network &&
      this.config.active &&
      this.config.enabledAdapters.includes("dnsx");
    return [
      {
        rank: 1,
        action: domains
          ? "Review source evidence for discovered domains"
          : "Collect a configured domain with passive sources",
        reason:
          "Confirm provenance and avoid treating source coverage as ownership",
      },
      {
        rank: 2,
        action: "Compare an independent source or import a sanitized export",
        reason:
          "Corroborate findings; aggregate tools may share upstream sources",
      },
      {
        rank: 3,
        action: canResolve
          ? "Resolve one in-scope host with dnsx"
          : "Review unresolved data and configured scope",
        reason: canResolve
          ? "Prioritize a concrete host without broadening to neighboring assets"
          : "Reduce ambiguity before enabling another collection step",
      },
    ];
  }
  capabilities() {
    return {
      version: "0.3.0",
      durable_jobs: true,
      workflows: WORKFLOWS,
      network: this.config.network,
      active: this.config.active,
      adapters: Object.entries(ADAPTERS).map(([name, data]) => ({
        name,
        ...data,
        enabled: this.config.enabledAdapters.includes(name),
      })),
      imports: ImportInput.shape.adapter.options,
      scope: this.config.scope,
      limits: this.config.limits,
      collectors: this.config.collectors,
    };
  }
  async workflow(input, signal) {
    const request = WorkflowInput.parse(input);
    if (!request.execute) return runWorkflow(this, request);
    const job = this.jobs.create(request);
    return this.resume({ id: job.id }, signal);
  }
  resume(input, signal) {
    return this.jobs.resume(
      input,
      (request, job) => runWorkflow(this, request, job),
      signal,
    );
  }
}
export function openEngine(configPath, databasePath, dependencies) {
  const absolute = resolve(configPath);
  const config = Config.parse(JSON.parse(readFileSync(absolute, "utf8")));
  const store = new Store(
    databasePath ?? resolve(dirname(absolute), ".osint-power", "state.sqlite"),
  );
  try {
    return new Engine(config, store, dependencies);
  } catch (error) {
    store.close();
    throw error;
  }
}
