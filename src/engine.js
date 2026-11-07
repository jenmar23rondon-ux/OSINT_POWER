import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { Config, ImportInput, Observation, RunInput } from "./schema.js";
import { Scope } from "./scope.js";
import { Store, hash } from "./store.js";
import { parse } from "./parsers.js";
import { collect, ADAPTERS } from "./adapters.js";
import { retry } from "./transport.js";
import { z } from "zod";

export class Engine {
  constructor(config, store, dependencies = {}) {
    this.config = Config.parse(config);
    this.scope = new Scope(this.config);
    this.store = store;
    this.store.bindScope(this.config.scope);
    this.dependencies = dependencies;
    this.tail = Promise.resolve();
    this.lastCall = new Map();
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
        ...this.store.ingest(items),
        ...stats,
        input_hash: hash(data),
        next_actions: this.next(),
      };
      this.store.finish(id, summary.status, summary);
      return summary;
    } catch {
      this.store.finish(id, "failed", { code: "IMPORT_PARSE_ERROR" });
      return {
        run_id: id,
        status: "failed",
        code: "IMPORT_PARSE_ERROR",
        next_actions: this.next(),
      };
    }
  }
  run(input) {
    return this.queue(() => this.execute(input));
  }
  async execute(input) {
    const { adapter, target: raw } = RunInput.parse(input);
    const target = this.scope.target(adapter, raw);
    if (!this.config.network) throw new Error("NETWORK_DISABLED");
    if (!this.config.enabledAdapters.includes(adapter))
      throw new Error("ADAPTER_DISABLED");
    if (ADAPTERS[adapter].mode === "active" && !this.config.active)
      throw new Error("ACTIVE_DISABLED");
    const runId = this.store.start(adapter, target);
    const cacheKey = hash([adapter, target, this.config]);
    const cached = this.store.cached(cacheKey);
    if (cached) {
      const result = {
        ...cached,
        run_id: runId,
        cached: true,
        next_actions: this.next(),
      };
      this.store.finish(runId, "cached", result);
      return result;
    }
    try {
      let attempts = 0;
      const raw = await retry(async () => {
        attempts++;
        const interval =
          adapter === "hibp"
            ? Math.max(this.config.limits.minIntervalMs, 6000)
            : this.config.limits.minIntervalMs;
        const remaining =
          interval - (Date.now() - (this.lastCall.get(adapter) ?? 0));
        if (remaining > 0) await sleep(remaining);
        this.lastCall.set(adapter, Date.now());
        return collect(adapter, target, this.config, this.dependencies);
      }, this.config.limits);
      let parsed;
      if (adapter === "hibp") {
        const data = z
          .array(z.object({ Name: z.string().min(1).max(200) }))
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
                reason: "Breach association; no passwords retrieved",
              },
            }),
          ),
          skipped: 0,
          invalid: 0,
          truncated: data.length > this.config.limits.maxRecords,
        };
      } else
        parsed = parse(adapter, raw, this.scope, this.config.limits.maxRecords);
      const { items, ...stats } = parsed;
      const summary = {
        run_id: runId,
        adapter,
        target,
        status: stats.invalid || stats.truncated ? "partial" : "completed",
        cached: false,
        attempts,
        ...this.store.ingest(items),
        ...stats,
        next_actions: this.next(),
      };
      this.store.finish(runId, summary.status, summary);
      if (summary.status === "completed")
        this.store.cache(
          cacheKey,
          { ...summary, inserted: 0, repeated: summary.observations },
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
        status: "failed",
        code,
        next_actions: this.next(),
      };
      this.store.finish(runId, "failed", summary);
      return summary;
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
      version: "0.1.0",
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
    };
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
