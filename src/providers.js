import { setTimeout as sleep } from "node:timers/promises";
import { OperationError } from "./transport.js";

export function retryAfter(value, now = Date.now()) {
  if (!value) return 0;
  const delay = /^\d+$/.test(value)
    ? Number(value) * 1000
    : Date.parse(value) - now;
  return Number.isFinite(delay) ? Math.max(0, delay) : 0;
}
export class ProviderGate {
  constructor(store, limits, dependencies = {}) {
    this.db = store.db;
    this.limits = limits;
    this.now = dependencies.now ?? Date.now;
    this.wait =
      dependencies.wait ?? ((ms, signal) => sleep(ms, undefined, { signal }));
  }
  policy(provider) {
    return {
      ...this.limits.providers.defaults,
      ...this.limits.providers.overrides[provider],
    };
  }
  reserve(provider, signal) {
    signal?.throwIfAborted();
    const now = this.now(),
      policy = this.policy(provider);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare("INSERT OR IGNORE INTO provider_state(provider) VALUES(?)")
        .run(provider);
      const row = this.db
        .prepare("SELECT * FROM provider_state WHERE provider=?")
        .get(provider);
      const reset = now - row.window_start >= policy.windowMs;
      const used = reset ? 0 : row.used;
      const windowStart = reset ? now : row.window_start;
      if (row.cooldown_until > now)
        throw new OperationError(
          "PROVIDER_COOLDOWN",
          false,
          row.cooldown_until - now,
        );
      if (used >= policy.maxRequests)
        throw new OperationError(
          "PROVIDER_QUOTA_EXHAUSTED",
          false,
          windowStart + policy.windowMs - now,
        );
      const interval = Math.max(
        this.limits.minIntervalMs,
        policy.minIntervalMs,
        provider === "haveibeenpwned.com" ? 6000 : 0,
      );
      const wait = Math.max(0, row.next_at - now);
      if (wait) {
        this.db.exec("COMMIT");
        return wait;
      }
      this.db
        .prepare(
          "UPDATE provider_state SET next_at=?,window_start=?,used=?,requests=requests+1 WHERE provider=?",
        )
        .run(now + interval, windowStart, used + 1, provider);
      this.db.exec("COMMIT");
      return 0;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  async before(provider, signal) {
    const deadline = this.now() + this.limits.providers.maxWaitMs;
    while (true) {
      const delay = this.reserve(provider, signal);
      if (!delay) return;
      if (this.now() + delay > deadline)
        throw new OperationError("PROVIDER_WAIT_REQUIRED", false, delay);
      await this.wait(delay, signal);
    }
  }
  success(provider) {
    this.db
      .prepare(
        "UPDATE provider_state SET failures=0,last_code=NULL,last_success=? WHERE provider=?",
      )
      .run(new Date(this.now()).toISOString(), provider);
  }
  failure(provider, code, delay = 0) {
    const now = this.now(),
      policy = this.policy(provider);
    const row = this.db
      .prepare("SELECT failures FROM provider_state WHERE provider=?")
      .get(provider);
    if (!row) return;
    const failures = row.failures + 1;
    const cooldown =
      /HTTP_(429|401|403)/.test(code) || failures >= policy.failureThreshold
        ? Math.max(delay, policy.cooldownMs)
        : delay;
    this.db
      .prepare(
        "UPDATE provider_state SET failures=?,last_code=?,last_failure=?,cooldown_until=MAX(cooldown_until,?) WHERE provider=?",
      )
      .run(
        failures,
        code,
        new Date(now).toISOString(),
        now + cooldown,
        provider,
      );
  }
  async fetch(url, options, fetcher, signal) {
    const provider = new URL(url).hostname;
    await this.before(provider, signal);
    try {
      const response = await fetcher(url, {
        ...options,
        signal: signal
          ? AbortSignal.any([signal, options.signal].filter(Boolean))
          : options.signal,
      });
      if (response.ok || response.status === 404) {
        this.success(provider);
        const delay = retryAfter(
          response.headers.get("retry-after"),
          this.now(),
        );
        if (delay)
          this.db
            .prepare(
              "UPDATE provider_state SET next_at=MAX(next_at,?) WHERE provider=?",
            )
            .run(this.now() + delay, provider);
      } else
        this.failure(
          provider,
          `HTTP_${response.status}`,
          retryAfter(response.headers.get("retry-after"), this.now()),
        );
      return response;
    } catch (error) {
      if (signal?.aborted) throw signal.reason;
      this.failure(provider, "NETWORK_ERROR");
      throw error;
    }
  }
  async process(adapter, runner, args, signal) {
    const key = "binary:" + adapter;
    await this.before(key, signal);
    try {
      const result = await runner(...args, { signal });
      this.success(key);
      return result;
    } catch (error) {
      if (!signal?.aborted) this.failure(key, error.code ?? "TOOL_FAILED");
      throw error;
    }
  }
  health() {
    const now = this.now();
    return {
      providers: this.db
        .prepare("SELECT * FROM provider_state ORDER BY provider")
        .all()
        .map((row) => {
          const p = this.policy(row.provider);
          const inWindow = now - row.window_start < p.windowMs;
          const used = inWindow ? row.used : 0;
          return {
            ...row,
            used,
            remaining: Math.max(0, p.maxRequests - used),
            policy: p,
            status:
              row.cooldown_until > now
                ? "cooldown"
                : used >= p.maxRequests
                  ? "quota_exhausted"
                  : row.last_code
                    ? "degraded"
                    : "available",
            retry_at: new Date(
              Math.max(
                row.cooldown_until,
                row.next_at,
                used >= p.maxRequests ? row.window_start + p.windowMs : 0,
              ),
            ).toISOString(),
          };
        }),
      coordination:
        "Shared by processes using this SQLite workspace. Native binary quotas count process invocations, not their internal requests.",
    };
  }
}
