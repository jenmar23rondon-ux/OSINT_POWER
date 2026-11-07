import { randomUUID } from "node:crypto";
import { hash } from "./store.js";
import {
  WorkflowInput,
  JobInput,
  ResumeInput,
  JobListInput,
  WORKFLOW_ALIASES,
} from "./schema.js";
import { domain } from "./scope.js";
import { OperationError } from "./transport.js";
import { mirrorRun } from "./state.js";

const LEASE_MS = 15000;
const planHash = (config) =>
  hash([1, config.scope, config.collectors, config.limits.ports]);
export class Jobs {
  constructor(engine) {
    this.engine = engine;
    this.store = engine.store;
    this.db = this.store.db;
    this.owner = randomUUID();
  }
  create(input) {
    const request = WorkflowInput.parse({ ...input, execute: true });
    request.workflow = WORKFLOW_ALIASES[request.workflow] ?? request.workflow;
    // Validate scope before creating a queued job; planning never sends traffic.
    const scope = this.engine.scope;
    if (request.workflow === "people" || request.workflow === "personas") {
      if (!scope.person(request.target)) throw new Error("PERSON_OUT_OF_SCOPE");
    } else if (!scope.host(request.target)) throw new Error("OUT_OF_SCOPE");
    request.target =
      request.workflow === "people"
        ? scope.person(request.target).name
        : domain(request.target);
    const id = this.store.start("workflow:" + request.workflow, request.target);
    this.store.finish(id, "queued", { workflow: request.workflow });
    const now = new Date().toISOString();
    this.db
      .prepare(
        "INSERT INTO jobs(id,request,plan_hash,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
      )
      .run(
        id,
        JSON.stringify(request),
        planHash(this.engine.config),
        "queued",
        now,
        now,
      );
    return { id, status: "queued", request };
  }
  inspect(input) {
    const { id } = JobInput.parse(input);
    const row = this.db.prepare("SELECT * FROM jobs WHERE id=?").get(id);
    if (!row) throw new Error("JOB_NOT_FOUND");
    const steps = this.db
      .prepare(
        "SELECT * FROM job_steps WHERE job_id=? ORDER BY rowid LIMIT 100",
      )
      .all(id)
      .map((r) => ({
        ...r,
        input: JSON.parse(r.input),
        result: r.result ? JSON.parse(r.result) : null,
      }));
    return {
      id,
      status: row.status,
      request: JSON.parse(row.request),
      calls: row.calls,
      cancel_requested: Boolean(row.cancel_requested),
      lease_active: row.lease_until > Date.now(),
      lease_expires_at: row.lease_until
        ? new Date(row.lease_until).toISOString()
        : null,
      created_at: row.created_at,
      updated_at: row.updated_at,
      result: row.result ? JSON.parse(row.result) : null,
      steps,
      total_steps: this.db
        .prepare("SELECT COUNT(*) AS n FROM job_steps WHERE job_id=?")
        .get(id).n,
    };
  }
  list(input = {}) {
    const { limit, offset } = JobListInput.parse(input);
    const rows = this.db
      .prepare(
        "SELECT id,status,calls,cancel_requested,lease_until,created_at,updated_at FROM jobs ORDER BY created_at DESC,id LIMIT ? OFFSET ?",
      )
      .all(limit + 1, offset);
    const items = rows.slice(0, limit).map((r) => ({
      ...r,
      cancel_requested: Boolean(r.cancel_requested),
      lease_active: r.lease_until > Date.now(),
    }));
    return {
      items,
      returned: items.length,
      total: this.db.prepare("SELECT COUNT(*) AS n FROM jobs").get().n,
      next_offset: rows.length > limit ? offset + limit : null,
    };
  }
  cancel(input) {
    const { id } = JobInput.parse(input);
    const job = this.inspect({ id });
    if (["completed", "cancelled"].includes(job.status))
      return { id, status: job.status };
    if (job.lease_active) {
      this.db
        .prepare("UPDATE jobs SET cancel_requested=1,updated_at=? WHERE id=?")
        .run(new Date().toISOString(), id);
      return { id, status: "cancellation_requested" };
    }
    this.db
      .prepare(
        "UPDATE jobs SET cancel_requested=1,status='cancelled',owner=NULL,lease_until=0,updated_at=? WHERE id=?",
      )
      .run(new Date().toISOString(), id);
    this.store.finish(id, "cancelled", { code: "CANCELLED" });
    return { id, status: "cancelled" };
  }
  async resume(input, execute, externalSignal) {
    const { id, maxCalls } = ResumeInput.parse(input);
    const owner = this.owner + ":" + randomUUID();
    const now = Date.now();
    this.db.exec("BEGIN IMMEDIATE");
    let row;
    try {
      row = this.db.prepare("SELECT * FROM jobs WHERE id=?").get(id);
      if (!row) throw new Error("JOB_NOT_FOUND");
      if (row.status === "completed") {
        this.db.exec("COMMIT");
        return row.result ? JSON.parse(row.result) : this.inspect({ id });
      }
      if (row.cancel_requested || row.status === "cancelled")
        throw new Error("JOB_CANCELLED");
      if (row.plan_hash !== planHash(this.engine.config))
        throw new Error("JOB_CONFIGURATION_CHANGED");
      if (row.owner && row.lease_until > now) throw new Error("JOB_BUSY");
      this.db
        .prepare(
          "UPDATE jobs SET owner=?,lease_until=?,status='running',updated_at=? WHERE id=?",
        )
        .run(owner, now + LEASE_MS, new Date(now).toISOString(), id);
      this.db
        .prepare(
          "UPDATE job_steps SET status='interrupted' WHERE job_id=? AND status='running'",
        )
        .run(id);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    const controller = new AbortController();
    const abort = () =>
      controller.abort(
        externalSignal?.reason ?? new OperationError("CANCELLED"),
      );
    externalSignal?.addEventListener("abort", abort, { once: true });
    if (externalSignal?.aborted) abort();
    const heartbeat = setInterval(() => {
      try {
        const state = this.db
          .prepare("SELECT owner,cancel_requested FROM jobs WHERE id=?")
          .get(id);
        if (state?.owner !== owner) {
          controller.abort(new OperationError("JOB_LEASE_LOST"));
          return;
        }
        if (state.cancel_requested) {
          controller.abort(new OperationError("CANCELLED"));
          return;
        }
        this.db
          .prepare("UPDATE jobs SET lease_until=? WHERE id=? AND owner=?")
          .run(Date.now() + LEASE_MS, id, owner);
      } catch {
        controller.abort(new OperationError("JOB_LEASE_LOST"));
      }
    }, 250);
    const check = () => {
      controller.signal.throwIfAborted();
      const state = this.db
        .prepare("SELECT owner,cancel_requested FROM jobs WHERE id=?")
        .get(id);
      if (state?.owner !== owner) throw new OperationError("JOB_LEASE_LOST");
      if (state.cancel_requested) throw new OperationError("CANCELLED");
    };
    const touch = () => {
      check();
      this.db
        .prepare("UPDATE jobs SET lease_until=? WHERE id=? AND owner=?")
        .run(Date.now() + LEASE_MS, id, owner);
    };
    const key = (stage, kind, target = "") => hash([stage, kind, target]);
    const get = (stage, kind, target = "") =>
      this.db
        .prepare("SELECT * FROM job_steps WHERE job_id=? AND step_key=?")
        .get(id, key(stage, kind, target));
    const step = (stage, kind, target, result, status) => {
      check();
      this.db
        .prepare(
          `INSERT INTO job_steps(job_id,step_key,stage,kind,input,status,result,updated_at) VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(job_id,step_key) DO UPDATE SET status=excluded.status,result=excluded.result,updated_at=excluded.updated_at`,
        )
        .run(
          id,
          key(stage, kind, target),
          stage,
          kind,
          JSON.stringify({ target }),
          status,
          JSON.stringify(result),
          new Date().toISOString(),
        );
    };
    const context = {
      id,
      signal: controller.signal,
      maxCalls: maxCalls ?? JSON.parse(row.request).maxCalls,
      check,
      isOwner: () =>
        this.db.prepare("SELECT owner FROM jobs WHERE id=?").get(id)?.owner ===
        owner,
      freeze: (name, compute) => {
        check();
        const old = this.db
          .prepare("SELECT value FROM job_batches WHERE job_id=? AND name=?")
          .get(id, name);
        if (old) return JSON.parse(old.value);
        const value = compute();
        if (value.length)
          this.db
            .prepare("INSERT OR IGNORE INTO job_batches VALUES(?,?,?)")
            .run(id, name, JSON.stringify(value));
        return value;
      },
      local: (stage, _observations, operation) => {
        check();
        const old = get(stage, "local");
        if (old?.status === "completed")
          return { ...JSON.parse(old.result), checkpoint_reused: true };
        const result = operation();
        step(stage, "local", "", result, "completed");
        return result;
      },
      before: (stage, adapter, target) => {
        touch();
        const old = get(stage, adapter, target);
        if (old?.status === "completed")
          return { ...JSON.parse(old.result), checkpoint_reused: true };
        if (old?.child_run_id) {
          const child = this.db
            .prepare("SELECT status,summary FROM runs WHERE id=?")
            .get(old.child_run_id);
          if (["completed", "cached"].includes(child?.status)) {
            mirrorRun(this.store, old.child_run_id, id);
            const result = JSON.parse(child.summary);
            step(stage, adapter, target, result, "completed");
            return { ...result, checkpoint_reused: true };
          }
        }
        if (old?.attempts >= 3)
          return {
            stage,
            adapter,
            target,
            status: "attempt_limit",
            code: "STEP_ATTEMPT_LIMIT",
          };
        if (
          this.db.prepare("SELECT calls FROM jobs WHERE id=?").get(id).calls >=
          100
        )
          return {
            stage,
            adapter,
            target,
            status: "budget_exhausted",
            code: "JOB_LIFETIME_BUDGET",
          };
        return null;
      },
      start: (stage, adapter, target) => {
        check();
        step(
          stage,
          adapter,
          target,
          { stage, adapter, target, status: "running" },
          "running",
        );
        this.db
          .prepare(
            "UPDATE job_steps SET attempts=attempts+1 WHERE job_id=? AND step_key=?",
          )
          .run(id, key(stage, adapter, target));
        this.db.prepare("UPDATE jobs SET calls=calls+1 WHERE id=?").run(id);
      },
      child: (stage, adapter, target, childId) => {
        check();
        this.db
          .prepare(
            "UPDATE job_steps SET child_run_id=? WHERE job_id=? AND step_key=?",
          )
          .run(childId, id, key(stage, adapter, target));
      },
      complete: (stage, adapter, target, result) => {
        step(
          stage,
          adapter,
          target,
          result,
          ["completed", "cached"].includes(result.status)
            ? "completed"
            : "pending",
        );
      },
    };
    this.db
      .prepare("UPDATE runs SET status='running',finished=NULL WHERE id=?")
      .run(id);
    const seal = (result) => {
      this.db.exec("BEGIN IMMEDIATE");
      try {
        const lease = this.db
          .prepare("SELECT owner,lease_until FROM jobs WHERE id=?")
          .get(id);
        if (lease?.owner !== owner || lease.lease_until <= Date.now())
          throw new OperationError("JOB_LEASE_LOST");
        const root = this.db
          .prepare("SELECT adapter,target FROM runs WHERE id=?")
          .get(id);
        const snapshotId = this.store.start(root.adapter, root.target);
        mirrorRun(this.store, id, snapshotId);
        this.store.finish(snapshotId, result.status, {
          snapshot_of: id,
          status: result.status,
        });
        this.db.exec("COMMIT");
        return { ...result, snapshot_id: snapshotId };
      } catch (error) {
        this.db.exec("ROLLBACK");
        throw error;
      }
    };
    try {
      let result = await execute(JSON.parse(row.request), context);
      check();
      result = seal(result);
      this.db
        .prepare(
          "UPDATE jobs SET status=?,result=?,updated_at=? WHERE id=? AND owner=?",
        )
        .run(
          result.status,
          JSON.stringify(result),
          new Date().toISOString(),
          id,
          owner,
        );
      return result;
    } catch (error) {
      const code = error instanceof OperationError ? error.code : "JOB_FAILED";
      const status = code === "CANCELLED" ? "cancelled" : "interrupted";
      let result = { run_id: id, status, code };
      if (code !== "JOB_LEASE_LOST") {
        result = seal(result);
        this.db
          .prepare(
            "UPDATE jobs SET status=?,result=?,updated_at=? WHERE id=? AND owner=?",
          )
          .run(
            status,
            JSON.stringify(result),
            new Date().toISOString(),
            id,
            owner,
          );
        this.store.finish(id, status, { code });
      }
      return result;
    } finally {
      clearInterval(heartbeat);
      externalSignal?.removeEventListener("abort", abort);
      this.db
        .prepare(
          "UPDATE jobs SET owner=NULL,lease_until=0 WHERE id=? AND owner=?",
        )
        .run(id, owner);
    }
  }
}
