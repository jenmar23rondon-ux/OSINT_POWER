import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { setPriority } from "node:os";
import { basename, isAbsolute, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { StringDecoder } from "node:string_decoder";

const ERROR_KINDS = {
  PROCESS_TIMEOUT: "timeout",
  CANCELLED: "cancelled",
  RESPONSE_TOO_LARGE: "output-truncated",
  TOOL_NOT_INSTALLED: "binary-missing",
  REJECTED_ARGUMENT: "rejected-argument",
};

// Shell metacharacters never belong in an argv entry. Backslash is allowed so
// Windows paths survive; spawn is always shell:false, so the shell never sees them.
const SHELL_META = /[\0\r\n;|&$`<>(){}[\]!*?"']/;
const SAFE_FLAG = /^--?[A-Za-z0-9][A-Za-z0-9-]{0,64}$/;
const HOST_TARGET = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,253})?$/;
const HTTP_TARGET =
  /^https?:\/\/[A-Za-z0-9][A-Za-z0-9._:-]*(?::\d{1,5})?(?:\/[A-Za-z0-9._~-]*)?$/;
const ENV_ALLOW = new Set([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "WINDIR",
  "TEMP",
  "TMP",
  "HOME",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "XDG_CONFIG_HOME",
]);

export const NATIVE_BINARY_NAMES = new Set([
  "subfinder",
  "amass",
  "dnsx",
  "httpx",
  "naabu",
  "sherlock",
  "theHarvester",
]);
export const OUTPUT_TRUNCATED_MARKER = "\n[OSINT_POWER_OUTPUT_TRUNCATED]\n";
const TERMINATE_GRACE_MS = 250;
const PRLIMIT = "/usr/bin/prlimit";

// In-process cap. Provider quotas in SQLite remain a separate control and are
// shared across processes; this limit is not.
let nativeLimit = 4;
let nativeActive = 0;
const nativeQueue = [];
const liveGroups = new Set();
let exitHooked = false;

function trackGroup(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return;
  liveGroups.add(pid);
  if (exitHooked) return;
  exitHooked = true;
  process.on("exit", () => {
    for (const group of liveGroups) forceTree(group);
  });
}

function untrackGroup(pid) {
  liveGroups.delete(pid);
}

function forceTree(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return;
  if (process.platform === "win32") {
    try {
      spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], {
        shell: false,
        windowsHide: true,
        stdio: "ignore",
      });
    } catch {
      /* The process already exited. */
    }
    return;
  }
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* The process already exited. */
    }
  }
}

export class OperationError extends Error {
  constructor(code, retryable = false, retryAfterMs = 0) {
    super(code);
    this.code = code;
    this.kind = ERROR_KINDS[code] ?? "operation";
    this.retryable = retryable;
    this.retryAfterMs = retryAfterMs;
  }
}

export function nativeConcurrency() {
  return nativeLimit;
}

export function setNativeConcurrency(value) {
  if (!Number.isInteger(value) || value < 1 || value > 32)
    throw new OperationError("REJECTED_ARGUMENT");
  nativeLimit = value;
  drainNative();
  return nativeLimit;
}

function drainNative() {
  while (nativeActive < nativeLimit && nativeQueue.length) {
    const entry = nativeQueue.shift();
    entry.signal?.removeEventListener("abort", entry.onAbort);
    if (entry.signal?.aborted) {
      entry.reject(
        entry.signal.reason instanceof Error
          ? entry.signal.reason
          : new OperationError("CANCELLED"),
      );
      continue;
    }
    nativeActive++;
    entry.resolve();
  }
}

function acquireNative(signal) {
  if (signal?.aborted) {
    return Promise.reject(
      signal.reason instanceof Error
        ? signal.reason
        : new OperationError("CANCELLED"),
    );
  }
  if (nativeActive < nativeLimit && nativeQueue.length === 0) {
    nativeActive++;
    return Promise.resolve();
  }
  return new Promise((resolvePromise, reject) => {
    const entry = { resolve: resolvePromise, reject, signal };
    entry.onAbort = () => {
      const index = nativeQueue.indexOf(entry);
      if (index >= 0) nativeQueue.splice(index, 1);
      reject(
        signal.reason instanceof Error
          ? signal.reason
          : new OperationError("CANCELLED"),
      );
    };
    nativeQueue.push(entry);
    signal?.addEventListener("abort", entry.onAbort, { once: true });
  });
}

function releaseNative() {
  nativeActive = Math.max(0, nativeActive - 1);
  drainNative();
}

export function assertSafeTarget(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.startsWith("-") ||
    value.includes("..") ||
    (!HOST_TARGET.test(value) && !HTTP_TARGET.test(value))
  )
    throw new OperationError("REJECTED_ARGUMENT");
}

export function assertSafeArgument(arg) {
  if (typeof arg !== "string" || arg.length === 0 || arg.length > 4096)
    throw new OperationError("REJECTED_ARGUMENT");
  if (SHELL_META.test(arg)) throw new OperationError("REJECTED_ARGUMENT");
  if (arg.startsWith("-") && !SAFE_FLAG.test(arg))
    throw new OperationError("REJECTED_ARGUMENT");
}

function samePath(left, right) {
  const a = resolve(left);
  const b = resolve(right);
  return process.platform === "win32"
    ? a.toLowerCase() === b.toLowerCase()
    : a === b;
}

function assertCommand(command, allow) {
  if (
    typeof command !== "string" ||
    command.length === 0 ||
    command.length > 1024
  )
    throw new OperationError("REJECTED_ARGUMENT");
  if (SHELL_META.test(command)) throw new OperationError("REJECTED_ARGUMENT");
  const base = basename(command).replace(/\.exe$/i, "");
  const bare =
    !command.includes("/") &&
    !command.includes("\\") &&
    (command === base || command.toLowerCase() === `${base.toLowerCase()}.exe`);
  if (bare) {
    if (!NATIVE_BINARY_NAMES.has(base))
      throw new OperationError("REJECTED_ARGUMENT");
    return;
  }
  if (!isAbsolute(command)) throw new OperationError("REJECTED_ARGUMENT");
  const resolved = resolve(command);
  const allowedPath =
    Array.isArray(allow) && allow.some((entry) => samePath(entry, resolved));
  if (NATIVE_BINARY_NAMES.has(base) || allowedPath) return;
  throw new OperationError("REJECTED_ARGUMENT");
}

function assertStdin(stdin) {
  if (stdin === undefined || stdin === null || stdin === "") return;
  if (typeof stdin !== "string" || stdin.length > 8192)
    throw new OperationError("REJECTED_ARGUMENT");
  const body = stdin.endsWith("\n") ? stdin.slice(0, -1) : stdin;
  if (body.includes("\n")) throw new OperationError("REJECTED_ARGUMENT");
  assertSafeTarget(body);
}

function assertTargets(targets, args, stdin) {
  if (targets === undefined || targets === null) return;
  if (!Array.isArray(targets)) throw new OperationError("REJECTED_ARGUMENT");
  const lines = typeof stdin === "string" ? stdin.split("\n") : [];
  for (const target of targets) {
    assertSafeTarget(target);
    if (!args.includes(target) && !lines.includes(target))
      throw new OperationError("REJECTED_ARGUMENT");
  }
}

function assertLimits(limits) {
  if (
    !limits ||
    !Number.isInteger(limits.timeoutMs) ||
    limits.timeoutMs < 1 ||
    !Number.isInteger(limits.maxBytes) ||
    limits.maxBytes < 1
  )
    throw new OperationError("REJECTED_ARGUMENT");
}

function sanitizedEnv() {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value !== "string" || value.includes("\0")) continue;
    if (!ENV_ALLOW.has(key.toUpperCase())) continue;
    env[key] = value;
  }
  return env;
}

function signalTree(pid, signal) {
  if (!Number.isInteger(pid) || pid <= 0) return;
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if (error?.code === "ESRCH") return;
    try {
      process.kill(pid, signal);
    } catch {
      /* The process already exited. */
    }
  }
}

function taskkill(pid, force) {
  if (!Number.isInteger(pid) || pid <= 0) return;
  const args = ["/PID", String(pid), "/T"];
  if (force) args.push("/F");
  const killer = spawn("taskkill", args, {
    shell: false,
    windowsHide: true,
    stdio: "ignore",
  });
  killer.unref();
  killer.on("error", () => {});
}

function terminateTree(pid) {
  if (process.platform === "win32") taskkill(pid, false);
  else signalTree(pid, "SIGTERM");
  return setTimeout(() => {
    if (process.platform === "win32") taskkill(pid, true);
    else signalTree(pid, "SIGKILL");
  }, TERMINATE_GRACE_MS);
}

// CPU niceness is best-effort on every platform os.setPriority supports.
// Linux CPU-time rlimit is a backstop slightly above the wall-clock timeout
// (CPU time cannot exceed wall time, so it does not preempt a run we already
// kill on timeout). Memory address-space limits are intentionally not applied:
// Go recon tools reserve large virtual ranges and RLIMIT_AS breaks them.
// Hard memory control belongs on the host cgroup, job object, or container.
function applyBestEffortLimits(pid, limits) {
  if (!Number.isInteger(pid) || pid <= 0) return;
  try {
    setPriority(pid, 10);
  } catch {
    /* Priority changes are optional and may be denied. */
  }
  if (process.platform === "win32" || !existsSync(PRLIMIT)) return;
  const seconds = Math.min(120, Math.ceil(limits.timeoutMs / 1000) + 2);
  const limiter = spawn(PRLIMIT, ["--pid", String(pid), `--cpu=${seconds}`], {
    shell: false,
    stdio: "ignore",
    windowsHide: true,
  });
  limiter.unref();
  limiter.on("error", () => {});
}

export async function retry(operation, limits, wait = sleep, signal) {
  for (let attempt = 1; attempt <= limits.attempts; attempt++) {
    signal?.throwIfAborted();
    try {
      return await operation();
    } catch (error) {
      if (signal?.aborted) throw signal.reason;
      if (!error.retryable || attempt === limits.attempts) throw error;
      // Do not shorten a provider's Retry-After. Long waits end this run instead.
      const delay = Math.max(
        limits.minIntervalMs,
        500 * 2 ** (attempt - 1),
        error.retryAfterMs ?? 0,
      );
      if (delay > 60_000) throw new OperationError("RETRY_LATER");
      await wait(delay, undefined, { signal });
    }
  }
}
export async function fetchText(url, limits, headers = {}, fetcher = fetch) {
  let response;
  try {
    response = await fetcher(url, {
      headers: {
        "User-Agent":
          "OSINT_POWER/0.4 (+https://github.com/jenmar23rondon-ux/OSINT_POWER)",
        ...headers,
      },
      redirect: "error",
      signal: AbortSignal.timeout(limits.timeoutMs),
    });
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw new OperationError("NETWORK_ERROR", true);
  }
  if (
    response.status === 404 &&
    new URL(url).hostname === "haveibeenpwned.com"
  ) {
    await response.body?.cancel();
    return "[]";
  }
  if (!response.ok) {
    const value = response.headers.get("retry-after");
    const retryAfter = value
      ? /^\d+$/.test(value)
        ? Number(value) * 1000
        : Math.max(0, Date.parse(value) - Date.now())
      : 0;
    await response.body?.cancel();
    throw new OperationError(
      `HTTP_${response.status}`,
      response.status === 429 || response.status >= 500,
      Number.isFinite(retryAfter) ? retryAfter : 0,
    );
  }
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limits.maxBytes) {
        await reader.cancel();
        throw new OperationError("RESPONSE_TOO_LARGE");
      }
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw new OperationError("BODY_READ_ERROR", true);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function runProcess(
  command,
  args,
  limits,
  stdin = "",
  options = {},
) {
  assertLimits(limits);
  if (
    options.allow !== undefined &&
    options.allow !== null &&
    !Array.isArray(options.allow)
  )
    throw new OperationError("REJECTED_ARGUMENT");
  assertCommand(command, options.allow);
  if (!Array.isArray(args) || args.length > 64)
    throw new OperationError("REJECTED_ARGUMENT");
  for (const arg of args) assertSafeArgument(arg);
  assertStdin(stdin);
  assertTargets(options.targets, args, stdin);
  if (options.signal?.aborted)
    throw options.signal.reason ?? new OperationError("CANCELLED");

  await acquireNative(options.signal);
  try {
    if (options.signal?.aborted)
      throw options.signal.reason ?? new OperationError("CANCELLED");
    return await spawnCollected(command, args, limits, stdin, options);
  } finally {
    releaseNative();
  }
}

function spawnCollected(command, args, limits, stdin, options) {
  return new Promise((resolve, reject) => {
    const env = sanitizedEnv();
    const child = spawn(command, args, {
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env,
      // New process group on POSIX so a negative-pid signal reaches grandchildren.
      // Windows tree kill uses taskkill /T and does not need a detached console.
      detached: process.platform !== "win32",
    });
    applyBestEffortLimits(child.pid, limits);
    trackGroup(child.pid);
    let bytes = 0;
    let output = "";
    let stderr = "";
    const decoder = new StringDecoder("utf8");
    const errDecoder = new StringDecoder("utf8");
    let failure;
    let settled = false;
    let escalate;
    const cleanup = () => {
      clearTimeout(timer);
      clearTimeout(escalate);
      options.signal?.removeEventListener("abort", abort);
    };
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      cleanup();
      // SIGTERM may reap the leader before a grandchild that ignored it.
      // Force the group once more while this pid is still the one we spawned.
      if (failure) forceTree(child.pid);
      untrackGroup(child.pid);
      callback();
    };
    const stop = (code) => {
      if (failure) return;
      failure = new OperationError(code);
      if (code === "RESPONSE_TOO_LARGE") {
        failure.truncated = true;
        if (!output.includes(OUTPUT_TRUNCATED_MARKER))
          output += OUTPUT_TRUNCATED_MARKER;
      }
      failure.output = output;
      escalate = terminateTree(child.pid);
    };
    const take = (chunk, decode, sink) => {
      if (failure) return;
      const room = limits.maxBytes - bytes;
      if (chunk.length > room) {
        if (room > 0) sink(decode(chunk.subarray(0, room)));
        stop("RESPONSE_TOO_LARGE");
        return;
      }
      bytes += chunk.length;
      sink(decode(chunk));
    };
    const timer = setTimeout(() => stop("PROCESS_TIMEOUT"), limits.timeoutMs);
    const abort = () => stop("CANCELLED");
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
    child.stdout.on("data", (chunk) => {
      take(
        chunk,
        (part) => decoder.write(part),
        (text) => {
          output += text;
        },
      );
    });
    child.stderr.on("data", (chunk) => {
      take(
        chunk,
        (part) => errDecoder.write(part),
        (text) => {
          if (options.captureStderr) stderr += text;
        },
      );
    });
    child.stdin.on("error", () => {});
    child.on("error", (error) => {
      finish(() =>
        reject(
          failure ??
            new OperationError(
              error.code === "ENOENT"
                ? "TOOL_NOT_INSTALLED"
                : "PROCESS_START_ERROR",
            ),
        ),
      );
    });
    child.on("close", (code) => {
      if (!failure) output += decoder.end();
      if (failure) {
        failure.output = output;
        if (options.captureStderr) failure.stderr = stderr;
        finish(() => reject(failure));
        return;
      }
      if (code !== 0) {
        finish(() => reject(new OperationError("TOOL_FAILED")));
        return;
      }
      finish(() =>
        resolve(
          output + (options.captureStderr ? stderr + errDecoder.end() : ""),
        ),
      );
    });
    child.stdin.end(stdin);
  });
}
