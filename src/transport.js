import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { StringDecoder } from "node:string_decoder";

export class OperationError extends Error {
  constructor(code, retryable = false, retryAfterMs = 0) {
    super(code);
    this.code = code;
    this.retryable = retryable;
    this.retryAfterMs = retryAfterMs;
  }
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
export function runProcess(command, args, limits, stdin = "", options = {}) {
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(options.signal.reason);
      return;
    }
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([key]) =>
        [
          "PATH",
          "SYSTEMROOT",
          "WINDIR",
          "TEMP",
          "TMP",
          "HOME",
          "USERPROFILE",
          "APPDATA",
          "LOCALAPPDATA",
          "XDG_CONFIG_HOME",
        ].includes(key.toUpperCase()),
      ),
    );
    const child = spawn(command, args, {
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env,
    });
    let bytes = 0;
    let output = "";
    let stderr = "";
    const errDecoder = new StringDecoder("utf8");
    const decoder = new StringDecoder("utf8");
    let failure;
    const stop = (code) => {
      failure ??= new OperationError(code);
      child.kill("SIGKILL");
    };
    const timer = setTimeout(() => stop("PROCESS_TIMEOUT"), limits.timeoutMs);
    const abort = () => stop("CANCELLED");
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
    const cleanup = () => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
    };
    child.stdout.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > limits.maxBytes) stop("RESPONSE_TOO_LARGE");
      else output += decoder.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > limits.maxBytes) stop("RESPONSE_TOO_LARGE");
      else if (options.captureStderr) stderr += errDecoder.write(chunk);
    });
    child.stdin.on("error", () => {});
    child.on("error", (error) => {
      cleanup();
      reject(
        new OperationError(
          error.code === "ENOENT"
            ? "TOOL_NOT_INSTALLED"
            : "PROCESS_START_ERROR",
        ),
      );
    });
    child.on("close", (code) => {
      cleanup();
      if (failure) reject(failure);
      else if (code !== 0) reject(new OperationError("TOOL_FAILED"));
      else
        resolve(
          output +
            decoder.end() +
            (options.captureStderr ? stderr + errDecoder.end() : ""),
        );
    });
    child.stdin.end(stdin);
  });
}
