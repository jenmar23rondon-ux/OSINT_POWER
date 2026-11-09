import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { collect, commandFor } from "../src/adapters.js";
import { Config } from "../src/schema.js";
import { Scope } from "../src/scope.js";
import {
  nativeConcurrency,
  OperationError,
  OUTPUT_TRUNCATED_MARKER,
  runProcess,
  setNativeConcurrency,
} from "../src/transport.js";

const limits = {
  timeoutMs: 5000,
  maxBytes: 1000,
  requestRate: 2,
  ports: [80, 443],
};
const allow = [process.execPath];

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM";
  }
}
async function waitForFile(path, timeout = 4000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const value = (await readFile(path, "utf8")).trim();
      if (value) return value;
    } catch {
      /* The grandchild has not written its pid yet. */
    }
    await delay(20);
  }
  throw new Error("PID_FILE_TIMEOUT");
}
async function waitDead(pid) {
  const start = Date.now();
  while (Date.now() - start < 4000) {
    if (!alive(pid)) return;
    await delay(30);
  }
  assert.equal(alive(pid), false);
}

const treeSource = `const { spawn } = require("node:child_process");
const { writeFileSync } = require("node:fs");
const args = process.argv.slice(2);
if (args[0] === "grandchild") {
  writeFileSync(args[1], String(process.pid));
  setInterval(() => {}, 1000);
} else {
  const pidFile = args[0];
  const child = spawn(process.execPath, [__filename, "grandchild", pidFile], {
    stdio: "ignore",
    windowsHide: true,
  });
  child.unref();
  writeFileSync(pidFile + ".parent", String(process.pid));
  setInterval(() => {}, 1000);
}
`;

describe("native execution limits", { concurrency: 1 }, () => {
  test("rejects shell metacharacters, option injection, and unknown binaries", async () => {
    assert.throws(
      () => commandFor("subfinder", "-example.com", limits),
      (error) =>
        error instanceof OperationError &&
        error.code === "REJECTED_ARGUMENT" &&
        error.kind === "rejected-argument",
    );
    assert.throws(
      () => commandFor("amass", "example.com;id", limits),
      /REJECTED_ARGUMENT/,
    );
    assert.throws(
      () => commandFor("dnsx", "example.com\n-json", limits),
      /REJECTED_ARGUMENT/,
    );
    assert.throws(
      () => commandFor("httpx", "--follow-redirects", limits),
      /REJECTED_ARGUMENT/,
    );
    assert.equal(
      commandFor("httpx", "http://127.0.0.1:9", limits).stdin,
      "http://127.0.0.1:9\n",
    );
    await assert.rejects(
      runProcess("subfinder", ["-d", "example.com;id"], limits),
      (error) => error.code === "REJECTED_ARGUMENT",
    );
    await assert.rejects(
      runProcess("subfinder", ["-d", "-example.com"], limits),
      (error) => error.code === "REJECTED_ARGUMENT",
    );
    await assert.rejects(
      runProcess("subfinder", ["-d", "-silent"], limits, "", {
        targets: ["-silent"],
      }),
      (error) =>
        error.code === "REJECTED_ARGUMENT" &&
        error.kind === "rejected-argument",
    );
    await assert.rejects(
      runProcess("sh", ["-c", "echo hi"], limits),
      (error) =>
        error.code === "REJECTED_ARGUMENT" &&
        error.kind === "rejected-argument",
    );
  });

  test("missing allowlisted binary is a structured not-installed error", async () => {
    const directory = await mkdtemp(join(tmpdir(), "osint-power-missing-"));
    try {
      await assert.rejects(
        runProcess(join(directory, "subfinder"), ["-version"], limits),
        (error) =>
          error instanceof OperationError &&
          error.code === "TOOL_NOT_INSTALLED" &&
          error.kind === "binary-missing",
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("stdout cap truncates with a marker and stops the run", async () => {
    const directory = await mkdtemp(join(tmpdir(), "osint-power-cap-"));
    const script = join(directory, "big.cjs");
    await writeFile(script, 'process.stdout.write("x".repeat(5000))\n');
    try {
      await assert.rejects(
        runProcess(
          process.execPath,
          [script],
          { ...limits, maxBytes: 100 },
          "",
          { allow },
        ),
        (error) => {
          assert.equal(error.code, "RESPONSE_TOO_LARGE");
          assert.equal(error.kind, "output-truncated");
          assert.equal(error.truncated, true);
          assert.equal(error.output.endsWith(OUTPUT_TRUNCATED_MARKER), true);
          assert.equal(error.output.slice(0, 100), "x".repeat(100));
          assert.ok(
            error.output.length <= 100 + OUTPUT_TRUNCATED_MARKER.length,
          );
          return true;
        },
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("child environment omits secrets and unapproved variables", async () => {
    const directory = await mkdtemp(join(tmpdir(), "osint-power-env-"));
    const script = join(directory, "env.cjs");
    const previous = process.env.HIBP_API_KEY;
    await writeFile(
      script,
      `process.stdout.write(JSON.stringify({
        leaked: ["OSINT_POWER_SENTINEL", "HIBP_API_KEY", "NODE_OPTIONS"].filter((key) => process.env[key]),
        path: typeof process.env.PATH
      }))`,
    );
    process.env.OSINT_POWER_SENTINEL = "nope";
    process.env.HIBP_API_KEY = "secret";
    try {
      const output = await runProcess(process.execPath, [script], limits, "", {
        allow,
      });
      const parsed = JSON.parse(output);
      assert.deepEqual(parsed.leaked, []);
      assert.equal(parsed.path, "string");
    } finally {
      delete process.env.OSINT_POWER_SENTINEL;
      if (previous === undefined) delete process.env.HIBP_API_KEY;
      else process.env.HIBP_API_KEY = previous;
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("native launch reuses scope and does not start an out-of-scope target", async () => {
    const config = Config.parse({
      version: 1,
      scope: { domains: ["example.com"] },
      limits,
    });
    const scope = new Scope(config);
    let called = false;
    await assert.rejects(
      () =>
        collect("subfinder", "evil.invalid", config, {
          scope,
          runner: () => {
            called = true;
            return "";
          },
        }),
      /OUT_OF_SCOPE/,
    );
    assert.equal(called, false);
    let seen;
    const output = await collect("subfinder", "Example.COM", config, {
      scope,
      runner: (command, args, _limits, _stdin, options) => {
        seen = { command, args, targets: options.targets };
        return "api.example.com\n";
      },
    });
    assert.equal(output, "api.example.com\n");
    assert.equal(seen.command, "subfinder");
    assert.deepEqual(seen.targets, ["example.com"]);
    assert.equal(seen.args.includes("example.com"), true);
    assert.equal(seen.args.includes("Example.COM"), false);
  });

  test("cancel and timeout kill the grandchild as well as the child", async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "osint-power-tree-"));
    const script = join(directory, "tree.cjs");
    await writeFile(script, treeSource);
    const leftovers = [];
    t.after(async () => {
      for (const pid of leftovers) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          /* already exited */
        }
      }
      await rm(directory, { recursive: true, force: true });
    });
    const runTree = (pidFile, timeoutMs) =>
      runProcess(
        process.execPath,
        [script, pidFile],
        { ...limits, timeoutMs },
        "",
        { allow },
      );

    const cancelledPid = join(directory, "cancelled.pid");
    const controller = new AbortController();
    const cancelled = runProcess(
      process.execPath,
      [script, cancelledPid],
      limits,
      "",
      { allow, signal: controller.signal },
    );
    const grandchild = Number(await waitForFile(cancelledPid));
    const parent = Number(await waitForFile(cancelledPid + ".parent"));
    leftovers.push(grandchild, parent);
    assert.equal(alive(grandchild), true);
    controller.abort(new OperationError("CANCELLED"));
    await assert.rejects(
      cancelled,
      (error) => error.code === "CANCELLED" && error.kind === "cancelled",
    );
    await waitDead(grandchild);
    await waitDead(parent);

    const timedPid = join(directory, "timed.pid");
    const timed = runTree(timedPid, 3000);
    const timedGrandchild = Number(await waitForFile(timedPid));
    const timedParent = Number(await waitForFile(timedPid + ".parent"));
    leftovers.push(timedGrandchild, timedParent);
    await assert.rejects(
      timed,
      (error) => error.code === "PROCESS_TIMEOUT" && error.kind === "timeout",
    );
    await waitDead(timedGrandchild);
    await waitDead(timedParent);
  });

  test("concurrency cap holds until a slot is released", async (t) => {
    const previous = nativeConcurrency();
    setNativeConcurrency(1);
    const directory = await mkdtemp(join(tmpdir(), "osint-power-slots-"));
    const hold = join(directory, "hold.cjs");
    const next = join(directory, "next.cjs");
    const firstPid = join(directory, "first.pid");
    const secondPid = join(directory, "second.pid");
    await writeFile(
      hold,
      'require("node:fs").writeFileSync(process.argv[2], String(process.pid)); setInterval(() => {}, 1000);\n',
    );
    await writeFile(
      next,
      'require("node:fs").writeFileSync(process.argv[2], String(process.pid));\n',
    );
    const controller = new AbortController();
    const pids = [];
    let first;
    let second;
    t.after(async () => {
      controller.abort();
      for (const pid of pids) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          /* already exited */
        }
      }
      setNativeConcurrency(previous);
      await rm(directory, { recursive: true, force: true });
    });
    try {
      first = runProcess(process.execPath, [hold, firstPid], limits, "", {
        allow,
        signal: controller.signal,
      });
      pids.push(Number(await waitForFile(firstPid)));
      second = runProcess(process.execPath, [next, secondPid], limits, "", {
        allow,
      });
      await delay(250);
      assert.equal(existsSync(secondPid), false);
      controller.abort(new OperationError("CANCELLED"));
      await assert.rejects(first, /CANCELLED/);
      await second;
      assert.equal(existsSync(secondPid), true);
    } finally {
      controller.abort();
      await first?.catch(() => {});
      await second?.catch(() => {});
      setNativeConcurrency(previous);
    }
  });
});
