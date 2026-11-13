import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("CLI returns stable codes, actionable guidance, and failure exit codes", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-errors-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const run = (args, env = process.env) => {
    const child = spawnSync(process.execPath, [cli, ...args], {
      cwd: dir,
      encoding: "utf8",
      env,
    });
    assert.ifError(child.error);
    const output = JSON.parse(child.stdout);
    assert.equal(child.status, output.ok ? 0 : 1);
    return output;
  };
  const failure = (args, code, hint) => {
    const output = run(args);
    assert.equal(output.ok, false);
    assert.equal(output.error.code, code);
    assert.match(output.error.hint, hint);
    assert.ok(output.error.message);
    assert.equal(JSON.stringify(output).includes("SENSITIVE-MARKER"), false);
    return output;
  };
  failure(
    ["query", "--config", "SENSITIVE-MARKER.json"],
    "FILE_NOT_FOUND",
    /init/,
  );
  writeFileSync(join(dir, "bad.json"), "{SENSITIVE-MARKER");
  failure(["query", "--config", "bad.json"], "INVALID_INPUT", /configuration/);
  assert.equal(run(["init"]).ok, true);
  failure(["init"], "CONFIG_EXISTS", /--config/);
  failure(
    ["import", "--adapter", "subfinder", "--file", "SENSITIVE-MARKER.txt"],
    "FILE_NOT_FOUND",
    /--file/,
  );
  failure(
    ["import", "--adapter", "subfinder", "--file", "."],
    "INVALID_IMPORT_FILE",
    /readable file/,
  );
  failure(["query", "--limit", "SENSITIVE-MARKER"], "INVALID_INPUT", /help/);

  writeFileSync(
    join(dir, "network.json"),
    JSON.stringify({
      version: 1,
      network: true,
      enabledAdapters: ["subfinder"],
      scope: { domains: ["example.com"] },
    }),
  );
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => key.toLowerCase() !== "path"),
  );
  const dependency = run(
    [
      "run",
      "--adapter",
      "subfinder",
      "--target",
      "example.com",
      "--config",
      "network.json",
      "--db",
      "network.sqlite",
    ],
    { ...env, PATH: dir },
  );
  assert.equal(dependency.ok, false);
  assert.equal(dependency.result.code, "TOOL_NOT_INSTALLED");
  assert.equal(dependency.error.code, "TOOL_NOT_INSTALLED");
  assert.match(dependency.error.hint, /PATH/);
});
