import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  isSqliteExperimentalWarning,
  silenceSqliteWarning,
  supportedNode,
} from "../src/runtime-check.js";

test("Node 24.14 is the minimum and older versions are rejected", () => {
  assert.equal(supportedNode("24.14.0"), true);
  assert.equal(supportedNode("v24.14.2"), true);
  assert.equal(supportedNode("25.0.0"), true);
  assert.equal(supportedNode("24.13.9"), false);
  assert.equal(supportedNode("22.23.4"), false);
  assert.equal(supportedNode("20.0.0"), false);
});

test("only the SQLite experimental warning is swallowed", async () => {
  const original = process.emitWarning;
  silenceSqliteWarning();
  const seen = [];
  const onWarning = (warning) => seen.push(warning);
  process.on("warning", onWarning);
  try {
    process.emitWarning(
      "SQLite is an experimental feature and might change at any time",
      "ExperimentalWarning",
    );
    process.emitWarning("Another experiment", "ExperimentalWarning");
    process.emitWarning("A deprecation", "DeprecationWarning");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(
      seen.some((warning) => /SQLite/.test(warning.message)),
      false,
    );
    assert.equal(
      seen.some((warning) => /Another experiment/.test(warning.message)),
      true,
    );
    assert.equal(
      seen.some((warning) => warning.name === "DeprecationWarning"),
      true,
    );
    assert.equal(
      isSqliteExperimentalWarning(
        "SQLite is an experimental feature",
        "ExperimentalWarning",
      ),
      true,
    );
  } finally {
    process.off("warning", onWarning);
    process.emitWarning = original;
  }
});

test("commands that do not open the database omit the SQLite warning", () => {
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  for (const args of [
    ["privacy-check-image", "--file", "missing.jpg"],
    ["search-image-copies", "--file", "missing.jpg", "--dir", "."],
    ["help"],
  ]) {
    const child = spawnSync(process.execPath, [cli, ...args], {
      encoding: "utf8",
    });
    assert.equal(child.error, undefined);
    assert.equal(/ExperimentalWarning|node:sqlite/i.test(child.stderr), false);
    assert.equal(JSON.parse(child.stdout).ok !== undefined, true);
  }
});

test("Node below 24 prints NODE_VERSION instead of crashing on node:sqlite", () => {
  const node22 = "/exec-daemon/node";
  if (!existsSync(node22)) return;
  const version = spawnSync(node22, ["-p", "process.versions.node"], {
    encoding: "utf8",
  });
  if (!version.stdout || supportedNode(version.stdout.trim())) return;
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const child = spawnSync(node22, [cli, "help"], { encoding: "utf8" });
  const output = JSON.parse(child.stdout);
  assert.equal(child.status, 1);
  assert.equal(output.ok, false);
  assert.equal(output.error.code, "NODE_VERSION");
  assert.match(output.error.message, /node:sqlite/);
  assert.match(output.error.hint, /24\.14/);
  assert.equal(
    /Cannot find module|ERR_UNKNOWN_BUILTIN/i.test(child.stderr),
    false,
  );
});
