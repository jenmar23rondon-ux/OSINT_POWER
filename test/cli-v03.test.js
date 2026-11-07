import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

test("v0.3 CLI supports queued jobs, snapshots, diagnostics, comparison and HTML export", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "osint-cli-v03-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = join(dir, "config.json"),
    db = join(dir, "state.sqlite"),
    firstFile = join(dir, "first.txt"),
    secondFile = join(dir, "second.txt");
  writeFileSync(
    config,
    JSON.stringify({
      version: 1,
      scope: { domains: ["example.com"] },
      enabledAdapters: ["crtsh"],
    }),
  );
  writeFileSync(firstFile, "old.example.com");
  writeFileSync(secondFile, "new.example.com");
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const call = (args) =>
    JSON.parse(
      execFileSync(
        process.execPath,
        [cli, ...args, "--config", config, "--db", db],
        { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
      ),
    ).result;
  const job = call([
    "workflow",
    "--workflow",
    "correlation",
    "--target",
    "example.com",
    "--queue",
  ]);
  assert.equal(job.status, "queued");
  assert.equal(call(["jobs"]).total, 1);
  assert.equal(call(["job", "--id", job.id]).status, "queued");
  const completed = call(["resume", "--id", job.id]);
  assert.equal(completed.status, "completed");
  assert.match(completed.snapshot_id, /^[a-f0-9-]{36}$/);
  assert.equal(call(["doctor", "--skip-probes"]).network_probe, false);
  assert.equal(
    call(["plan", "--workflow", "company", "--target", "example.com"]).network,
    false,
  );
  const before = call([
    "import",
    "--adapter",
    "subfinder",
    "--file",
    firstFile,
  ]);
  const after = call([
    "import",
    "--adapter",
    "subfinder",
    "--file",
    secondFile,
  ]);
  const diff = call([
    "compare",
    "--before",
    before.run_id,
    "--after",
    after.run_id,
  ]);
  assert.equal(diff.counts.added, 1);
  assert.equal(diff.counts.not_observed, 1);
  const entity = call(["query", "--type", "domain"]).items[0];
  assert.equal(call(["explain", "--id", entity.id]).history.length, 1);
  const html = join(dir, "report.html");
  assert.equal(
    call(["report", "--format", "html", "--output", html]).status,
    "completed",
  );
  assert.equal(readFileSync(html, "utf8").includes("Evidence inventory"), true);
  assert.equal(call(["health"]).providers.length, 0);
  assert.equal(call(["runs", "--limit", "1"]).items.length, 1);
});
