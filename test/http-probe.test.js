import assert from "node:assert/strict";
import test from "node:test";
import { commandFor } from "../src/adapters.js";
import { Engine } from "../src/engine.js";
import { probeDiscoveredHosts } from "../src/http-probe.js";
import { Store } from "../src/store.js";

const httpxHelp = [
  "-silent",
  "-json",
  "-tech-detect",
  "-web-server",
  "-ip",
  "-cdn",
  "-tls-grab",
  "-duc",
  "projectdiscovery",
].join("\n");

function workspace(t, dependencies) {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(
    {
      version: 1,
      scope: { domains: ["example.com"] },
      network: true,
      active: true,
      enabledAdapters: ["httpx", "crtsh"],
      limits: { minIntervalMs: 0, cacheTtlSeconds: 0 },
    },
    store,
    dependencies,
  );
  engine.import({
    adapter: "subfinder",
    data: "api.example.com\nexcluded.example.net\n",
  });
  return engine;
}

test("httpx probe stays off without both opt-in flags and never follows redirects", async (t) => {
  let calls = 0;
  const engine = workspace(t, {
    locateBinary: () => "/fixture/httpx",
    diagnosticRunner: async () => httpxHelp,
    runner: async () => {
      calls++;
      return "";
    },
  });
  const planned = await engine.workflow({
    workflow: "company",
    target: "example.com",
    execute: false,
  });
  assert.equal(
    planned.steps.some((step) => step.adapter === "httpx"),
    false,
  );
  await assert.rejects(
    () =>
      probeDiscoveredHosts(engine, {
        target: "example.com",
        probe_http: true,
        authorized: false,
      }),
    /authorized/,
  );
  assert.equal(calls, 0);
  const limits = engine.config.limits;
  const plan = commandFor("httpx", "api.example.com", limits);
  assert.equal(plan.args.includes("-follow-redirects"), false);
  assert.equal(plan.args.includes("-threads"), true);
  assert.equal(plan.args[plan.args.indexOf("-threads") + 1], "1");
  assert.equal(plan.args.includes("-web-server"), true);
  assert.equal(plan.stdin, "api.example.com\n");
});

test("authorized httpx probe stores status, title, tech, server, TLS, IP and CDN", async (t) => {
  const engine = workspace(t, {
    locateBinary: () => "/fixture/httpx",
    diagnosticRunner: async (_path, args) =>
      args[0] === "-h" ? httpxHelp : "httpx v1.12.0",
    runner: async (_command, args, _limits, stdin) => {
      assert.equal(args.includes("-follow-redirects"), false);
      assert.equal(stdin.includes("\n", stdin.indexOf("\n") + 1), false);
      const host = stdin.trim();
      return JSON.stringify({
        url: `https://${host}/`,
        status_code: 200,
        title: "Example API",
        tech: ["nginx"],
        webserver: "nginx",
        ip: "192.0.2.10",
        cdn_name: "cloudflare",
        tls: { subject_cn: host, issuer_cn: "Example CA" },
      });
    },
  });
  const result = await probeDiscoveredHosts(engine, {
    target: "example.com",
    probe_http: true,
    authorized: true,
    maxTargets: 2,
  });
  assert.equal(result.status, "completed");
  assert.equal(result.authorized, true);
  assert.deepEqual(result.hosts, ["example.com", "api.example.com"]);
  const services = engine.store.query({ type: "url" }).items;
  assert.equal(services.length, 2);
  const evidence = engine.store.evidence(services[0].id).items[0].evidence;
  assert.equal(evidence.status, 200);
  assert.equal(evidence.title, "Example API");
  assert.deepEqual(evidence.technology, ["nginx"]);
  assert.equal(evidence.webserver, "nginx");
  assert.equal(evidence.cdn, "cloudflare");
  assert.equal(evidence.certificate_cn.length > 0, true);
  assert.equal(engine.store.query({ type: "ip" }).total, 1);
});

test("a Python httpx binary is rejected with an install hint and is not spawned against hosts", async (t) => {
  let calls = 0;
  const engine = workspace(t, {
    locateBinary: () => "/usr/bin/httpx",
    diagnosticRunner: async () => "Python httpx --help\nusage: httpx",
    runner: async () => {
      calls++;
      return "";
    },
  });
  await assert.rejects(
    () =>
      probeDiscoveredHosts(engine, {
        target: "example.com",
        probe_http: true,
        authorized: true,
      }),
    /HTTPX_NOT_PROJECTDISCOVERY/,
  );
  assert.equal(calls, 0);
  await assert.rejects(
    () =>
      probeDiscoveredHosts(
        workspace(t, { locateBinary: () => null, runner: async () => "" }),
        {
          target: "example.com",
          probe_http: true,
          authorized: true,
        },
      ),
    /TOOL_NOT_INSTALLED/,
  );
});
