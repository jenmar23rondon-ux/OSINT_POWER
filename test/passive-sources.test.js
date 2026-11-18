import assert from "node:assert/strict";
import test from "node:test";
import { Engine } from "../src/engine.js";
import { domainRdapBase } from "../src/passive-sources.js";
import { Store } from "../src/store.js";

const KEY = "synthetic-test-key";

function responseFor(url, headers) {
  const parsed = new URL(url);
  const host = parsed.hostname;
  if (host === "data.iana.org")
    return {
      services: [
        [["com"], ["http://127.0.0.1/rdap/", "https://rdap.example.net/com/"]],
      ],
    };
  if (host === "rdap.example.net")
    return {
      ldhName: "example.com",
      nameservers: [{ ldhName: "ns.example.com" }],
      entities: [
        {
          roles: ["registrar"],
          vcardArray: ["vcard", [["fn", {}, "text", "Example Registrar"]]],
        },
      ],
      events: [
        { eventAction: "registration", eventDate: "1995-08-14T04:00:00Z" },
      ],
    };
  if (host === "cloudflare-dns.com") {
    const type = parsed.searchParams.get("type");
    const data =
      type === "A"
        ? "192.0.2.10"
        : type === "MX"
          ? "10 mx.example.com"
          : type === "TXT"
            ? '"v=spf1 include:example.com"'
            : type === "NS"
              ? "ns.example.com"
              : "";
    return { Status: 0, Answer: data ? [{ data }] : [] };
  }
  if (host === "otx.alienvault.com")
    return {
      passive_dns: [
        {
          hostname: "api.example.com",
          address: "192.0.2.10",
          record_type: "A",
        },
        {
          hostname: "out.example.net",
          address: "198.51.100.8",
          record_type: "A",
        },
      ],
    };
  if (host === "api.hackertarget.com")
    return "api.example.com,192.0.2.10\nout.example.net,198.51.100.9\n";
  if (host === "urlscan.io") {
    assert.equal(headers["API-Key"], undefined);
    return {
      results: [
        {
          page: {
            domain: "api.example.com",
            url: "https://api.example.com/login?token=secret",
            title: "API",
          },
        },
      ],
    };
  }
  if (host === "internetdb.shodan.io")
    return {
      ip: "192.0.2.10",
      ports: [443],
      hostnames: ["api.example.com"],
      cpes: ["cpe:/a:nginx:nginx"],
      vulns: ["CVE-2024-0001", "not-a-cve"],
      tags: ["cloud"],
    };
  if (host === "api.securitytrails.com") {
    assert.equal(headers.APIKEY, KEY);
    return { subdomains: ["www", "excluded"] };
  }
  if (host === "www.virustotal.com") {
    assert.equal(headers["x-apikey"], KEY);
    if (parsed.pathname.includes("/ip_addresses/"))
      return {
        data: {
          attributes: {
            network: "192.0.2.0/24",
            as_owner: "Example",
            country: "ZZ",
          },
        },
      };
    return {
      data: {
        attributes: {
          last_analysis_stats: { malicious: 4 },
          last_dns_records: [{ type: "A", value: "192.0.2.10" }],
        },
      },
    };
  }
  if (host === "api.github.com") {
    assert.equal(headers.Authorization, undefined);
    if (parsed.pathname.endsWith("/keys"))
      return [
        {
          id: 7,
          key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnly comment",
        },
      ];
    if (parsed.pathname.endsWith("/events/public"))
      return [
        {
          type: "PushEvent",
          payload: {
            commits: [
              {
                message: "contact hidden@example.com",
                author: { email: "dev@example.com" },
              },
            ],
          },
        },
      ];
    return { login: "example-researcher" };
  }
  if (host === "en.gravatar.com")
    return {
      entry: [
        {
          displayName: "Alex Rivera",
          profileUrl: "https://gravatar.com/alex",
        },
      ],
    };
  if (host === "keybase.io")
    return {
      them: [
        {
          basics: { username: "example-researcher" },
          proofs_summary: {
            all: [
              {
                proof_type: "github",
                service_url: "https://github.com/example-researcher",
              },
            ],
          },
        },
      ],
    };
  if (host === "emailrep.io")
    return {
      email: "alex@example.com",
      details: { profiles: ["twitter", "github"] },
    };
  throw new Error("UNEXPECTED_HOST " + host);
}

test("passive adapters deduplicate one target and record keyless sources as gaps", async (t) => {
  const previousTrails = process.env.SECURITYTRAILS_API_KEY;
  const previousVirus = process.env.VIRUSTOTAL_API_KEY;
  process.env.SECURITYTRAILS_API_KEY = KEY;
  delete process.env.VIRUSTOTAL_API_KEY;
  delete process.env.GITHUB_TOKEN;
  const store = new Store();
  t.after(() => {
    store.close();
    if (previousTrails === undefined) delete process.env.SECURITYTRAILS_API_KEY;
    else process.env.SECURITYTRAILS_API_KEY = previousTrails;
    if (previousVirus === undefined) delete process.env.VIRUSTOTAL_API_KEY;
    else process.env.VIRUSTOTAL_API_KEY = previousVirus;
  });
  const seen = [];
  const engine = new Engine(
    {
      version: 1,
      scope: {
        domains: ["example.com"],
        excludeDomains: ["excluded.example.com"],
        emails: ["alex@example.com"],
        usernames: ["example-researcher"],
      },
      network: true,
      enabledAdapters: [
        "domain-rdap",
        "doh",
        "otx",
        "hackertarget",
        "urlscan",
        "securitytrails",
        "virustotal",
      ],
      limits: { minIntervalMs: 0, attempts: 1, cacheTtlSeconds: 0 },
    },
    store,
    {
      fetcher: async (url, options = {}) => {
        seen.push(new URL(url).hostname);
        const body = responseFor(url, options.headers ?? {});
        return new Response(
          typeof body === "string" ? body : JSON.stringify(body),
        );
      },
    },
  );
  const result = await engine.pipeline("example.com");
  assert.equal(result.status, "partial");
  assert.equal(
    result.coverage_gaps.some(
      (gap) => gap.source === "virustotal" && gap.reason === "missing_key",
    ),
    true,
  );
  assert.equal(seen.includes("www.virustotal.com"), false);
  assert.equal(seen.includes("127.0.0.1"), false);
  const names = store
    .query({ type: "domain" })
    .items.map((item) => item.value)
    .sort();
  assert.equal(names.includes("example.com"), true);
  assert.equal(names.includes("api.example.com"), true);
  assert.equal(names.includes("www.example.com"), true);
  assert.equal(names.includes("out.example.net"), false);
  assert.equal(names.includes("excluded.example.com"), false);
  const api = store
    .query({ type: "domain" })
    .items.find((item) => item.value === "api.example.com");
  assert.ok(api.sources.includes("otx"));
  assert.ok(api.sources.includes("hackertarget"));
  assert.equal(store.query({ type: "ip" }).total >= 1, true);
  assert.equal(JSON.stringify(store.runs()).includes(KEY), false);
  assert.equal(JSON.stringify(store.runs()).includes("token=secret"), false);
  assert.equal(JSON.stringify(store.runs()).includes("malicious"), false);
  const again = await engine.pipeline("example.com");
  assert.equal(again.correlation.target, "example.com");
  assert.equal(again.correlation.sources.length > 1, true);
});

test("domain RDAP refuses IP literals and non-HTTPS bootstrap URLs", () => {
  assert.equal(
    domainRdapBase("example.com", {
      services: [[["com"], ["http://127.0.0.1/", "https://rdap.example.net/"]]],
    }),
    "https://rdap.example.net/",
  );
  assert.throws(
    () =>
      domainRdapBase("example.com", {
        services: [[["com"], ["https://127.0.0.1/"]]],
      }),
    /RDAP_PROVIDER_NOT_FOUND/,
  );
});

test("username and email passive sources keep public data and drop message text", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(
    {
      version: 1,
      scope: {
        domains: ["example.com"],
        emails: ["alex@example.com"],
        usernames: ["example-researcher"],
      },
      network: true,
      enabledAdapters: [
        "github-keys",
        "github-events",
        "gravatar",
        "keybase",
        "emailrep",
      ],
      limits: { minIntervalMs: 0, attempts: 1, cacheTtlSeconds: 0 },
    },
    store,
    {
      fetcher: async (url, options = {}) => {
        const body = responseFor(url, options.headers ?? {});
        return new Response(JSON.stringify(body));
      },
    },
  );
  const people = await engine.pipeline("example-researcher");
  assert.equal(people.status, "completed");
  const emails = store.query({ type: "email" }).items.map((item) => item.value);
  assert.deepEqual(emails, ["dev@example.com"]);
  assert.equal(
    JSON.stringify(store.runs()).includes("hidden@example.com"),
    false,
  );
  assert.equal(JSON.stringify(store.runs()).includes("AAAAC3Nza"), false);
  const keys = store
    .query({ type: "profile" })
    .items.flatMap((item) => store.evidence(item.id).items);
  assert.equal(
    keys.some(
      (item) => item.evidence.fingerprint && item.evidence.key_id === "7",
    ),
    true,
  );
  const mail = await engine.run({
    adapter: "gravatar",
    target: "alex@example.com",
  });
  assert.equal(mail.status, "completed");
  const reputation = await engine.run({
    adapter: "emailrep",
    target: "alex@example.com",
  });
  assert.equal(reputation.status, "completed");
  const account = store
    .query({ type: "email" })
    .items.find((item) => item.value === "alex@example.com");
  assert.deepEqual(
    store.evidence(account.id).items[0].evidence.profiles.sort(),
    ["github", "twitter"],
  );
});

test("Shodan InternetDB enriches a discovered IP without treating CVEs as confirmed vulnerabilities", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  const engine = new Engine(
    {
      version: 1,
      scope: { domains: ["example.com"] },
      network: true,
      enabledAdapters: ["shodan-internetdb"],
      limits: { minIntervalMs: 0, attempts: 1 },
    },
    store,
    {
      fetcher: async (url) =>
        new Response(JSON.stringify(responseFor(url, {}))),
    },
  );
  engine.import({
    adapter: "dnsx",
    data: '{"host":"api.example.com","a":["192.0.2.10"]}\n',
  });
  const result = await engine.run({
    adapter: "shodan-internetdb",
    target: "192.0.2.10",
  });
  assert.equal(result.status, "completed");
  const ip = store.query({ type: "ip" }).items[0];
  const evidence = store
    .evidence(ip.id)
    .items.find((item) => item.source === "shodan-internetdb").evidence;
  assert.deepEqual(evidence.cves, ["CVE-2024-0001"]);
  assert.equal(
    evidence.verification,
    "internetdb_not_a_vulnerability_confirmation",
  );
  assert.equal(
    store.query({ type: "service" }).items[0].value,
    "api.example.com:443",
  );
});

test("a rate-limited passive source does not remove findings from another source", async (t) => {
  const store = new Store();
  t.after(() => store.close());
  let hacker = 0;
  const engine = new Engine(
    {
      version: 1,
      scope: { domains: ["example.com"] },
      network: true,
      enabledAdapters: ["otx", "hackertarget"],
      limits: { minIntervalMs: 0, attempts: 1, cacheTtlSeconds: 0 },
    },
    store,
    {
      fetcher: async (url) => {
        const host = new URL(url).hostname;
        if (host === "api.hackertarget.com") {
          hacker++;
          return new Response("API count exceeded", { status: 200 });
        }
        return new Response(JSON.stringify(responseFor(url, {})));
      },
    },
  );
  const result = await engine.pipeline("example.com");
  assert.equal(hacker, 1);
  assert.equal(
    result.coverage_gaps.some(
      (gap) => gap.source === "hackertarget" && gap.reason === "rate_limited",
    ),
    true,
  );
  assert.equal(
    store
      .query({ type: "domain" })
      .items.some((item) => item.value === "api.example.com"),
    true,
  );
});
