import { Resolver } from "node:dns/promises";
import { request } from "node:https";
import { BlockList, isIP } from "node:net";
import { domain } from "./scope.js";

const blocked = new BlockList();
for (const [network, bits] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.31.196.0", 24],
  ["192.52.193.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["192.175.48.0", 24],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 3],
])
  blocked.addSubnet(network, bits);
for (const [network, bits] of [
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["2620:4f:8000::", 48],
  ["3fff::", 20],
])
  blocked.addSubnet(network, bits, "ipv6");
const globalUnicast = new BlockList();
globalUnicast.addSubnet("2000::", 3, "ipv6");

export function parseWebhookUrl(value) {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.hash ||
      url.port ||
      domain(url.hostname) !== url.hostname ||
      /(?:^|\.)(?:localhost|local|internal|home\.arpa|onion|invalid|test)$/.test(
        url.hostname,
      )
    )
      throw new Error();
    return url;
  } catch {
    throw new Error("WEBHOOK_URL_REJECTED");
  }
}

export function allowedWebhook(value, allowedUrls) {
  const url = parseWebhookUrl(value);
  if (!allowedUrls.some((allowed) => new URL(allowed).href === url.href))
    throw new Error("WEBHOOK_DESTINATION_NOT_ALLOWED");
  return url;
}

function publicAddress(address) {
  const family = isIP(address);
  if (family === 4) return !blocked.check(address);
  return (
    family === 6 &&
    !address.includes("%") &&
    globalUnicast.check(address, "ipv6") &&
    !blocked.check(address, "ipv6")
  );
}

async function resolveAddresses(hostname, signal) {
  signal.throwIfAborted();
  const resolver = new Resolver({ timeout: 2500, tries: 1 });
  const cancel = () => resolver.cancel();
  signal.addEventListener("abort", cancel, { once: true });
  try {
    const absent = (error) => {
      if (["ENODATA", "ENOTFOUND"].includes(error.code)) return [];
      throw error;
    };
    const fqdn = hostname + ".";
    const [ipv4, ipv6] = await Promise.all([
      resolver.resolve4(fqdn).catch(absent),
      resolver.resolve6(fqdn).catch(absent),
    ]);
    return [...ipv4, ...ipv6];
  } finally {
    signal.removeEventListener("abort", cancel);
    cancel();
  }
}

export async function postWebhook(url, options, dependencies = {}) {
  const addresses = await (dependencies.webhookResolve ?? resolveAddresses)(
    url.hostname,
    options.signal,
  );
  options.signal.throwIfAborted();
  if (!addresses.length || !addresses.every(publicAddress))
    throw new Error("WEBHOOK_ADDRESS_REJECTED");
  const address = addresses[0];
  return new Promise((resolve, reject) => {
    // Use a numeric socket destination. TLS and Host still authenticate the approved hostname.
    const req = (dependencies.webhookRequest ?? request)(
      {
        hostname: address,
        family: isIP(address),
        servername: url.hostname,
        rejectUnauthorized: true,
        agent: false,
        path: url.pathname + url.search,
        method: "POST",
        headers: {
          ...options.headers,
          host: url.hostname,
          "content-length": Buffer.byteLength(options.body),
        },
        signal: options.signal,
      },
      (response) => {
        const status = response.statusCode;
        const retry = response.headers["retry-after"];
        resolve({
          status,
          ok: status >= 200 && status < 300,
          headers: new Headers(
            typeof retry === "string" ? { "retry-after": retry } : {},
          ),
        });
        // The status is sufficient. Discard the body without following redirects.
        response.destroy();
      },
    );
    req.once("error", reject);
    req.end(options.body);
  });
}
