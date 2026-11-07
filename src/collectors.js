import { Resolver } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { mkdtemp, readFile, stat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { fetchText, runProcess } from "./transport.js";

const RIR_HOSTS = new Set([
  "rdap.arin.net",
  "rdap.db.ripe.net",
  "rdap.apnic.net",
  "rdap.lacnic.net",
  "rdap.afrinic.net",
]);
export function rdapBase(ip, bootstrap) {
  const family = isIP(ip) === 6 ? "ipv6" : "ipv4";
  const matches = [];
  for (const [prefixes, urls] of bootstrap.services ?? [])
    for (const prefix of prefixes) {
      const [address, bits] = prefix.split("/");
      try {
        const list = new BlockList();
        list.addSubnet(address, Number(bits), family);
        if (list.check(ip, family))
          for (const value of urls) {
            const url = new URL(value);
            if (
              url.protocol === "https:" &&
              RIR_HOSTS.has(url.hostname) &&
              !url.username &&
              !url.password &&
              !url.port
            )
              matches.push({ url: url.href, bits: Number(bits) });
          }
      } catch {
        /* Ignore malformed bootstrap entries; never accept a response-controlled URL. */
      }
    }
  const base = matches.sort((a, b) => b.bits - a.bits)[0]?.url;
  if (!base) throw new Error("RDAP_PROVIDER_NOT_FOUND");
  return base;
}
export async function collectMX(target, config, dependencies = {}) {
  const resolver =
    dependencies.resolver ??
    new Resolver({ timeout: config.limits.timeoutMs, tries: 1 });
  const timer = setTimeout(() => resolver.cancel(), config.limits.timeoutMs);
  try {
    let records;
    let status;
    try {
      records = await resolver.resolveMx(target);
      status = records.some((r) => r.exchange === "" || r.exchange === ".")
        ? "null_mx"
        : records.length
          ? "mx_present"
          : "no_explicit_mx";
    } catch (error) {
      if (!["ENODATA", "ENOTFOUND"].includes(error.code))
        throw new Error("DNS_LOOKUP_FAILED");
      records = [];
      status = error.code === "ENOTFOUND" ? "nxdomain" : "no_explicit_mx";
    }
    return JSON.stringify({
      domain: target,
      records: records.slice(0, 20),
      status,
      mailbox: "unknown",
      catch_all: "unknown",
    });
  } finally {
    clearTimeout(timer);
  }
}
export async function collectExtra(adapter, target, config, dependencies = {}) {
  const fetcher = dependencies.fetcher ?? fetch;
  if (adapter === "mx") return collectMX(target, config, dependencies);
  if (adapter === "routing")
    return fetchText(
      `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(target)}`,
      config.limits,
      {},
      fetcher,
    );
  if (adapter === "rdap") {
    const bootstrap = JSON.parse(
      await fetchText(
        `https://data.iana.org/rdap/ipv${isIP(target)}.json`,
        config.limits,
        {},
        fetcher,
      ),
    );
    const base = rdapBase(target, bootstrap);
    return fetchText(
      new URL(
        `ip/${encodeURIComponent(target)}`,
        base.endsWith("/") ? base : base + "/",
      ).href,
      config.limits,
      {},
      fetcher,
    );
  }
  if (adapter === "github-profile")
    return fetchText(
      `https://api.github.com/users/${encodeURIComponent(target)}`,
      config.limits,
      { Accept: "application/vnd.github+json" },
      fetcher,
    );
  if (!["sherlock", "theharvester"].includes(adapter))
    throw new Error("UNKNOWN_COLLECTOR");
  const directory = await mkdtemp(join(tmpdir(), "osint-power-collector-"));
  try {
    let filename;
    let command;
    let args;
    if (adapter === "sherlock") {
      filename = join(directory, `${target}.csv`);
      command = "sherlock";
      args = [
        target,
        "--csv",
        "--folderoutput",
        directory,
        "--local",
        "--timeout",
        String(Math.max(1, Math.floor(config.limits.timeoutMs / 1000))),
        ...config.collectors.sherlockSites.flatMap((site) => ["--site", site]),
      ];
    } else {
      const prefix = join(directory, "report");
      filename = prefix + ".json";
      command = "theHarvester";
      args = [
        "-d",
        target,
        "-b",
        config.collectors.harvesterSources.join(","),
        "-l",
        String(Math.min(100, config.limits.maxRecords)),
        "-j",
        "1",
        "-f",
        prefix,
      ];
    }
    await (dependencies.runner ?? runProcess)(command, args, config.limits);
    if ((await stat(filename)).size > config.limits.maxBytes)
      throw new Error("RESPONSE_TOO_LARGE");
    return await readFile(filename, "utf8");
  } finally {
    const safe = resolve(directory);
    if (
      !safe.startsWith(resolve(tmpdir()) + sep) ||
      !safe.split(sep).at(-1).startsWith("osint-power-collector-")
    )
      throw new Error("INVALID_TEMP_PATH");
    await rm(safe, { recursive: true, force: true });
  }
}
