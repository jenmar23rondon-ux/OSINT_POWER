import { fetchText, runProcess } from "./transport.js";
import { collectExtra } from "./collectors.js";
import { collectDiscovery, HISTORICAL_ADAPTERS } from "./discovery.js";

export const ADAPTERS = {
  certspotter: {
    mode: "passive",
    kind: "api",
    description:
      "One CT issuance page; persistent after cursor, optional CERTSPOTTER_API_KEY",
  },
  wayback: {
    mode: "passive",
    kind: "api",
    description:
      "One historical CDX URL page; persistent resume key, no archived page downloads",
  },
  sherlock: {
    mode: "passive",
    kind: "binary",
    description:
      "One scoped username, 1-3 configured professional sites; CSV output",
  },
  theharvester: {
    mode: "passive",
    kind: "binary",
    description:
      "Configured crtsh/certspotter sources only; bounded JSON report",
  },
  mx: {
    mode: "active",
    kind: "dns",
    description: "DNS MX only; mailbox and catch-all remain unknown",
  },
  rdap: {
    mode: "passive",
    kind: "api",
    description:
      "IANA bootstrap to allowlisted RIRs; registered network is not ownership or location",
  },
  routing: {
    mode: "passive",
    kind: "api",
    description: "RIPE RIS prefix and origin ASN; never expands active scope",
  },
  "github-profile": {
    mode: "passive",
    kind: "api",
    description:
      "Public GitHub profile for one scoped alias; no employment verification",
  },
  crtsh: {
    mode: "passive",
    kind: "api",
    description:
      "Certificate Transparency names; certificate presence is not ownership",
  },
  subfinder: {
    mode: "passive",
    kind: "binary",
    description: "Passive sources; upstream keys/config belong to subfinder",
  },
  amass: {
    mode: "passive",
    kind: "binary",
    description:
      "Legacy enum -passive -nocolor interface; verify your installed version",
  },
  dnsx: {
    mode: "active",
    kind: "binary",
    description: "A/AAAA resolution for one configured host",
  },
  httpx: {
    mode: "active",
    kind: "binary",
    description:
      "ProjectDiscovery httpx; HTTP status and technology, no redirect following",
  },
  naabu: {
    mode: "active",
    kind: "binary",
    description: "TCP connect on explicit configured ports",
  },
  hibp: {
    mode: "passive",
    kind: "api",
    description: "Breach names only; exact configured account and HIBP_API_KEY",
  },
};
export function commandFor(adapter, target, limits) {
  const rate = String(limits.requestRate);
  const seconds = String(Math.max(1, Math.floor(limits.timeoutMs / 1000)));
  if (adapter === "subfinder")
    return {
      command: "subfinder",
      args: ["-d", target, "-silent", "-rl", rate, "-timeout", seconds, "-duc"],
    };
  if (adapter === "amass")
    return {
      command: "amass",
      args: ["enum", "-passive", "-nocolor", "-d", target],
    };
  if (adapter === "dnsx")
    return {
      command: "dnsx",
      args: [
        "-silent",
        "-json",
        "-a",
        "-aaaa",
        "-rl",
        rate,
        "-t",
        "1",
        "-retry",
        "1",
        "-duc",
      ],
      stdin: target + "\n",
    };
  if (adapter === "httpx")
    return {
      command: "httpx",
      args: [
        "-silent",
        "-json",
        "-status-code",
        "-tech-detect",
        "-title",
        "-tls-grab",
        "-rl",
        rate,
        "-threads",
        "1",
        "-timeout",
        seconds,
        "-retries",
        "0",
        "-duc",
      ],
      stdin: target + "\n",
    };
  if (adapter === "naabu")
    return {
      command: "naabu",
      args: [
        "-host",
        target,
        "-p",
        limits.ports.join(","),
        "-scan-type",
        "c",
        "-rate",
        rate,
        "-c",
        "1",
        "-retries",
        "1",
        "-silent",
        "-json",
        "-duc",
      ],
    };
  throw new Error("UNKNOWN_BINARY");
}
export async function collect(adapter, target, config, dependencies = {}) {
  if (HISTORICAL_ADAPTERS.includes(adapter))
    return collectDiscovery(adapter, target, config, dependencies);
  if (
    [
      "sherlock",
      "theharvester",
      "mx",
      "rdap",
      "routing",
      "github-profile",
    ].includes(adapter)
  )
    return collectExtra(adapter, target, config, dependencies);
  const { fetcher = fetch, runner = runProcess } = dependencies;
  if (adapter === "crtsh")
    return fetchText(
      `https://crt.sh/?q=${encodeURIComponent(`%.${target}`)}&output=json`,
      config.limits,
      {},
      fetcher,
    );
  if (adapter === "hibp") {
    const key = process.env.HIBP_API_KEY;
    if (!key) throw new Error("HIBP_KEY_MISSING");
    return fetchText(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(target)}?truncateResponse=false`,
      config.limits,
      { "hibp-api-key": key },
      fetcher,
    );
  }
  const { command, args, stdin } = commandFor(adapter, target, config.limits);
  return runner(command, args, config.limits, stdin);
}
