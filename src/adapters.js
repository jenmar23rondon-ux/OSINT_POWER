import { fetchText, runProcess } from "./transport.js";

export const ADAPTERS = {
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
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(target)}?truncateResponse=true`,
      config.limits,
      { "hibp-api-key": key },
      fetcher,
    );
  }
  const { command, args, stdin } = commandFor(adapter, target, config.limits);
  return runner(command, args, config.limits, stdin);
}
