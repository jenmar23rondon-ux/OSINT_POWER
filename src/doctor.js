import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";
import { runProcess } from "./transport.js";
import { z } from "zod";

export const DoctorInput = z
  .object({ probe: z.boolean().default(true) })
  .strict();
export const BINARY_CONTRACTS = {
  subfinder: {
    command: "subfinder",
    version: ["-version", "-duc"],
    help: ["-h"],
    flags: ["-silent", "-rl", "-timeout", "-duc"],
  },
  dnsx: {
    command: "dnsx",
    version: ["-version", "-duc"],
    help: ["-h"],
    flags: ["-json", "-aaaa", "-rl", "-retry", "-duc"],
  },
  httpx: {
    command: "httpx",
    version: ["-version", "-duc"],
    help: ["-h"],
    flags: ["-silent", "-json", "-tech-detect", "-tls-grab", "-duc"],
  },
  naabu: {
    command: "naabu",
    version: ["-version", "-duc"],
    help: ["-h"],
    flags: ["-scan-type", "-rate", "-retries", "-json", "-duc"],
  },
  amass: {
    command: "amass",
    version: ["-version"],
    help: ["enum", "-h"],
    flags: ["-passive", "-nocolor", "-d"],
  },
  sherlock: {
    command: "sherlock",
    version: ["--version"],
    help: ["--help"],
    flags: ["--csv", "--folderoutput", "--site", "--local", "--timeout"],
  },
  theharvester: {
    command: "theHarvester",
    version: ["--help"],
    help: ["--help"],
    flags: ["--source", "--limit", "--filename", "--source-workers"],
  },
};
export function locateBinary(name) {
  const extensions = process.platform === "win32" ? [".exe"] : [""];
  for (const directory of (process.env.PATH ?? "")
    .split(delimiter)
    .filter(Boolean))
    for (const extension of extensions) {
      const path = join(directory, name + extension);
      try {
        accessSync(path, constants.X_OK);
        return path;
      } catch {
        /* Continue through PATH. */
      }
    }
  return null;
}
export async function doctor(engine, input = {}) {
  const { probe } = DoctorInput.parse(input);
  const binaries = [];
  for (const adapter of engine.config.enabledAdapters) {
    const contract = BINARY_CONTRACTS[adapter];
    if (!contract) continue;
    const path = (engine.dependencies.locateBinary ?? locateBinary)(
      contract.command,
    );
    const result = {
      adapter,
      path,
      installed: Boolean(path),
      version: null,
      compatibility: "not_probed",
      missing_flags: [],
    };
    if (!path) result.compatibility = "missing";
    else if (probe) {
      try {
        const runner = engine.dependencies.diagnosticRunner ?? runProcess;
        const limits = { timeoutMs: 3000, maxBytes: 65536 };
        const version = await runner(path, contract.version, limits, "", {
          captureStderr: true,
        });
        const help = await runner(path, contract.help, limits, "", {
          captureStderr: true,
        });
        result.version =
          version.match(/\b[vV]?\d+\.\d+(?:\.\d+)?\b/)?.[0] ?? null;
        result.missing_flags = contract.flags.filter(
          (flag) => !help.includes(flag),
        );
        result.compatibility = result.missing_flags.length
          ? "incompatible"
          : "flags_present";
      } catch {
        result.compatibility = "probe_failed";
      }
    }
    binaries.push(result);
  }
  const problems = binaries.filter((b) =>
    ["missing", "incompatible", "probe_failed"].includes(b.compatibility),
  );
  return {
    version: "0.3.0",
    status: problems.length ? "attention_required" : "completed",
    network_probe: false,
    database: {
      schema_version: engine.store.db.prepare("PRAGMA user_version").get()
        .user_version,
      resumable_jobs: engine.store.db
        .prepare(
          "SELECT COUNT(*) AS n FROM jobs WHERE status NOT IN ('completed','cancelled')",
        )
        .get().n,
      expired_leases: engine.store.db
        .prepare(
          "SELECT COUNT(*) AS n FROM jobs WHERE owner IS NOT NULL AND lease_until<=?",
        )
        .get(Date.now()).n,
    },
    binaries,
    credentials: { hibp_api_key_configured: Boolean(process.env.HIBP_API_KEY) },
    providers: engine.providers.health(),
    note: "Local version/help probes do not query targets or validate credentials. Flag presence does not certify runtime compatibility; use the native lab.",
  };
}
