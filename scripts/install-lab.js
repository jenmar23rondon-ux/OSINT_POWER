import { readFile, mkdir, writeFile, chmod, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const platform =
  process.platform === "win32"
    ? "windows"
    : process.platform === "linux"
      ? "linux"
      : null;
if (!platform || process.arch !== "x64")
  throw new Error("NATIVE_LAB_PLATFORM_UNSUPPORTED");
const manifest = JSON.parse(
  await readFile(new URL("../native-tools.lock.json", import.meta.url), "utf8"),
);
const directory = fileURLToPath(new URL("../.lab/", import.meta.url));
await mkdir(directory, { recursive: true });
for (const [name, definition] of Object.entries(manifest)) {
  if (platform === "windows" && name === "naabu") continue; // Npcap is not installed or modified by this project.
  const archive = definition.platforms[platform];
  const response = await fetch(archive.url, {
    signal: AbortSignal.timeout(120000),
  });
  if (!response.ok) throw new Error("LAB_DOWNLOAD_FAILED");
  const bytes = Buffer.from(await response.arrayBuffer());
  if (createHash("sha256").update(bytes).digest("hex") !== archive.sha256)
    throw new Error("LAB_CHECKSUM_MISMATCH");
  const path = join(directory, name + ".zip"),
    binary = name + (platform === "windows" ? ".exe" : "");
  await writeFile(path, bytes);
  try {
    const command = platform === "linux" ? "unzip" : "tar";
    const args =
      platform === "linux"
        ? ["-o", "-j", path, binary, "-d", directory]
        : ["-xf", path, "-C", directory, binary];
    await promisify(execFile)(command, args, {
      windowsHide: true,
    });
    await chmod(join(directory, binary), 0o755);
  } finally {
    await rm(path, { force: true });
  }
  process.stdout.write(`${name} ${definition.version}: verified\n`);
}
