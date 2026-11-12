import { open, lstat } from "node:fs/promises";
import { Worker } from "node:worker_threads";
import { z } from "zod";

export const MAX_LOCAL_IMAGE_BYTES = 16 * 1024 * 1024;
const MAX_MCP_IMAGE_BYTES = 2 * 1024 * 1024;
const MAX_MCP_BASE64_LENGTH = Math.ceil(MAX_MCP_IMAGE_BYTES / 3) * 4;
const WORKER_TIMEOUT_MS = 5000;
let workerActive = false;

export const AnalyzeImageInput = z
  .object({
    data_base64: z.string().min(4).max(MAX_MCP_BASE64_LENGTH),
  })
  .strict();

const dimension = z.number().int().positive().max(1_000_000);
export const AnalyzeImageResult = z
  .object({
    format: z.enum(["jpeg", "png", "webp", "tiff"]),
    bytes: z.number().int().positive().max(MAX_LOCAL_IMAGE_BYTES),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    dimensions: z.object({ width: dimension, height: dimension }).strict(),
    metadata: z
      .array(
        z
          .object({
            group: z.enum(["exif", "xmp", "iptc"]),
            tag: z.enum([
              "Make",
              "Model",
              "Software",
              "DateTimeOriginal",
              "DateTime",
              "DateTimeDigitized",
              "CreateDate",
              "ModifyDate",
              "CreatorTool",
              "Date Created",
              "Time Created",
            ]),
            value: z.string().max(120),
          })
          .strict(),
      )
      .max(16),
    gps_tags_present: z.boolean(),
    inconsistencies: z.array(
      z.enum(["exif_dimensions_differ", "capture_after_modification"]),
    ),
    authenticity: z.literal("unassessed"),
    metadata_trust: z.literal("untrusted"),
    network: z.literal(false),
  })
  .strict();

export async function inspectImage(bytes, signal) {
  if (!bytes.length || bytes.length > MAX_LOCAL_IMAGE_BYTES)
    throw new Error("INVALID_IMAGE_SIZE");
  if (signal?.aborted) throw new Error("CANCELLED");
  if (workerActive) throw new Error("IMAGE_ANALYZER_BUSY");
  workerActive = true;
  let worker;
  let timer;
  let onAbort;
  try {
    const input = Uint8Array.from(bytes);
    worker = new Worker(new URL("./image-worker.js", import.meta.url), {
      workerData: input,
      transferList: [input.buffer],
      resourceLimits: {
        maxOldGenerationSizeMb: 64,
        maxYoungGenerationSizeMb: 16,
        stackSizeMb: 2,
      },
      execArgv: [],
      env: {},
      stdout: true,
      stderr: true,
    });
    worker.stdout.resume();
    worker.stderr.resume();
    const response = await new Promise((resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error("IMAGE_PARSE_TIMEOUT")),
        WORKER_TIMEOUT_MS,
      );
      onAbort = () => reject(new Error("CANCELLED"));
      signal?.addEventListener("abort", onAbort, { once: true });
      worker.once("message", resolve);
      worker.once("error", () => reject(new Error("IMAGE_PARSE_FAILED")));
      worker.once("exit", () => reject(new Error("IMAGE_PARSE_FAILED")));
    });
    if (response.error) throw new Error(response.error);
    const result = AnalyzeImageResult.safeParse(response.result);
    if (!result.success) throw new Error("IMAGE_PARSE_FAILED");
    return result.data;
  } finally {
    clearTimeout(timer);
    if (onAbort) signal?.removeEventListener("abort", onAbort);
    try {
      if (worker) await worker.terminate();
    } finally {
      workerActive = false;
    }
  }
}

export function analyzeImage(input, signal) {
  const { data_base64 } = AnalyzeImageInput.parse(input);
  return inspectImage(decodeImageBytes(data_base64), signal);
}

export function decodeImageBytes(dataBase64) {
  const bytes = Buffer.from(dataBase64, "base64");
  if (
    !bytes.length ||
    bytes.length > MAX_MCP_IMAGE_BYTES ||
    bytes.toString("base64") !== dataBase64
  )
    throw new Error("INVALID_IMAGE_BASE64");
  return bytes;
}

export async function readImageFile(path) {
  if (!path || /^[\\/]{2}/.test(path)) throw new Error("IMAGE_FILE_REQUIRED");
  if (!(await lstat(path)).isFile()) throw new Error("IMAGE_FILE_REQUIRED");
  const file = await open(path, "r");
  try {
    const stat = await file.stat();
    if (!stat.isFile() || !stat.size || stat.size > MAX_LOCAL_IMAGE_BYTES)
      throw new Error("INVALID_IMAGE_SIZE");
    const bytes = Buffer.alloc(stat.size + 1);
    let size = 0;
    while (size < bytes.length) {
      const { bytesRead } = await file.read(
        bytes,
        size,
        bytes.length - size,
        size,
      );
      if (!bytesRead) break;
      size += bytesRead;
    }
    if (size !== stat.size || (await file.stat()).mtimeMs !== stat.mtimeMs)
      throw new Error("IMAGE_CHANGED_DURING_READ");
    return bytes.subarray(0, size);
  } finally {
    await file.close();
  }
}

export async function inspectImageFile(path) {
  return inspectImage(await readImageFile(path));
}
