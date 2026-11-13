import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { z } from "zod";
import { locateBinary } from "./doctor.js";
import { imageFormat } from "./image-format.js";
import {
  AnalyzeImageInput,
  decodeImageBytes,
  inspectImage,
  readImageFile,
} from "./image-forensics.js";
import { OperationError, runProcess } from "./transport.js";

const MAX_DIRECTORY_FILES = 64;
const EXTENSIONS = {
  jpeg: ".jpg",
  png: ".png",
  webp: ".webp",
  tiff: ".tif",
};
const KEEP_JPEG_APP = new Set([0xe0, 0xee]);
const PNG_TEXT = new Set(["tEXt", "zTXt", "iTXt", "eXIf", "tIME"]);
const WEBP_META = new Set(["EXIF", "XMP "]);
const sha = z.string().regex(/^[a-f0-9]{64}$/);
const dimension = z.number().int().positive().max(1_000_000);
const findingTag = z.enum([
  "GPSLatitude",
  "GPSLongitude",
  "GPSAltitude",
  "Artist",
  "Copyright",
  "CameraOwnerName",
  "OwnerName",
  "BodySerialNumber",
  "SerialNumber",
  "LensSerialNumber",
  "InternalSerialNumber",
  "ImageUniqueID",
  "Creator",
  "Rights",
  "By-line",
  "Copyright Notice",
  "Credit",
  "Make",
  "Model",
  "LensMake",
  "LensModel",
  "Software",
  "CreatorTool",
  "DateTime",
  "DateTimeOriginal",
  "DateTimeDigitized",
  "CreateDate",
  "ModifyDate",
  "Date Created",
  "Time Created",
  "GPSDateStamp",
  "GPSTimeStamp",
]);

export const PrivacyCoreResult = z
  .object({
    purpose: z.literal("own-photo-privacy-check"),
    network: z.literal(false),
    persisted: z.literal(false),
    format: z.enum(["jpeg", "png", "webp", "tiff"]),
    bytes: z.number().int().positive(),
    sha256: sha,
    dimensions: z.object({ width: dimension, height: dimension }).strict(),
    rating: z.enum(["high", "medium", "low", "none"]),
    counts: z
      .object({
        high: z.number().int().nonnegative().max(48),
        medium: z.number().int().nonnegative().max(48),
        low: z.number().int().nonnegative().max(48),
      })
      .strict(),
    gps: z
      .object({
        present: z.boolean(),
        latitude: z.number().finite().min(-90).max(90).nullable(),
        longitude: z.number().finite().min(-180).max(180).nullable(),
        altitude_meters: z.number().finite().min(-20000).max(20000).nullable(),
      })
      .strict(),
    findings: z
      .array(
        z
          .object({
            group: z.enum(["exif", "xmp", "iptc"]),
            tag: findingTag,
            risk: z.enum(["high", "medium", "low"]),
            value: z.string().min(1).max(120),
          })
          .strict(),
      )
      .max(48),
    metadata_trust: z.literal("untrusted"),
  })
  .strict();

const scrubSummary = z
  .object({
    backend: z.literal("builtin"),
    clean: z.literal(true),
    sha256: sha,
    rating: z.literal("none"),
    scrubbed_base64: AnalyzeImageInput.shape.data_base64,
  })
  .strict();

export const PrivacyCheckImageResult = PrivacyCoreResult.extend({
  file: z.string().min(1).max(255).nullable(),
  scrub: scrubSummary.nullable(),
}).strict();

export const PrivacyCheckImageInput = z
  .object({
    data_base64: AnalyzeImageInput.shape.data_base64,
    scrub: z.boolean().default(false),
  })
  .strict();

function samePath(left, right) {
  const a = resolve(left);
  const b = resolve(right);
  return process.platform === "win32"
    ? a.toLowerCase() === b.toLowerCase()
    : a === b;
}

export function isPrivacyClean(report) {
  return (
    report.rating === "none" &&
    report.findings.length === 0 &&
    report.gps.present === false &&
    report.gps.latitude === null &&
    report.gps.longitude === null &&
    report.gps.altitude_meters === null
  );
}

export function checkImageBytes(bytes, signal) {
  return inspectImage(bytes, signal, {
    mode: "privacy",
    schema: PrivacyCoreResult,
  });
}

function indexOfEoi(bytes, from) {
  for (let i = from; i + 1 < bytes.length; i++) {
    if (bytes[i] !== 0xff) continue;
    const next = bytes[i + 1];
    if (next === 0x00) {
      i += 1;
      continue;
    }
    if (next === 0xd9) return i;
  }
  return -1;
}

export function stripJpegMetadata(bytes) {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8)
    throw new Error("SCRUB_UNSUPPORTED");
  const parts = [Buffer.from([0xff, 0xd8])];
  let i = 2;
  while (i < bytes.length) {
    if (bytes[i] !== 0xff) throw new Error("SCRUB_UNSUPPORTED");
    let markerStart = i;
    i += 1;
    while (i < bytes.length && bytes[i] === 0xff) {
      markerStart = i;
      i += 1;
    }
    if (i >= bytes.length) throw new Error("SCRUB_UNSUPPORTED");
    const marker = bytes[i];
    i += 1;
    if (marker === 0xd9) {
      parts.push(Buffer.from([0xff, 0xd9]));
      break;
    }
    if (marker === 0x00 || (marker >= 0xd0 && marker <= 0xd7)) {
      parts.push(Buffer.from([0xff, marker]));
      continue;
    }
    if (i + 2 > bytes.length) throw new Error("SCRUB_UNSUPPORTED");
    const length = bytes.readUInt16BE(i);
    const segmentEnd = i + length;
    if (length < 2 || segmentEnd > bytes.length)
      throw new Error("SCRUB_UNSUPPORTED");
    if (marker === 0xda) {
      const eoi = indexOfEoi(bytes, segmentEnd);
      if (eoi < 0) throw new Error("SCRUB_UNSUPPORTED");
      parts.push(bytes.subarray(markerStart, eoi + 2));
      break;
    }
    const drop =
      marker === 0xfe ||
      (marker >= 0xe0 && marker <= 0xef && !KEEP_JPEG_APP.has(marker));
    if (!drop) parts.push(bytes.subarray(markerStart, segmentEnd));
    i = segmentEnd;
  }
  const stripped = Buffer.concat(parts);
  if (
    stripped.length < 4 ||
    stripped.at(-2) !== 0xff ||
    stripped.at(-1) !== 0xd9
  )
    throw new Error("SCRUB_UNSUPPORTED");
  return stripped;
}

export function stripPngMetadata(bytes) {
  const signature = Buffer.from("89504e470d0a1a0a", "hex");
  if (!bytes.subarray(0, 8).equals(signature))
    throw new Error("SCRUB_UNSUPPORTED");
  const parts = [bytes.subarray(0, 8)];
  let i = 8;
  let ended = false;
  while (i + 12 <= bytes.length) {
    const length = bytes.readUInt32BE(i);
    const type = bytes.toString("ascii", i + 4, i + 8);
    const end = i + 12 + length;
    if (end > bytes.length) throw new Error("SCRUB_UNSUPPORTED");
    if (!PNG_TEXT.has(type)) parts.push(bytes.subarray(i, end));
    i = end;
    if (type === "IEND") {
      ended = true;
      break;
    }
  }
  if (!ended) throw new Error("SCRUB_UNSUPPORTED");
  return Buffer.concat(parts);
}

export function stripWebpMetadata(bytes) {
  if (
    bytes.toString("ascii", 0, 4) !== "RIFF" ||
    bytes.toString("ascii", 8, 12) !== "WEBP"
  )
    throw new Error("SCRUB_UNSUPPORTED");
  const parts = [];
  let i = 12;
  while (i + 8 <= bytes.length) {
    const type = bytes.toString("ascii", i, i + 4);
    const size = bytes.readUInt32LE(i + 4);
    const end = i + 8 + size + (size % 2);
    if (end > bytes.length) throw new Error("SCRUB_UNSUPPORTED");
    if (!WEBP_META.has(type)) parts.push(bytes.subarray(i, end));
    i = end;
  }
  if (i !== bytes.length) throw new Error("SCRUB_UNSUPPORTED");
  const body = Buffer.concat(parts);
  const stripped = Buffer.alloc(12 + body.length);
  stripped.write("RIFF", 0, "ascii");
  stripped.writeUInt32LE(body.length + 4, 4);
  stripped.write("WEBP", 8, "ascii");
  body.copy(stripped, 12);
  return stripped;
}

export function stripImageMetadata(bytes) {
  const format = imageFormat(bytes);
  if (format === "jpeg") return stripJpegMetadata(bytes);
  if (format === "png") return stripPngMetadata(bytes);
  if (format === "webp") return stripWebpMetadata(bytes);
  throw new Error("SCRUB_UNSUPPORTED");
}

async function withTempCopy(bytes, extension, run) {
  const directory = await mkdtemp(join(tmpdir(), "osint-privacy-"));
  try {
    const source = join(directory, "source" + extension);
    await writeFile(source, bytes, { mode: 0o600 });
    return await run(directory, source);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function asScrubError(error) {
  if (error instanceof OperationError) {
    if (
      error.code === "TOOL_NOT_INSTALLED" ||
      error.code === "REJECTED_ARGUMENT"
    )
      return new Error(error.code);
    return new Error("SCRUB_FAILED");
  }
  if (/^[A-Z][A-Z_0-9]{1,79}$/.test(error?.message ?? "")) return error;
  return new Error("SCRUB_FAILED");
}

async function scrubWithExiftool(bytes, extension) {
  const binary = locateBinary("exiftool");
  if (!binary) throw new Error("TOOL_NOT_INSTALLED");
  try {
    return await withTempCopy(bytes, extension, async (directory, source) => {
      const output = join(directory, "scrubbed" + extension);
      // -o writes a new file. The source here is a temp copy, never the original.
      await runProcess(
        binary,
        ["-all=", "-o", output, source],
        { timeoutMs: 15000, maxBytes: 1024 * 1024 },
        "",
        { allow: [binary] },
      );
      return await readFile(output);
    });
  } catch (error) {
    throw asScrubError(error);
  }
}

async function scrubWithMat2(bytes, extension) {
  const binary = locateBinary("mat2");
  if (!binary) throw new Error("TOOL_NOT_INSTALLED");
  try {
    return await withTempCopy(bytes, extension, async (directory, source) => {
      await runProcess(
        binary,
        [source],
        { timeoutMs: 20000, maxBytes: 1024 * 1024 },
        "",
        { allow: [binary] },
      );
      const cleaned = join(directory, "source.cleaned" + extension);
      return await readFile(cleaned);
    });
  } catch (error) {
    throw asScrubError(error);
  }
}

async function produceStripped(bytes, backend) {
  if (!["builtin", "exiftool", "mat2"].includes(backend))
    throw new Error("INVALID_PRIVACY_BACKEND");
  const format = imageFormat(bytes);
  if (backend === "builtin") return stripImageMetadata(bytes);
  const extension = EXTENSIONS[format];
  if (!extension) throw new Error("SCRUB_UNSUPPORTED");
  if (backend === "exiftool") return scrubWithExiftool(bytes, extension);
  return scrubWithMat2(bytes, extension);
}

async function assertNewFile(path) {
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (info.isDirectory()) throw new Error("OUTPUT_IS_DIRECTORY");
  throw new Error("OUTPUT_EXISTS");
}

async function unchanged(path, before, beforeStat) {
  const after = await readFile(path);
  const afterStat = await stat(path);
  if (
    !after.equals(before) ||
    afterStat.size !== beforeStat.size ||
    afterStat.mtimeMs !== beforeStat.mtimeMs
  )
    throw new Error("ORIGINAL_MODIFIED");
}

export async function checkImageFile(path) {
  const bytes = await readImageFile(path);
  const report = await checkImageBytes(bytes);
  return { ...report, file: basename(path) };
}

export async function privacyCheckImage(input, signal) {
  const parsed = PrivacyCheckImageInput.parse(input);
  const bytes = decodeImageBytes(parsed.data_base64);
  const report = await checkImageBytes(bytes, signal);
  if (!parsed.scrub)
    return PrivacyCheckImageResult.parse({
      ...report,
      file: null,
      scrub: null,
    });
  const stripped = stripImageMetadata(bytes);
  const after = await checkImageBytes(stripped, signal);
  if (!isPrivacyClean(after)) throw new Error("SCRUB_INCOMPLETE");
  return PrivacyCheckImageResult.parse({
    ...report,
    file: null,
    scrub: {
      backend: "builtin",
      clean: true,
      sha256: after.sha256,
      rating: "none",
      scrubbed_base64: Buffer.from(stripped).toString("base64"),
    },
  });
}

function scrubResult(file, output, backend, before, after, clean) {
  return {
    purpose: "own-photo-privacy-check",
    network: false,
    persisted: false,
    status: clean ? "completed" : "failed",
    ...(clean ? {} : { code: "SCRUB_INCOMPLETE" }),
    backend,
    file,
    output,
    original_sha256: before.sha256,
    output_sha256: after.sha256,
    original_unchanged: true,
    clean,
    rating_before: before.rating,
    rating_after: after.rating,
    gps_after: after.gps,
    findings_after: after.findings,
  };
}

export async function scrubImageFile(path, output, backend = "builtin") {
  if (!output) throw new Error("SCRUB_OUTPUT_REQUIRED");
  if (samePath(path, output)) throw new Error("OUTPUT_IS_INPUT");
  let outputReal = null;
  try {
    outputReal = await realpath(output);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (outputReal && samePath(outputReal, await realpath(path)))
    throw new Error("OUTPUT_IS_INPUT");
  await assertNewFile(output);
  const beforeStat = await stat(path);
  const bytes = await readImageFile(path);
  const before = await checkImageBytes(bytes);
  const stripped = Buffer.from(await produceStripped(bytes, backend));
  await unchanged(path, bytes, beforeStat);
  const preview = await checkImageBytes(stripped);
  try {
    await writeFile(output, stripped, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error("OUTPUT_EXISTS");
    if (error.code === "ENOENT") throw new Error("FILE_NOT_FOUND");
    throw error;
  }
  await unchanged(path, bytes, beforeStat);
  const written = await readImageFile(output);
  if (!written.equals(stripped)) throw new Error("SCRUB_INCOMPLETE");
  const after = await checkImageBytes(written);
  return scrubResult(
    basename(path),
    output,
    backend,
    before,
    after,
    isPrivacyClean(preview) && isPrivacyClean(after),
  );
}

async function imagePaths(directory) {
  let info;
  try {
    info = await lstat(directory);
  } catch (error) {
    if (error.code === "ENOENT") throw new Error("FILE_NOT_FOUND");
    throw error;
  }
  if (!info.isDirectory()) throw new Error("DIRECTORY_REQUIRED");
  const entries = await readdir(directory, { withFileTypes: true });
  const files = entries
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();
  if (files.length > MAX_DIRECTORY_FILES) throw new Error("TOO_MANY_IMAGES");
  return files;
}

export async function checkImageDirectory(directory) {
  const names = await imagePaths(directory);
  const files = [];
  const skipped = [];
  for (const name of names) {
    try {
      files.push(await checkImageFile(join(directory, name)));
    } catch (error) {
      if (error.message === "UNSUPPORTED_IMAGE_FORMAT") skipped.push(name);
      else
        files.push({
          file: name,
          code: /^[A-Z][A-Z_0-9]{1,79}$/.test(error.message)
            ? error.message
            : "IMAGE_PARSE_FAILED",
        });
    }
  }
  if (!files.length) throw new Error("IMAGE_FILE_REQUIRED");
  const failed = files.some((file) => file.code);
  return {
    purpose: "own-photo-privacy-check",
    network: false,
    persisted: false,
    status: failed ? "partial" : "completed",
    count: files.length,
    skipped,
    files,
  };
}

export async function scrubImageDirectory(
  directory,
  output,
  backend = "builtin",
) {
  if (!output) throw new Error("SCRUB_OUTPUT_REQUIRED");
  if (samePath(directory, output)) throw new Error("OUTPUT_IS_INPUT");
  const names = await imagePaths(directory);
  try {
    await mkdir(output, { recursive: true, mode: 0o700 });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error("OUTPUT_EXISTS");
    throw error;
  }
  const outputInfo = await lstat(output);
  if (!outputInfo.isDirectory()) throw new Error("OUTPUT_IS_DIRECTORY");
  const files = [];
  const skipped = [];
  for (const name of names) {
    const source = join(directory, name);
    const destination = join(output, name);
    if (samePath(source, destination)) throw new Error("OUTPUT_IS_INPUT");
    try {
      files.push(await scrubImageFile(source, destination, backend));
    } catch (error) {
      if (error.message === "UNSUPPORTED_IMAGE_FORMAT") skipped.push(name);
      else throw error;
    }
  }
  if (!files.length) throw new Error("IMAGE_FILE_REQUIRED");
  const clean = files.every((file) => file.clean);
  return {
    purpose: "own-photo-privacy-check",
    network: false,
    persisted: false,
    status: clean ? "completed" : "failed",
    ...(clean ? {} : { code: "SCRUB_INCOMPLETE" }),
    backend,
    original_unchanged: files.every((file) => file.original_unchanged),
    clean,
    count: files.length,
    skipped,
    files,
  };
}

export async function privacyCheckCommand(options) {
  const backend = options.backend ?? "builtin";
  if (!["builtin", "exiftool", "mat2"].includes(backend))
    throw new Error("INVALID_PRIVACY_BACKEND");
  if (options.file && options.directory) throw new Error("INVALID_INPUT");
  if (!options.file && !options.directory)
    throw new Error("IMAGE_FILE_REQUIRED");
  if (options.output && !options.scrub)
    throw new Error("OUTPUT_REQUIRES_SCRUB");
  if (options.scrub && !options.output)
    throw new Error("SCRUB_OUTPUT_REQUIRED");
  if (options.directory) {
    return options.scrub
      ? scrubImageDirectory(options.directory, options.output, backend)
      : checkImageDirectory(options.directory);
  }
  return options.scrub
    ? scrubImageFile(options.file, options.output, backend)
    : checkImageFile(options.file);
}
