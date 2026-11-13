import { createHash } from "node:crypto";
import { lstat, open, opendir, realpath } from "node:fs/promises";
import { extname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { locateBinary } from "./doctor.js";
import {
  AnalyzeImageInput,
  decodeImageBytes,
  readImageFile,
} from "./image-forensics.js";
import { PNG_SIGNATURE } from "./image-format.js";
import { runProcess } from "./transport.js";

const SIDE = 128;
const SAMPLE = 32;
const frequencies = Array.from({ length: 8 }, (_, frequency) =>
  Array.from(
    { length: SAMPLE },
    (_, position) =>
      Math.cos((Math.PI * (position + 0.5) * frequency) / SAMPLE) *
      (frequency === 0 ? Math.SQRT1_2 : 1),
  ),
);
const decoder = fileURLToPath(new URL("./visual-decoder.js", import.meta.url));
const sha = z.string().regex(/^[a-f0-9]{64}$/);
const distance = z.number().int().min(0).max(63);
const coordinate = z.number().min(0).max(1);
const language = z.enum(["eng", "spa"]);
const crop = z
  .object({
    image: z.enum(["left", "right"]),
    x: coordinate,
    y: coordinate,
    width: coordinate,
    height: coordinate,
    distance,
  })
  .strict();
let mediaActive = false;

export const CompareImagesInput = z
  .object({
    left_base64: AnalyzeImageInput.shape.data_base64,
    right_base64: AnalyzeImageInput.shape.data_base64,
  })
  .strict();
export const CompareImagesResult = z
  .object({
    algorithm: z.literal("phash-dct-63-v1"),
    left_sha256: sha,
    right_sha256: sha,
    match: z.enum([
      "exact",
      "similar_candidate",
      "crop_candidate",
      "insufficient_detail",
      "no_match",
    ]),
    full_distance: distance.nullable(),
    crop: crop.nullable(),
    network: z.literal(false),
  })
  .strict();
const maxSearchFiles = 24;
const maxInlineImages = 8;
const maxInlineEncoded = Math.ceil((8 * 1024 * 1024) / 3) * 4;
const imageData = AnalyzeImageInput.shape.data_base64;
const candidateId = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/);
const sourceUrl = z.url({ protocol: /^https?$/ }).max(2048);
const sourceManifest = z
  .array(
    z
      .object({
        file: z.string().min(1).max(255),
        source_url: sourceUrl,
      })
      .strict(),
  )
  .min(1)
  .max(maxSearchFiles);
const searchMatch = z.enum(["exact", "similar_candidate", "crop_candidate"]);
const matchRank = { exact: 0, similar_candidate: 1, crop_candidate: 2 };
const invalidImageCodes = new Set([
  "INVALID_IMAGE_BASE64",
  "INVALID_IMAGE_SIZE",
  "IMAGE_FILE_REQUIRED",
  "IMAGE_CHANGED_DURING_READ",
  "IMAGE_PARSE_FAILED",
  "IMAGE_DECODE_FAILED",
  "UNSUPPORTED_IMAGE_FORMAT",
  "MULTIPAGE_IMAGE_UNSUPPORTED",
]);
export const SearchImageCopiesInput = z
  .object({
    query_base64: imageData,
    candidates: z
      .array(
        z
          .object({
            id: candidateId,
            data_base64: imageData,
            source_url: sourceUrl.optional(),
          })
          .strict(),
      )
      .min(1)
      .max(maxInlineImages),
  })
  .strict();
export const SearchImageCopiesResult = z
  .object({
    algorithm: CompareImagesResult.shape.algorithm,
    query_sha256: sha,
    compared: z.number().int().min(0).max(maxSearchFiles),
    no_match: z.number().int().min(0).max(maxSearchFiles),
    insufficient_detail: z.number().int().min(0).max(maxSearchFiles),
    matches: z
      .array(
        z
          .object({
            id: z.string().min(1).max(255),
            sha256: sha,
            match: searchMatch,
            full_distance: distance.nullable(),
            crop: crop.nullable(),
            source_url: sourceUrl.optional(),
            source_status: z.literal("supplied_unverified").optional(),
          })
          .strict(),
      )
      .max(maxSearchFiles),
    rejected: z
      .array(
        z.object({ id: z.string().min(1).max(255), code: z.string() }).strict(),
      )
      .max(maxSearchFiles),
    network: z.literal(false),
  })
  .strict();
export const OcrImageInput = AnalyzeImageInput.extend({
  language: language.default("eng"),
});
export const OcrImageResult = z
  .object({
    sha256: sha,
    engine: z.literal("tesseract"),
    language,
    text: z.string().max(8000),
    text_truncated: z.boolean(),
    text_trust: z.literal("untrusted"),
    network: z.literal(false),
  })
  .strict();

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function withMediaSlot(operation) {
  if (mediaActive) throw new Error("VISUAL_ANALYZER_BUSY");
  mediaActive = true;
  try {
    return await operation();
  } finally {
    mediaActive = false;
  }
}

async function decode(bytes, mode, signal) {
  const response = await runProcess(
    process.execPath,
    [decoder, mode],
    {
      timeoutMs: 8000,
      maxBytes: mode === "thumbnail" ? 32768 : 4 * 1024 * 1024,
    },
    bytes,
    { allow: [process.execPath], signal },
  );
  const parsed = JSON.parse(response);
  if (parsed.error) throw new Error(parsed.error);
  const normalized = Buffer.from(parsed.data ?? "", "base64");
  const valid =
    mode === "thumbnail"
      ? normalized.length === SIDE ** 2
      : normalized.subarray(0, 8).equals(PNG_SIGNATURE);
  if (!valid) throw new Error("IMAGE_DECODE_FAILED");
  return normalized;
}

function perceptualHash(pixels, left = 0, top = 0, side = SIDE) {
  const sample = [];
  const block = side / SAMPLE;
  let sum = 0;
  let squared = 0;
  for (let y = 0; y < SAMPLE; y++) {
    for (let x = 0; x < SAMPLE; x++) {
      let total = 0;
      for (let dy = 0; dy < block; dy++) {
        for (let dx = 0; dx < block; dx++) {
          total +=
            pixels[(top + y * block + dy) * SIDE + left + x * block + dx];
        }
      }
      const average = total / (block * block);
      sample.push(average);
      sum += average;
      squared += average * average;
    }
  }
  const variance = squared / sample.length - (sum / sample.length) ** 2;
  if (variance < 64) return null;

  const rows = [];
  for (let y = 0; y < SAMPLE; y++) {
    rows.push(
      frequencies.map((weights) =>
        weights.reduce(
          (total, weight, x) => total + sample[y * SAMPLE + x] * weight,
          0,
        ),
      ),
    );
  }
  const coefficients = [];
  for (let v = 0; v < 8; v++) {
    for (let u = 0; u < 8; u++) {
      if (!u && !v) continue;
      coefficients.push(
        frequencies[v].reduce(
          (total, weight, y) => total + rows[y][u] * weight,
          0,
        ),
      );
    }
  }
  const median = [...coefficients].sort((a, b) => a - b)[31];
  return coefficients.map((value) => Number(value > median));
}

function hamming(left, right) {
  return left.reduce((count, bit, i) => count + Number(bit !== right[i]), 0);
}

function findCrop(pixels, reference, image, best) {
  for (const side of [96, 64]) {
    const offsets = [0, (SIDE - side) / 2, SIDE - side];
    for (const top of offsets) {
      for (const left of offsets) {
        const hash = perceptualHash(pixels, left, top, side);
        if (!hash) continue;
        const difference = hamming(hash, reference);
        if (difference <= 6 && (!best || difference < best.distance)) {
          best = {
            image,
            x: left / SIDE,
            y: top / SIDE,
            width: side / SIDE,
            height: side / SIDE,
            distance: difference,
          };
        }
      }
    }
  }
  return best;
}

async function prepareReference(left, signal) {
  const pixels = await decode(left, "thumbnail", signal);
  return {
    bytes: left,
    pixels,
    hash: perceptualHash(pixels),
    sha256: digest(left),
  };
}

async function compareReference(reference, right, signal) {
  const { bytes: left, pixels: first, hash: firstHash } = reference;
  const exact = left.equals(right);
  let match = "insufficient_detail";
  let fullDistance = null;
  let cropMatch = null;
  if (exact) {
    match = "exact";
    fullDistance = firstHash ? 0 : null;
  } else {
    const second = await decode(right, "thumbnail", signal);
    const secondHash = perceptualHash(second);
    if (firstHash && secondHash) {
      fullDistance = hamming(firstHash, secondHash);
      if (fullDistance <= 8) match = "similar_candidate";
      else {
        cropMatch = findCrop(first, secondHash, "left", null);
        cropMatch = findCrop(second, firstHash, "right", cropMatch);
        match = cropMatch ? "crop_candidate" : "no_match";
      }
    }
  }
  return {
    algorithm: "phash-dct-63-v1",
    left_sha256: reference.sha256,
    right_sha256: exact ? reference.sha256 : digest(right),
    match,
    full_distance: fullDistance,
    crop: cropMatch,
    network: false,
  };
}

async function compareBytes(left, right, signal) {
  return compareReference(await prepareReference(left, signal), right, signal);
}

export async function compareImages(input, signal) {
  const { left_base64, right_base64 } = CompareImagesInput.parse(input);
  return withMediaSlot(() =>
    compareBytes(
      decodeImageBytes(left_base64),
      decodeImageBytes(right_base64),
      signal,
    ),
  );
}

export async function compareImageFiles(leftPath, rightPath) {
  return withMediaSlot(async () =>
    compareBytes(await readImageFile(leftPath), await readImageFile(rightPath)),
  );
}

async function searchCopies(query, candidates, signal) {
  const deadline = AbortSignal.timeout(45000);
  const cancellation = signal ? AbortSignal.any([signal, deadline]) : deadline;
  return withMediaSlot(async () => {
    try {
      cancellation.throwIfAborted();
      const reference = await prepareReference(await query(), cancellation);
      const matches = [];
      const rejected = [];
      let no_match = 0;
      let insufficient_detail = 0;
      for (const { id, read, source_url } of candidates) {
        cancellation.throwIfAborted();
        try {
          const comparison = await compareReference(
            reference,
            await read(),
            cancellation,
          );
          if (comparison.match === "no_match") no_match++;
          else if (comparison.match === "insufficient_detail")
            insufficient_detail++;
          else
            matches.push({
              id,
              sha256: comparison.right_sha256,
              match: comparison.match,
              full_distance: comparison.full_distance,
              crop: comparison.crop,
              ...(source_url
                ? { source_url, source_status: "supplied_unverified" }
                : {}),
            });
        } catch (error) {
          cancellation.throwIfAborted();
          const code = ["ENOENT", "EACCES", "EPERM", "EISDIR"].includes(
            error.code,
          )
            ? "IMAGE_FILE_UNREADABLE"
            : error.message;
          if (code !== "IMAGE_FILE_UNREADABLE" && !invalidImageCodes.has(code))
            throw error;
          rejected.push({ id, code });
        }
      }
      cancellation.throwIfAborted();
      matches.sort(
        (a, b) =>
          matchRank[a.match] - matchRank[b.match] ||
          (a.crop?.distance ?? a.full_distance ?? 0) -
            (b.crop?.distance ?? b.full_distance ?? 0) ||
          (a.id < b.id ? -1 : Number(a.id > b.id)),
      );
      return {
        algorithm: "phash-dct-63-v1",
        query_sha256: reference.sha256,
        compared: candidates.length - rejected.length,
        no_match,
        insufficient_detail,
        matches,
        rejected,
        network: false,
      };
    } catch (error) {
      signal?.throwIfAborted();
      if (deadline.aborted) throw new Error("IMAGE_SEARCH_TIMEOUT");
      throw error;
    }
  });
}

export function searchImageCopies(input, signal) {
  const { query_base64, candidates } = SearchImageCopiesInput.parse(input);
  if (new Set(candidates.map(({ id }) => id)).size !== candidates.length)
    throw new Error("DUPLICATE_IMAGE_CANDIDATE_ID");
  const total = candidates.reduce(
    (size, item) => size + item.data_base64.length,
    query_base64.length,
  );
  if (total > maxInlineEncoded) throw new Error("IMAGE_SEARCH_INPUT_TOO_LARGE");
  return searchCopies(
    () => decodeImageBytes(query_base64),
    candidates.map(({ id, data_base64, source_url }) => ({
      id,
      read: () => decodeImageBytes(data_base64),
      source_url: source_url ? sanitizedSourceUrl(source_url) : undefined,
    })),
    signal,
  );
}

function sanitizedSourceUrl(value) {
  const url = new URL(value);
  if (url.username || url.password) throw new Error("INVALID_PHOTO_SOURCE_URL");
  url.search = "";
  url.hash = "";
  return url.href;
}

async function readSourceManifest(path, names) {
  const limit = 64 * 1024;
  if (/^[\\/]{2}/.test(path) || !(await lstat(path)).isFile())
    throw new Error("INVALID_PHOTO_SOURCE_MANIFEST");
  const file = await open(path, "r");
  try {
    const size = (await file.stat()).size;
    if (size > limit) throw new Error("INVALID_PHOTO_SOURCE_MANIFEST");
    const buffer = Buffer.alloc(size + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(
        buffer,
        length,
        buffer.length - length,
        length,
      );
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length !== size) throw new Error("INVALID_PHOTO_SOURCE_MANIFEST");
    let rows;
    try {
      rows = sourceManifest.parse(
        JSON.parse(
          buffer
            .subarray(0, length)
            .toString("utf8")
            .replace(/^\uFEFF/, ""),
        ),
      );
    } catch {
      throw new Error("INVALID_PHOTO_SOURCE_MANIFEST");
    }
    const sources = new Map();
    for (const { file: name, source_url } of rows) {
      if (!names.includes(name) || sources.has(name))
        throw new Error("INVALID_PHOTO_SOURCE_MANIFEST");
      sources.set(name, sanitizedSourceUrl(source_url));
    }
    return sources;
  } finally {
    await file.close();
  }
}

export async function searchImageDirectory(queryPath, directory, manifestPath) {
  if (
    !directory ||
    /^[\\/]{2}/.test(directory) ||
    !(await lstat(directory)).isDirectory()
  )
    throw new Error("DIRECTORY_REQUIRED");
  const root = await realpath(directory);
  if (/^[\\/]{2}/.test(root)) throw new Error("DIRECTORY_REQUIRED");
  const names = [];
  let inspected = 0;
  for await (const entry of await opendir(root)) {
    if (++inspected > 256) throw new Error("IMAGE_DIRECTORY_TOO_LARGE");
    if (
      !entry.isFile() ||
      ![".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff"].includes(
        extname(entry.name).toLowerCase(),
      )
    )
      continue;
    names.push(entry.name);
    if (names.length > maxSearchFiles) throw new Error("TOO_MANY_IMAGES");
  }
  if (!names.length) throw new Error("IMAGE_FILE_REQUIRED");
  const sources = manifestPath
    ? await readSourceManifest(manifestPath, names)
    : new Map();
  return searchCopies(
    () => readImageFile(queryPath),
    names.sort().map((id) => ({
      id,
      read: () => readImageFile(join(root, id)),
      source_url: sources.get(id),
    })),
  );
}

async function ocrBytes(bytes, lang, signal) {
  const command = locateBinary("tesseract");
  if (!command || !isAbsolute(command))
    throw new Error("OCR_TOOL_NOT_INSTALLED");
  const png = await decode(bytes, "ocr", signal);
  const output = await runProcess(
    command,
    ["stdin", "stdout", "-l", lang, "--psm", "6"],
    { timeoutMs: 12000, maxBytes: 65536 },
    png,
    { allow: [command], signal },
  );
  const text = output
    .replace(/\r\n?/g, "\n")
    .replace(
      /[\u0000-\u0008\u000b-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g,
      " ",
    )
    .replace(
      /(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})/g,
      "[REDACTED]",
    )
    .trim();
  return {
    sha256: digest(bytes),
    engine: "tesseract",
    language: lang,
    text: text.slice(0, 8000),
    text_truncated: text.length > 8000,
    text_trust: "untrusted",
    network: false,
  };
}

export async function ocrImage(input, signal) {
  const { data_base64, language: lang } = OcrImageInput.parse(input);
  return withMediaSlot(() =>
    ocrBytes(decodeImageBytes(data_base64), lang, signal),
  );
}

export async function ocrImageFile(path, lang = "eng") {
  const checked = language.parse(lang);
  return withMediaSlot(async () =>
    ocrBytes(await readImageFile(path), checked),
  );
}
