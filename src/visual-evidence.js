import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
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

async function compareBytes(left, right, signal) {
  const first = await decode(left, "thumbnail", signal);
  const exact = left.equals(right);
  const second = exact ? first : await decode(right, "thumbnail", signal);
  const firstHash = perceptualHash(first);
  const secondHash = perceptualHash(second);
  let match = "insufficient_detail";
  let fullDistance = null;
  let cropMatch = null;
  if (exact) {
    match = "exact";
    fullDistance = firstHash ? 0 : null;
  } else if (firstHash && secondHash) {
    fullDistance = hamming(firstHash, secondHash);
    if (fullDistance <= 8) match = "similar_candidate";
    else {
      cropMatch = findCrop(first, secondHash, "left", null);
      cropMatch = findCrop(second, firstHash, "right", cropMatch);
      match = cropMatch ? "crop_candidate" : "no_match";
    }
  }
  return {
    algorithm: "phash-dct-63-v1",
    left_sha256: digest(left),
    right_sha256: digest(right),
    match,
    full_distance: fullDistance,
    crop: cropMatch,
    network: false,
  };
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
