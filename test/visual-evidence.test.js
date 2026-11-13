import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";
import {
  compareImages,
  ocrImage,
  searchImageCopies,
} from "../src/visual-evidence.js";
import { runProcess } from "../src/transport.js";

const bytes = (buffer) => buffer.toString("base64");
const compare = (left, right) =>
  compareImages({ left_base64: bytes(left), right_base64: bytes(right) });

async function pattern(seed) {
  const grid = Buffer.alloc(16 * 16);
  let state = seed;
  for (let i = 0; i < grid.length; i++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    grid[i] = state >>> 24;
  }
  return sharp(grid, { raw: { width: 16, height: 16, channels: 1 } })
    .resize(256, 256, { kernel: "nearest" })
    .png()
    .toBuffer();
}

test("perceptual comparison distinguishes exact, resized, cropped and unrelated images", async () => {
  const original = await pattern(314159);
  const resized = await sharp(original)
    .resize(160, 160)
    .jpeg({ quality: 70 })
    .toBuffer();
  const cropped = await sharp(original)
    .extract({ left: 64, top: 64, width: 128, height: 128 })
    .resize(192, 192)
    .webp({ quality: 76 })
    .toBuffer();
  const unrelated = await pattern(271828);

  assert.equal((await compare(original, original)).match, "exact");
  const tiff = await sharp(original).tiff().toBuffer();
  assert.equal((await compare(original, tiff)).match, "similar_candidate");
  const similar = await compare(original, resized);
  assert.equal(similar.match, "similar_candidate");
  assert.notEqual(similar.left_sha256, similar.right_sha256);
  const region = await compare(original, cropped);
  assert.equal(region.match, "crop_candidate");
  assert.equal(region.crop.image, "left");
  assert.equal(region.crop.x, 0.25);
  assert.equal(region.crop.y, 0.25);
  assert.equal(region.crop.width, 0.5);
  assert.equal((await compare(cropped, original)).crop.image, "right");
  assert.equal((await compare(original, unrelated)).match, "no_match");
});

test("low-detail images remain inconclusive and unsupported formats are rejected", async () => {
  const flat = (background) =>
    sharp({ create: { width: 16, height: 16, channels: 3, background } })
      .png()
      .toBuffer();
  const left = await flat("#000");
  const right = await flat("#fff");
  assert.equal((await compare(left, right)).match, "insufficient_detail");
  await assert.rejects(
    compare(Buffer.from("<svg/>"), right),
    /UNSUPPORTED_IMAGE_FORMAT/,
  );
  await assert.rejects(
    compare(left.subarray(0, 30), right),
    /IMAGE_DECODE_FAILED/,
  );
  await assert.rejects(
    runProcess(
      process.execPath,
      ["-v"],
      { timeoutMs: 100, maxBytes: 1024 },
      left,
    ),
    /REJECTED_ARGUMENT/,
  );
});

test("photo-copy search ranks known copies and isolates unreadable candidates", async () => {
  const original = await pattern(314159);
  const variants = [
    ["unrelated", await pattern(271828)],
    ["corrupt", Buffer.from("invalid image")],
    [
      "crop",
      await sharp(original)
        .extract({ left: 64, top: 64, width: 128, height: 128 })
        .png()
        .toBuffer(),
    ],
    [
      "resized",
      await sharp(original).resize(160).jpeg({ quality: 70 }).toBuffer(),
    ],
    ["exact", original],
  ];
  const input = {
    query_base64: bytes(original),
    candidates: variants.map(([id, buffer]) => ({
      id,
      data_base64: bytes(buffer),
    })),
  };
  const report = await searchImageCopies(input);
  assert.equal(report.network, false);
  assert.equal(report.compared, 4);
  assert.equal(report.no_match, 1);
  assert.deepEqual(
    report.matches.map(({ id, match }) => [id, match]),
    [
      ["exact", "exact"],
      ["resized", "similar_candidate"],
      ["crop", "crop_candidate"],
    ],
  );
  assert.equal(report.matches[0].sha256, report.query_sha256);
  assert.deepEqual(report.rejected, [
    { id: "corrupt", code: "UNSUPPORTED_IMAGE_FORMAT" },
  ]);
  assert.throws(
    () =>
      searchImageCopies({
        ...input,
        candidates: [input.candidates[0], input.candidates[0]],
      }),
    /DUPLICATE_IMAGE_CANDIDATE_ID/,
  );
  assert.throws(
    () =>
      searchImageCopies({
        ...input,
        candidates: [
          {
            ...input.candidates[0],
            source_url: "https://user:password@example.invalid/image",
          },
        ],
      }),
    /INVALID_PHOTO_SOURCE_URL/,
  );
  await assert.rejects(
    searchImageCopies(input, AbortSignal.abort(new Error("test abort"))),
    /test abort/,
  );
});

test("CLI photo-copy search accepts a local directory without a workspace", async (t) => {
  const root = mkdtempSync(join(tmpdir(), "osint-copy-search-"));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const directory = join(root, "reviewed");
  const reference = join(root, "original.png");
  const original = await pattern(42);
  mkdirSync(directory);
  writeFileSync(reference, original);
  writeFileSync(join(directory, "exact.png"), original);
  writeFileSync(join(directory, "skip.txt"), original);
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const result = JSON.parse(
    execFileSync(
      process.execPath,
      [cli, "search-image-copies", "--file", reference, "--dir", directory],
      { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ),
  ).result;
  assert.equal(result.network, false);
  assert.equal(result.compared, 1);
  assert.deepEqual(
    result.matches.map(({ id, match }) => [id, match]),
    [["exact.png", "exact"]],
  );
  const manifest = join(root, "sources.json");
  const run = () =>
    JSON.parse(
      execFileSync(
        process.execPath,
        [
          cli,
          "search-image-copies",
          "--file",
          reference,
          "--dir",
          directory,
          "--manifest",
          manifest,
        ],
        { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
      ),
    ).result;
  const source = {
    file: "exact.png",
    source_url: "https://example.invalid/reviewed?secret=omit",
  };
  writeFileSync(manifest, JSON.stringify([source]));
  assert.deepEqual(run().matches[0], {
    ...result.matches[0],
    source_url: "https://example.invalid/reviewed",
    source_status: "supplied_unverified",
  });
  for (const rows of [
    [source, source],
    [{ ...source, file: "../exact.png" }],
    [{ ...source, source_url: "file:///tmp/image.png" }],
  ]) {
    writeFileSync(manifest, JSON.stringify(rows));
    assert.throws(
      run,
      (error) =>
        error.status === 1 &&
        JSON.parse(error.stdout).error.code === "INVALID_PHOTO_SOURCE_MANIFEST",
    );
  }
});

test(
  "native OCR reads a synthetic document with the installed language data",
  {
    skip: process.env.OSINT_POWER_OCR_TEST !== "1",
  },
  async () => {
    const fixture = Buffer.from(
      '<svg xmlns="http://www.w3.org/2000/svg" width="850" height="145"><rect width="850" height="145" fill="white"/><text x="35" y="94" font-family="DejaVu Sans" font-size="56">VISUAL EVIDENCE 2026</text></svg>',
    );
    const png = await sharp(fixture).png().toBuffer();
    const report = await ocrImage({ data_base64: bytes(png), language: "eng" });
    assert.match(report.text, /VISUAL EVIDENCE 2026/);
    assert.equal(report.network, false);
    assert.equal(report.text_trust, "untrusted");
    assert.equal(report.text_truncated, false);
  },
);
