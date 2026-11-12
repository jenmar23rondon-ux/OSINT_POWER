import test from "node:test";
import assert from "node:assert/strict";
import sharp from "sharp";
import { compareImages, ocrImage } from "../src/visual-evidence.js";
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
