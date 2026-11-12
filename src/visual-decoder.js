import sharp from "sharp";
import { imageFormat } from "./image-format.js";

sharp.cache(false);
sharp.concurrency(1);
sharp.block({ operation: ["VipsForeignLoad"] });
sharp.unblock({
  operation: [
    "VipsForeignLoadJpegBuffer",
    "VipsForeignLoadPngBuffer",
    "VipsForeignLoadWebpBuffer",
    "VipsForeignLoadTiffBuffer",
  ],
});

async function decode(mode) {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 16 * 1024 * 1024) throw new Error("INVALID_IMAGE_SIZE");
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks, size);
  const expected = imageFormat(bytes);
  const image = sharp(bytes, {
    failOn: "error",
    limitInputPixels: 20_000_000,
    pages: 1,
  }).timeout({ seconds: 4 });
  const metadata = await image.metadata();
  if (metadata.format !== expected) throw new Error("IMAGE_DECODE_FAILED");
  if ((metadata.pages ?? 1) > 1) throw new Error("MULTIPAGE_IMAGE_UNSUPPORTED");
  const oriented = image
    .autoOrient()
    .flatten({ background: "#ffffff" })
    .toColourspace("b-w");
  const result =
    mode === "thumbnail"
      ? await oriented.resize(128, 128, { fit: "fill" }).raw().toBuffer()
      : await oriented
          .resize(1600, 1600, { fit: "inside", withoutEnlargement: true })
          .png()
          .toBuffer();
  return result.toString("base64");
}

try {
  const mode = process.argv[2];
  if (!["thumbnail", "ocr"].includes(mode)) throw new Error("INVALID_INPUT");
  process.stdout.write(JSON.stringify({ data: await decode(mode) }));
} catch (error) {
  const errors = new Set([
    "INVALID_IMAGE_SIZE",
    "IMAGE_PARSE_FAILED",
    "UNSUPPORTED_IMAGE_FORMAT",
    "MULTIPAGE_IMAGE_UNSUPPORTED",
  ]);
  process.stdout.write(
    JSON.stringify({
      error: errors.has(error.message) ? error.message : "IMAGE_DECODE_FAILED",
    }),
  );
}
