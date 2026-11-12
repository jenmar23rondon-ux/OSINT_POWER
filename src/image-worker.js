import { parentPort, workerData } from "node:worker_threads";
import { createHash } from "node:crypto";
import ExifReader from "exifreader";
import { imageFormat } from "./image-format.js";

const fields = {
  exif: [
    "Make",
    "Model",
    "Software",
    "DateTimeOriginal",
    "DateTime",
    "DateTimeDigitized",
  ],
  xmp: ["Make", "Model", "CreatorTool", "CreateDate", "ModifyDate"],
  iptc: ["Date Created", "Time Created"],
};

function pngDimensions(bytes) {
  let offset = 8;
  let hasData = false;
  if (
    bytes.length < 33 ||
    bytes.readUInt32BE(offset) !== 13 ||
    bytes.toString("ascii", 12, 16) !== "IHDR"
  )
    throw new Error("IMAGE_PARSE_FAILED");
  while (offset + 12 <= bytes.length) {
    const length = bytes.readUInt32BE(offset);
    const type = bytes.toString("ascii", offset + 4, offset + 8);
    offset += 12 + length;
    if (offset > bytes.length) break;
    if (type === "IDAT") hasData = true;
    if (type === "IEND" && length === 0 && hasData)
      return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
  }
  throw new Error("IMAGE_PARSE_FAILED");
}

function webpDimensions(bytes) {
  let canvas = null;
  let image = null;
  let frame = false;
  let offset = 12;
  while (offset + 8 <= bytes.length) {
    const type = bytes.toString("ascii", offset, offset + 4);
    const length = bytes.readUInt32LE(offset + 4);
    const start = offset + 8;
    offset = start + length + (length % 2);
    if (offset > bytes.length) throw new Error("IMAGE_PARSE_FAILED");
    if (type === "VP8X" && length === 10)
      canvas = {
        width: bytes.readUIntLE(start + 4, 3) + 1,
        height: bytes.readUIntLE(start + 7, 3) + 1,
      };
    if (
      type === "VP8 " &&
      length >= 10 &&
      bytes.subarray(start + 3, start + 6).toString("hex") === "9d012a"
    )
      image = {
        width: bytes.readUInt16LE(start + 6) & 0x3fff,
        height: bytes.readUInt16LE(start + 8) & 0x3fff,
      };
    if (type === "VP8L" && length >= 5 && bytes[start] === 0x2f) {
      const bits = bytes.readUInt32LE(start + 1);
      image = {
        width: (bits & 0x3fff) + 1,
        height: ((bits >>> 14) & 0x3fff) + 1,
      };
    }
    if (type === "ANMF" && length >= 16) frame = true;
  }
  if (offset !== bytes.length || (!image && !(canvas && frame)))
    throw new Error("IMAGE_PARSE_FAILED");
  return canvas ?? image;
}

function safeValue(tag) {
  let value = tag?.description;
  if (typeof value !== "string") return null;
  value = value
    .replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, " ")
    .replace(
      /(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})/g,
      "[REDACTED]",
    )
    .trim()
    .slice(0, 120);
  return value || null;
}

function analyze(bytes) {
  const format = imageFormat(bytes);
  const containerDimensions =
    format === "png"
      ? pngDimensions(bytes)
      : format === "webp"
        ? webpDimensions(bytes)
        : null;
  const tags = ExifReader.load(bytes, {
    expanded: true,
    includeTags: {
      file: ["FileType", "Image Width", "Image Height"],
      exif: [
        ...fields.exif,
        "ImageWidth",
        "ImageLength",
        "PixelXDimension",
        "PixelYDimension",
        "GPSLatitude",
        "GPSLongitude",
      ],
      xmp: fields.xmp,
      iptc: fields.iptc,
    },
  });
  if (tags.file?.FileType?.value !== format)
    throw new Error("IMAGE_PARSE_FAILED");
  const dimensions = containerDimensions ?? {
    width: tags.file?.["Image Width"]?.value ?? tags.exif?.ImageWidth?.value,
    height: tags.file?.["Image Height"]?.value ?? tags.exif?.ImageLength?.value,
  };
  const metadata = [];
  for (const [group, names] of Object.entries(fields)) {
    for (const tag of names) {
      const value = safeValue(tags[group]?.[tag]);
      if (value) metadata.push({ group, tag, value });
    }
  }
  const inconsistencies = [];
  const exifWidth = tags.exif?.PixelXDimension?.value;
  const exifHeight = tags.exif?.PixelYDimension?.value;
  if (
    (exifWidth && exifWidth !== dimensions.width) ||
    (exifHeight && exifHeight !== dimensions.height)
  )
    inconsistencies.push("exif_dimensions_differ");
  const capture = tags.exif?.DateTimeOriginal?.description;
  const modified = tags.exif?.DateTime?.description;
  const exifDate = /^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}$/;
  if (exifDate.test(capture) && exifDate.test(modified) && capture > modified)
    inconsistencies.push("capture_after_modification");
  return {
    format,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    dimensions,
    metadata,
    gps_tags_present: Boolean(
      tags.exif?.GPSLatitude || tags.exif?.GPSLongitude,
    ),
    inconsistencies,
    authenticity: "unassessed",
    metadata_trust: "untrusted",
    network: false,
  };
}

try {
  parentPort.postMessage({ result: analyze(Buffer.from(workerData.buffer)) });
} catch (error) {
  parentPort.postMessage({
    error:
      error.message === "UNSUPPORTED_IMAGE_FORMAT"
        ? error.message
        : "IMAGE_PARSE_FAILED",
  });
}
