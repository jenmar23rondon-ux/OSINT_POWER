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

const privacyTags = {
  exif: [
    "Make",
    "Model",
    "LensMake",
    "LensModel",
    "Software",
    "DateTime",
    "DateTimeOriginal",
    "DateTimeDigitized",
    "Artist",
    "Copyright",
    "CameraOwnerName",
    "OwnerName",
    "BodySerialNumber",
    "SerialNumber",
    "LensSerialNumber",
    "InternalSerialNumber",
    "ImageUniqueID",
    "GPSLatitude",
    "GPSLatitudeRef",
    "GPSLongitude",
    "GPSLongitudeRef",
    "GPSAltitude",
    "GPSAltitudeRef",
    "GPSDateStamp",
    "GPSTimeStamp",
  ],
  xmp: [
    "Make",
    "Model",
    "CreatorTool",
    "CreateDate",
    "ModifyDate",
    "Creator",
    "Rights",
  ],
  iptc: [
    "Date Created",
    "Time Created",
    "By-line",
    "Copyright Notice",
    "Credit",
  ],
};
const privacyRisk = {
  GPSLatitude: "high",
  GPSLongitude: "high",
  GPSAltitude: "high",
  Artist: "medium",
  Copyright: "medium",
  CameraOwnerName: "medium",
  OwnerName: "medium",
  BodySerialNumber: "medium",
  SerialNumber: "medium",
  LensSerialNumber: "medium",
  InternalSerialNumber: "medium",
  ImageUniqueID: "medium",
  Creator: "medium",
  Rights: "medium",
  "By-line": "medium",
  "Copyright Notice": "medium",
  Credit: "medium",
  Make: "low",
  Model: "low",
  LensMake: "low",
  LensModel: "low",
  Software: "low",
  CreatorTool: "low",
  DateTime: "low",
  DateTimeOriginal: "low",
  DateTimeDigitized: "low",
  CreateDate: "low",
  ModifyDate: "low",
  "Date Created": "low",
  "Time Created": "low",
  GPSDateStamp: "low",
  GPSTimeStamp: "low",
};

function loadTags(bytes, mode) {
  const privacy = mode === "privacy";
  return ExifReader.load(bytes, {
    expanded: true,
    includeTags: {
      file: ["FileType", "Image Width", "Image Height"],
      exif: [
        ...(privacy ? privacyTags.exif : fields.exif),
        "ImageWidth",
        "ImageLength",
        "PixelXDimension",
        "PixelYDimension",
        "GPSLatitude",
        "GPSLongitude",
      ],
      xmp: privacy ? privacyTags.xmp : fields.xmp,
      iptc: privacy ? privacyTags.iptc : fields.iptc,
      ...(privacy ? { gps: ["Latitude", "Longitude", "Altitude"] } : {}),
    },
  });
}

function parsedImage(bytes, mode) {
  const format = imageFormat(bytes);
  const containerDimensions =
    format === "png"
      ? pngDimensions(bytes)
      : format === "webp"
        ? webpDimensions(bytes)
        : null;
  const tags = loadTags(bytes, mode);
  if (tags.file?.FileType?.value !== format)
    throw new Error("IMAGE_PARSE_FAILED");
  const dimensions = containerDimensions ?? {
    width: tags.file?.["Image Width"]?.value ?? tags.exif?.ImageWidth?.value,
    height: tags.file?.["Image Height"]?.value ?? tags.exif?.ImageLength?.value,
  };
  return { format, dimensions, tags };
}

function analyze(bytes) {
  const { format, dimensions, tags } = parsedImage(bytes, "analyze");
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

function ratio(pair) {
  if (!Array.isArray(pair) || pair.length < 2) return null;
  const [numerator, denominator] = pair;
  if (
    typeof numerator !== "number" ||
    typeof denominator !== "number" ||
    denominator === 0
  )
    return null;
  return numerator / denominator;
}

function dms(tag) {
  const value = tag?.value;
  if (!Array.isArray(value) || value.length < 3) return null;
  const degrees = ratio(value[0]);
  const minutes = ratio(value[1]);
  const seconds = ratio(value[2]);
  if (degrees === null || minutes === null || seconds === null) return null;
  return degrees + minutes / 60 + seconds / 3600;
}

function bounded(value, limit) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (value < -limit || value > limit) return null;
  return value;
}

function formatNumber(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const rounded = Math.round(value * 1e6) / 1e6;
  return Object.is(rounded, -0) ? "0" : String(rounded);
}

function readGps(tags) {
  const latitudeRef = Array.isArray(tags.exif?.GPSLatitudeRef?.value)
    ? tags.exif.GPSLatitudeRef.value.join("")
    : "";
  const longitudeRef = Array.isArray(tags.exif?.GPSLongitudeRef?.value)
    ? tags.exif.GPSLongitudeRef.value.join("")
    : "";
  let latitude = bounded(tags.gps?.Latitude, 90);
  let longitude = bounded(tags.gps?.Longitude, 180);
  let altitude = bounded(tags.gps?.Altitude, 20000);
  if (latitude === null) {
    const magnitude = dms(tags.exif?.GPSLatitude);
    if (magnitude !== null)
      latitude = bounded(
        latitudeRef.includes("S") ? -magnitude : magnitude,
        90,
      );
  }
  if (longitude === null) {
    const magnitude = dms(tags.exif?.GPSLongitude);
    if (magnitude !== null)
      longitude = bounded(
        longitudeRef.includes("W") ? -magnitude : magnitude,
        180,
      );
  }
  if (altitude === null) {
    const meters = ratio(tags.exif?.GPSAltitude?.value);
    if (meters !== null)
      altitude = bounded(
        tags.exif?.GPSAltitudeRef?.value === 1 ? -meters : meters,
        20000,
      );
  }
  return {
    present: Boolean(
      tags.exif?.GPSLatitude ||
      tags.exif?.GPSLongitude ||
      tags.exif?.GPSAltitude ||
      latitude !== null ||
      longitude !== null ||
      altitude !== null,
    ),
    latitude,
    longitude,
    altitude_meters: altitude,
  };
}

function privacy(bytes) {
  const { format, dimensions, tags } = parsedImage(bytes, "privacy");
  const gps = readGps(tags);
  const signed = {
    GPSLatitude: formatNumber(gps.latitude),
    GPSLongitude: formatNumber(gps.longitude),
    GPSAltitude: formatNumber(gps.altitude_meters),
  };
  const findings = [];
  for (const [group, names] of Object.entries(privacyTags)) {
    for (const tag of names) {
      const risk = privacyRisk[tag];
      const source = tags[group]?.[tag];
      if (!risk || !source) continue;
      const value = signed[tag] || safeValue(source);
      if (value) findings.push({ group, tag, risk, value });
    }
  }
  if (gps.present && !findings.some((finding) => finding.risk === "high")) {
    findings.push({
      group: "exif",
      tag: "GPSLatitude",
      risk: "high",
      value:
        formatNumber(gps.latitude) ||
        formatNumber(gps.longitude) ||
        formatNumber(gps.altitude_meters) ||
        "present",
    });
  }
  const rank = { high: 0, medium: 1, low: 2 };
  findings.sort(
    (left, right) =>
      rank[left.risk] - rank[right.risk] ||
      left.tag.localeCompare(right.tag) ||
      left.group.localeCompare(right.group),
  );
  const reported = findings.slice(0, 48);
  const counts = { high: 0, medium: 0, low: 0 };
  for (const finding of reported) counts[finding.risk] += 1;
  const rating = counts.high
    ? "high"
    : counts.medium
      ? "medium"
      : counts.low
        ? "low"
        : "none";
  return {
    purpose: "own-photo-privacy-check",
    network: false,
    persisted: false,
    format,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    dimensions,
    rating,
    counts,
    gps,
    findings: reported,
    metadata_trust: "untrusted",
  };
}

try {
  const mode = workerData?.mode === "privacy" ? "privacy" : "analyze";
  const source = workerData?.buffer ?? workerData;
  parentPort.postMessage({
    result: (mode === "privacy" ? privacy : analyze)(Buffer.from(source)),
  });
} catch (error) {
  parentPort.postMessage({
    error:
      error.message === "UNSUPPORTED_IMAGE_FORMAT"
        ? error.message
        : "IMAGE_PARSE_FAILED",
  });
}
