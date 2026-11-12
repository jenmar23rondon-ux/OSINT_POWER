import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  analyzeImage,
  inspectImage,
  MAX_LOCAL_IMAGE_BYTES,
} from "../src/image-forensics.js";

const png = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aF9sAAAAASUVORK5CYII=",
  "base64",
);
const webp = Buffer.from(
  "UklGRhoAAABXRUJQVlA4TA4AAAAvAAAAAAfQ//73v/+BiOh/AAA=",
  "base64",
).subarray(0, 34);

const jpeg = Buffer.from(
  "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCAACAAMDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD8qqKKKAP/2Q==",
  "base64",
);

function appSegment(marker, data) {
  const header = Buffer.from([0xff, marker, 0, 0]);
  header.writeUInt16BE(data.length + 2, 2);
  return Buffer.concat([header, data]);
}

test("JPEG inspection separates selected XMP and IPTC fields", async () => {
  const xmp = Buffer.from(
    'http://ns.adobe.com/xap/1.0/\0<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="Fixture Editor"/></rdf:RDF></x:xmpmeta>',
  );
  const iptcDate = Buffer.concat([
    Buffer.from([0x1c, 2, 55, 0, 8]),
    Buffer.from("20261111"),
  ]);
  const iptc = Buffer.concat([
    Buffer.from("Photoshop 3.0\0" + "8BIM"),
    Buffer.from([4, 4, 0, 0, 0, 0, 0, iptcDate.length]),
    iptcDate,
    Buffer.alloc(1),
  ]);
  const photo = Buffer.concat([
    jpeg.subarray(0, 2),
    appSegment(0xe1, xmp),
    appSegment(0xed, iptc),
    jpeg.subarray(2),
  ]);
  const report = await inspectImage(photo);
  assert.equal(report.format, "jpeg");
  assert.deepEqual(report.dimensions, { width: 3, height: 2 });
  assert.equal(
    report.metadata.find((m) => m.group === "xmp" && m.tag === "CreatorTool")
      ?.value,
    "Fixture Editor",
  );
  assert.equal(
    report.metadata.some((m) => m.group === "iptc" && m.tag === "Date Created"),
    true,
  );
});

function tiffFixture() {
  const make = Buffer.from("FixtureCam\0");
  const software = Buffer.from("ghp_" + "A".repeat(36) + "\0");
  const start = 8 + 2 + 5 * 12 + 4;
  const gps = start + make.length + software.length;
  const bytes = Buffer.alloc(gps + 18 + 24);
  bytes.set(Buffer.from("49492a0008000000", "hex"));
  bytes.writeUInt16LE(5, 8);
  const tag = (offset, id, type, count, value) => {
    bytes.writeUInt16LE(id, offset);
    bytes.writeUInt16LE(type, offset + 2);
    bytes.writeUInt32LE(count, offset + 4);
    bytes.writeUInt32LE(value, offset + 8);
  };
  tag(10, 256, 4, 1, 3);
  tag(22, 257, 4, 1, 2);
  tag(34, 271, 2, make.length, start);
  tag(46, 305, 2, software.length, start + make.length);
  tag(58, 34853, 4, 1, gps);
  make.copy(bytes, start);
  software.copy(bytes, start + make.length);
  bytes.writeUInt16LE(1, gps);
  tag(gps + 2, 2, 5, 3, gps + 18);
  for (let i = 0; i < 3; i++) {
    bytes.writeUInt32LE(33 + i, gps + 18 + 8 * i);
    bytes.writeUInt32LE(1, gps + 22 + 8 * i);
  }
  return bytes;
}

test("image inspection reads container dimensions and hashes exact bytes", async () => {
  for (const [format, bytes] of [
    ["png", png],
    ["webp", webp],
  ]) {
    const report = await analyzeImage({
      data_base64: bytes.toString("base64"),
    });
    assert.equal(report.format, format);
    assert.deepEqual(report.dimensions, { width: 1, height: 1 });
    assert.equal(
      report.sha256,
      createHash("sha256").update(bytes).digest("hex"),
    );
    assert.equal(report.authenticity, "unassessed");
    assert.equal(report.network, false);
  }
});

test("the EXIF report excludes coordinates and redacts common credential patterns", async () => {
  const report = await inspectImage(tiffFixture());
  assert.equal(report.format, "tiff");
  assert.deepEqual(report.dimensions, { width: 3, height: 2 });
  assert.deepEqual(report.metadata, [
    { group: "exif", tag: "Make", value: "FixtureCam" },
    { group: "exif", tag: "Software", value: "[REDACTED]" },
  ]);
  assert.equal(report.gps_tags_present, true);
  assert.equal(JSON.stringify(report).includes("GPSLatitude"), false);
});

test("image processing rejects malformed inputs, excess bytes and cancelled work", async () => {
  await assert.rejects(inspectImage(png.subarray(0, 33)), /IMAGE_PARSE_FAILED/);
  await assert.rejects(
    inspectImage(Buffer.from("<svg/>")),
    /UNSUPPORTED_IMAGE_FORMAT/,
  );
  await assert.rejects(
    inspectImage(Buffer.alloc(MAX_LOCAL_IMAGE_BYTES + 1)),
    /INVALID_IMAGE_SIZE/,
  );
  assert.throws(
    () => analyzeImage({ data_base64: "AAAA\n" }),
    /INVALID_IMAGE_BASE64/,
  );
  const controller = new AbortController();
  const pending = inspectImage(png, controller.signal);
  await assert.rejects(inspectImage(png), /IMAGE_ANALYZER_BUSY/);
  controller.abort();
  await assert.rejects(pending, /CANCELLED/);
  assert.equal((await inspectImage(png)).format, "png");
});
