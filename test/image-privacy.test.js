import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { doctor } from "../src/doctor.js";
import { inspectImage } from "../src/image-forensics.js";
import {
  checkImageBytes,
  checkImageFile,
  isPrivacyClean,
  scrubImageFile,
} from "../src/image-privacy.js";
import { OperationError, runProcess } from "../src/transport.js";

const jpeg = Buffer.from(
  "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCAACAAMDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD8qqKKKAP/2Q==",
  "base64",
);

function ascii(text) {
  return Buffer.from(text + "\0", "latin1");
}

function rational(pairs) {
  const bytes = Buffer.alloc(8 * pairs.length);
  pairs.forEach(([numerator, denominator], index) => {
    bytes.writeUInt32LE(numerator, index * 8);
    bytes.writeUInt32LE(denominator, index * 8 + 4);
  });
  return bytes;
}

function ifdSize(entries) {
  return 2 + entries.length * 12 + 4;
}

function privacyJpeg() {
  const ifd0Specs = [
    [0x010f, 2, ascii("FixtureCam")],
    [0x0110, 2, ascii("FixturePhone")],
    [0x0131, 2, ascii("FixtureEdit 1.0")],
    [0x0132, 2, ascii("2026:11:13 18:00:00")],
    [0x013b, 2, ascii("Fixture Artist")],
    [0x8298, 2, ascii("Fixture Copyright")],
    [0x8769, 4, "exif"],
    [0x8825, 4, "gps"],
  ];
  const exifSpecs = [
    [0x9003, 2, ascii("2026:11:13 18:00:00")],
    [0x9004, 2, ascii("2026:11:13 18:00:01")],
    [0xa430, 2, ascii("Fixture Owner")],
    [0xa431, 2, ascii("SN-FIXTURE-001")],
    [0xa435, 2, ascii("LENS-FIXTURE-7")],
  ];
  const gpsSpecs = [
    [0x0001, 2, ascii("N")],
    [
      0x0002,
      5,
      rational([
        [10, 1],
        [30, 1],
        [0, 1],
      ]),
    ],
    [0x0003, 2, ascii("W")],
    [
      0x0004,
      5,
      rational([
        [20, 1],
        [15, 1],
        [0, 1],
      ]),
    ],
    [0x0005, 1, Buffer.from([0, 0, 0, 0])],
    [0x0006, 5, rational([[85, 2]])],
  ];
  const ifd0Offset = 8;
  const exifOffset = ifd0Offset + ifdSize(ifd0Specs);
  const gpsOffset = exifOffset + ifdSize(exifSpecs);
  let dataOffset = gpsOffset + ifdSize(gpsSpecs);
  const blobs = [];
  const place = (specs) => {
    const placed = [];
    for (const [tag, type, payload] of specs) {
      if (payload === "exif" || payload === "gps") {
        placed.push({
          tag,
          type,
          count: 1,
          value: payload === "exif" ? exifOffset : gpsOffset,
        });
        continue;
      }
      const count =
        type === 2 ? payload.length : type === 5 ? payload.length / 8 : 1;
      if (type === 1 || (type === 2 && payload.length <= 4)) {
        const inline = Buffer.alloc(4);
        payload.copy(inline);
        placed.push({ tag, type, count, inline });
      } else {
        placed.push({ tag, type, count, offset: dataOffset });
        blobs.push(payload);
        dataOffset += payload.length;
      }
    }
    return placed;
  };
  const directories = [place(ifd0Specs), place(exifSpecs), place(gpsSpecs)];
  const tiff = Buffer.alloc(dataOffset);
  tiff.write("II*\0", 0, "latin1");
  tiff.writeUInt32LE(8, 4);
  [ifd0Offset, exifOffset, gpsOffset].forEach((offset, index) => {
    const entries = directories[index];
    tiff.writeUInt16LE(entries.length, offset);
    entries.forEach((entry, entryIndex) => {
      const at = offset + 2 + entryIndex * 12;
      tiff.writeUInt16LE(entry.tag, at);
      tiff.writeUInt16LE(entry.type, at + 2);
      tiff.writeUInt32LE(entry.count, at + 4);
      if (entry.inline) entry.inline.copy(tiff, at + 8);
      else tiff.writeUInt32LE(entry.offset ?? entry.value, at + 8);
    });
    tiff.writeUInt32LE(0, offset + 2 + entries.length * 12);
  });
  let cursor = gpsOffset + ifdSize(gpsSpecs);
  for (const blob of blobs) {
    blob.copy(tiff, cursor);
    cursor += blob.length;
  }
  const payload = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), tiff]);
  const segment = Buffer.alloc(payload.length + 4);
  segment[0] = 0xff;
  segment[1] = 0xe1;
  segment.writeUInt16BE(payload.length + 2, 2);
  payload.copy(segment, 4);
  return Buffer.concat([jpeg.subarray(0, 2), segment, jpeg.subarray(2)]);
}

function removeDirectory(directory) {
  rmSync(directory, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100,
  });
}

function temporary(t) {
  const directory = mkdtempSync(join(tmpdir(), "osint-privacy-"));
  t.after(() => removeDirectory(directory));
  return directory;
}

function cli(directory, args, env = process.env) {
  const child = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("../src/cli.js", import.meta.url)), ...args],
    { cwd: directory, encoding: "utf8", env },
  );
  assert.ifError(child.error);
  const output = JSON.parse(child.stdout);
  assert.equal(child.status, output.ok ? 0 : 1);
  return output;
}

test("own-photo check reports coordinates and analyze-image still omits them", async () => {
  const photo = privacyJpeg();
  const report = await checkImageBytes(photo);
  assert.equal(report.persisted, false);
  assert.equal(report.network, false);
  assert.equal(report.rating, "high");
  assert.equal(report.gps.present, true);
  assert.equal(report.gps.latitude, 10.5);
  assert.equal(report.gps.longitude, -20.25);
  assert.equal(report.gps.altitude_meters, 42.5);
  assert.equal(
    report.findings.find((finding) => finding.tag === "BodySerialNumber")?.risk,
    "medium",
  );
  assert.equal(
    report.findings.find((finding) => finding.tag === "CameraOwnerName")?.value,
    "Fixture Owner",
  );
  assert.equal(
    report.findings.find((finding) => finding.tag === "Software")?.risk,
    "low",
  );
  assert.equal(isPrivacyClean(report), false);
  const analyzed = await inspectImage(photo);
  const encoded = JSON.stringify(analyzed);
  assert.equal(analyzed.gps_tags_present, true);
  assert.equal(encoded.includes("-20.25"), false);
  assert.equal(encoded.includes("10.5"), false);
  assert.equal(encoded.includes("SN-FIXTURE-001"), false);
  assert.equal(encoded.includes("Fixture Owner"), false);
  assert.equal(encoded.includes("latitude"), false);
});

test("scrub writes a clean copy and does not modify the original", async (t) => {
  const directory = temporary(t);
  const source = join(directory, "own.jpg");
  const output = join(directory, "public.jpg");
  const photo = privacyJpeg();
  writeFileSync(source, photo);
  const before = statSync(source);
  const result = await scrubImageFile(source, output);
  const after = statSync(source);
  assert.equal(result.status, "completed");
  assert.equal(result.clean, true);
  assert.equal(result.persisted, false);
  assert.equal(result.original_unchanged, true);
  assert.equal(result.rating_before, "high");
  assert.equal(result.rating_after, "none");
  assert.deepEqual(readFileSync(source), photo);
  assert.equal(after.mtimeMs, before.mtimeMs);
  assert.equal(after.size, before.size);
  const cleaned = await checkImageFile(output);
  assert.equal(isPrivacyClean(cleaned), true);
  assert.notEqual(result.output_sha256, result.original_sha256);
  await assert.rejects(() => scrubImageFile(source, source), /OUTPUT_IS_INPUT/);
  assert.deepEqual(readFileSync(source), photo);
});

test("privacy check does not create a workspace database", (t) => {
  const directory = temporary(t);
  const photo = join(directory, "own.jpg");
  const database = join(directory, "state.sqlite");
  writeFileSync(photo, privacyJpeg());
  writeFileSync(
    join(directory, "config.json"),
    readFileSync(new URL("../config.example.json", import.meta.url)),
  );
  const report = cli(directory, [
    "privacy-check-image",
    "--file",
    photo,
    "--config",
    "config.json",
    "--db",
    database,
  ]);
  assert.equal(report.ok, true);
  assert.equal(report.result.persisted, false);
  assert.equal(report.result.gps.latitude, 10.5);
  assert.equal(existsSync(database), false);
  const analyzed = cli(directory, ["analyze-image", "--file", photo]);
  assert.equal(JSON.stringify(analyzed).includes("-20.25"), false);
  assert.equal(analyzed.result.gps_tags_present, true);
  const folder = join(directory, "photos");
  mkdirSync(folder);
  writeFileSync(join(folder, "own.jpg"), privacyJpeg());
  writeFileSync(join(folder, "notes.txt"), "not a photo\n");
  const batch = cli(directory, ["privacy-check-image", "--dir", folder]);
  assert.equal(batch.result.count, 1);
  assert.deepEqual(batch.result.skipped, ["notes.txt"]);
  assert.equal(batch.result.files[0].rating, "high");
  assert.equal(batch.result.persisted, false);
});

test("a dirty scrub copy fails closed and the exiftool flag stays one argument", async (t) => {
  const directory = temporary(t);
  const photo = join(directory, "own.jpg");
  const output = join(directory, "still-dirty.jpg");
  const bytes = privacyJpeg();
  writeFileSync(photo, bytes);
  const before = statSync(photo);
  const missing = join(directory, "exiftool");
  await assert.rejects(
    () =>
      runProcess(
        missing,
        ["-all=", "-o", output, photo],
        { timeoutMs: 1000, maxBytes: 1024 },
        "",
        { allow: [missing] },
      ),
    (error) =>
      error instanceof OperationError && error.code === "TOOL_NOT_INSTALLED",
  );
  const result = await scrubImageFile(photo, output, "builtin", {
    strip: async (input) => Buffer.from(input),
  });
  const after = statSync(photo);
  assert.equal(result.status, "failed");
  assert.equal(result.code, "SCRUB_INCOMPLETE");
  assert.equal(result.clean, false);
  assert.equal(result.original_unchanged, true);
  assert.equal(result.persisted, false);
  assert.equal(after.mtimeMs, before.mtimeMs);
  assert.deepEqual(readFileSync(photo), bytes);
  assert.deepEqual(readFileSync(output), bytes);
});

test("missing scrub backends and same-path output leave the original in place", async (t) => {
  const directory = temporary(t);
  const photo = join(directory, "own.jpg");
  const output = join(directory, "clean.jpg");
  const bytes = privacyJpeg();
  writeFileSync(photo, bytes);
  const saved = process.env.PATH;
  process.env.PATH = directory;
  try {
    await assert.rejects(
      () => scrubImageFile(photo, output, "mat2"),
      /TOOL_NOT_INSTALLED/,
    );
    await assert.rejects(
      () => scrubImageFile(photo, output, "exiftool"),
      /TOOL_NOT_INSTALLED/,
    );
  } finally {
    process.env.PATH = saved;
  }
  assert.equal(existsSync(output), false);
  assert.equal(readFileSync(photo).equals(bytes), true);
  const failure = cli(directory, [
    "privacy-check-image",
    "--file",
    photo,
    "--scrub",
    "--output",
    photo,
  ]);
  assert.equal(failure.ok, false);
  assert.equal(failure.error.code, "OUTPUT_IS_INPUT");
  assert.equal(readFileSync(photo).equals(bytes), true);
});

test("doctor lists optional scrub backends without treating them as required", async () => {
  const diagnosed = await doctor(
    {
      config: { enabledAdapters: [] },
      dependencies: { locateBinary: () => null },
      providers: { health: () => ({ providers: [] }) },
      store: {
        db: {
          prepare: () => ({
            get: () => ({ user_version: 7, n: 0 }),
            run() {},
          }),
        },
      },
    },
    { probe: false },
  );
  assert.equal(diagnosed.status, "completed");
  assert.deepEqual(
    diagnosed.optional_binaries.map((tool) => [tool.name, tool.installed]),
    [
      ["exiftool", false],
      ["mat2", false],
    ],
  );
});

test(
  "MCP own-photo check returns coordinates and a scrubbed copy without a path",
  { timeout: 20_000 },
  async (t) => {
    const directory = mkdtempSync(join(tmpdir(), "osint-privacy-"));
    const config = join(directory, "config.json");
    writeFileSync(
      config,
      readFileSync(new URL("../config.example.json", import.meta.url)),
    );
    const client = new Client({ name: "privacy-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../src/mcp.js", import.meta.url))],
      env: {
        ...process.env,
        OSINT_POWER_CONFIG: config,
        OSINT_POWER_DB: join(directory, "state.sqlite"),
      },
      stderr: "pipe",
    });
    transport.stderr.on("data", () => {});
    t.after(async () => {
      await client.close();
      removeDirectory(directory);
    });
    await client.connect(transport);
    const names = (await client.listTools()).tools.map((tool) => tool.name);
    assert.equal(names.length, 50);
    assert.equal(names.includes("privacy_check_image"), true);
    const response = await client.callTool({
      name: "privacy_check_image",
      arguments: {
        data_base64: privacyJpeg().toString("base64"),
        scrub: true,
      },
    });
    assert.equal(response.isError, undefined);
    const result = response.structuredContent.result;
    assert.equal(result.persisted, false);
    assert.equal(result.network, false);
    assert.equal(result.file, null);
    assert.equal(result.gps.latitude, 10.5);
    assert.equal(result.gps.longitude, -20.25);
    assert.equal(result.scrub.clean, true);
    assert.equal(result.scrub.rating, "none");
    const scrubbed = Buffer.from(result.scrub.scrubbed_base64, "base64");
    assert.equal(isPrivacyClean(await checkImageBytes(scrubbed)), true);
    assert.equal(existsSync(join(directory, "state.sqlite")), true);
    const database = readFileSync(join(directory, "state.sqlite"));
    assert.equal(database.includes(Buffer.from("-20.25")), false);
    assert.equal(database.includes(Buffer.from("SN-FIXTURE-001")), false);
  },
);
