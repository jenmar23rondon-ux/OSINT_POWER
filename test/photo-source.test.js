import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import sharp from "sharp";
import { Engine } from "../src/engine.js";
import { verifyPhotoSource } from "../src/photo-source.js";
import { Store } from "../src/store.js";

test("a photo source check retrieves one approved public image and keeps the reference local", async (t) => {
  const reference = await sharp({
    create: { width: 16, height: 16, channels: 3, background: "#123456" },
  })
    .png()
    .toBuffer();
  const directory = mkdtempSync(join(tmpdir(), "osint-photo-source-"));
  const file = join(directory, "reference.png");
  writeFileSync(file, reference);
  const store = new Store();
  t.after(() => {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  });
  const input = {
    file,
    imageUrl: "https://images.example.com/public/image.png",
    approved: true,
  };
  let lookups = 0;
  let requests = 0;
  let addresses = ["93.184.215.14"];
  let statusCode = 200;
  let headers = { "content-type": "image/png" };
  let body = reference;
  const dependencies = {
    photoSourceResolve: async () => {
      lookups++;
      return addresses;
    },
    photoSourceRequest: (request, receive) => {
      requests++;
      assert.equal(request.method, "GET");
      assert.equal(request.hostname, "93.184.215.14");
      assert.equal(request.servername, "images.example.com");
      assert.equal(request.headers.host, request.servername);
      assert.equal(request.path, "/public/image.png");
      const outgoing = new EventEmitter();
      outgoing.end = (payload) => {
        assert.equal(payload, undefined);
        receive(Object.assign(Readable.from([body]), { statusCode, headers }));
      };
      return outgoing;
    },
  };
  const config = {
    version: 1,
    scope: {},
    network: true,
    limits: { maxBytes: 1024, minIntervalMs: 0 },
  };
  const engine = new Engine(config, store, dependencies);
  const offline = new Engine(
    { ...config, network: false },
    store,
    dependencies,
  );
  await assert.rejects(verifyPhotoSource(offline, input), /NETWORK_DISABLED/);
  await assert.rejects(
    verifyPhotoSource(engine, { ...input, approved: false }),
    /PHOTO_SOURCE_APPROVAL_REQUIRED/,
  );
  for (const imageUrl of [
    "https://127.0.0.1/x",
    "https://user:pass@images.example.com/x",
    input.imageUrl + "?token=secret",
  ])
    await assert.rejects(
      verifyPhotoSource(engine, { ...input, imageUrl }),
      /INVALID_REMOTE_PHOTO_URL/,
    );
  assert.equal(lookups, 0);

  const result = await verifyPhotoSource(engine, input);
  assert.equal(result.match, "exact");
  assert.equal(result.network, true);
  assert.equal(result.left_sha256, result.right_sha256);
  assert.equal(result.image_url, input.imageUrl);
  assert.equal(result.source_status, "image_retrieved");
  assert.equal(requests, 1);
  assert.equal(store.query().total, 0);

  statusCode = 302;
  headers = { location: "https://127.0.0.1/x" };
  await assert.rejects(
    verifyPhotoSource(engine, input),
    /PHOTO_SOURCE_HTTP_REJECTED/,
  );
  assert.equal(requests, 2);
  statusCode = 200;
  headers = { "content-type": "image/png" };
  body = Buffer.alloc(1025);
  await assert.rejects(
    verifyPhotoSource(engine, input),
    /PHOTO_SOURCE_TOO_LARGE/,
  );
  assert.equal(requests, 3);
  addresses = ["93.184.215.14", "::1"];
  await assert.rejects(
    verifyPhotoSource(engine, input),
    /PUBLIC_HTTPS_ADDRESS_REJECTED/,
  );
  assert.equal(requests, 3);
});
