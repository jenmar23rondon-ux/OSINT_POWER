import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import { allowedWebhook, postWebhook } from "../src/webhook.js";

const destination = "https://alerts.example.com/notifications";
const options = {
  body: '{"alerts":[]}',
  headers: {},
  signal: AbortSignal.timeout(5000),
};

test("webhook authorization requires an exact approved HTTPS destination", () => {
  for (const value of [
    "http://alerts.example.com/notifications",
    "https://127.0.0.1/notifications",
    "https://2130706433/notifications",
    "https://[::1]/notifications",
    "https://alerts.internal/notifications",
    "https://host.home.arpa/notifications",
    "https://user@alerts.example.com/notifications",
    "https://alerts.example.com:8443/notifications",
    "https://alerts.example.com/notifications#fragment",
  ])
    assert.throws(() => allowedWebhook(value, [value]), /WEBHOOK_URL_REJECTED/);
  for (const value of [
    destination + "/other",
    destination + "?different=1",
    "https://alerts.example.com.other.com/notifications",
  ])
    assert.throws(
      () => allowedWebhook(value, [destination]),
      /WEBHOOK_DESTINATION_NOT_ALLOWED/,
    );
  assert.throws(
    () => allowedWebhook(destination, []),
    /WEBHOOK_DESTINATION_NOT_ALLOWED/,
  );
  assert.equal(allowedWebhook(destination, [destination]).href, destination);
});

test("private, reserved, and mixed DNS responses stop before a connection", async () => {
  for (const addresses of [
    [],
    ["0.1.2.3"],
    ["10.1.2.3"],
    ["100.64.0.1"],
    ["127.0.0.1"],
    ["169.254.169.254"],
    ["172.16.0.1"],
    ["192.168.1.1"],
    ["198.18.0.1"],
    ["192.0.2.1"],
    ["239.0.0.1"],
    ["::"],
    ["::1"],
    ["::ffff:127.0.0.1"],
    ["64:ff9b::808:808"],
    ["fc00::1"],
    ["fe80::1%eth0"],
    ["ff02::1"],
    ["2001:db8::1"],
    ["2002::1"],
    ["3fff::1"],
    ["93.184.215.14", "fd00::1"],
    ["2606:4700::1111", "10.0.0.1"],
  ]) {
    let connections = 0;
    await assert.rejects(
      postWebhook(new URL(destination), options, {
        webhookResolve: async () => addresses,
        webhookRequest: () => {
          connections++;
        },
      }),
      /WEBHOOK_ADDRESS_REJECTED/,
    );
    assert.equal(connections, 0);
  }
});

test("webhook transport pins the IP, keeps hostname TLS verification, and refuses redirects", async () => {
  for (const [address, family, status] of [
    ["93.184.215.14", 4, 302],
    ["2606:4700::1111", 6, 204],
  ]) {
    let lookups = 0;
    let connections = 0;
    const response = await postWebhook(new URL(destination), options, {
      webhookResolve: async (host) => {
        assert.equal(host, "alerts.example.com");
        return ++lookups === 1 ? [address] : ["127.0.0.1"];
      },
      webhookRequest: (request, respond) => {
        connections++;
        assert.equal(request.hostname, address);
        assert.equal(request.family, family);
        assert.equal(request.servername, "alerts.example.com");
        assert.equal(request.headers.host, request.servername);
        assert.equal(request.rejectUnauthorized, true);
        assert.equal(request.agent, false);
        const req = new EventEmitter();
        req.end = (body) => {
          assert.equal(body, options.body);
          respond({
            statusCode: status,
            headers: { location: "https://127.0.0.1/private" },
            destroy() {},
          });
        };
        return req;
      },
    });
    assert.equal(response.status, status);
    assert.equal(response.ok, status === 204);
    assert.equal(lookups, 1);
    assert.equal(connections, 1);
  }
});
