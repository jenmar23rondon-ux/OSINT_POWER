import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createSocket } from "node:dgram";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { commandFor } from "../src/adapters.js";
import { runProcess } from "../src/transport.js";
import { parse } from "../src/parsers.js";
import { Config } from "../src/schema.js";
import { Scope } from "../src/scope.js";

const enabled = process.env.OSINT_POWER_NATIVE_LAB === "1";
const definitions = JSON.parse(
  readFileSync(new URL("../native-tools.lock.json", import.meta.url), "utf8"),
);
const binary = (name) =>
  fileURLToPath(
    new URL(
      `../.lab/${name}${process.platform === "win32" ? ".exe" : ""}`,
      import.meta.url,
    ),
  );
const config = Config.parse({
  version: 1,
  scope: { domains: ["lab.example.test"], ips: ["127.0.0.1"] },
  limits: { timeoutMs: 20000, maxBytes: 1000000, requestRate: 20 },
});
const scope = new Scope(config);
async function version(name) {
  const result = await runProcess(
    binary(name),
    ["-version", "-duc"],
    config.limits,
    "",
    { captureStderr: true },
  );
  assert.equal(
    result.includes(definitions[name].version.replace(/^v/, "")),
    true,
  );
}
async function server(t) {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/html", Server: "nginx" });
    res.end(
      "<html><head><title>OSINT POWER native lab</title></head><body>Fixture</body></html>",
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => {
    server.closeAllConnections();
    return new Promise((resolve) => server.close(resolve));
  });
  return server.address().port;
}

test(
  "pinned httpx fingerprints a loopback-only HTTP fixture",
  { skip: !enabled, timeout: 30000 },
  async (t) => {
    await version("httpx");
    const port = await server(t);
    const target = `http://127.0.0.1:${port}`;
    const plan = commandFor("httpx", target, config.limits);
    const output = await runProcess(
      binary("httpx"),
      plan.args,
      config.limits,
      plan.stdin,
    );
    const parsed = parse("httpx", output, scope);
    assert.equal(parsed.items.length > 0, true);
    assert.equal(parsed.items[0].evidence.status, 200);
    assert.equal(parsed.items[0].evidence.title, "OSINT POWER native lab");
  },
);
test(
  "pinned dnsx resolves using a local UDP DNS fixture",
  { skip: !enabled, timeout: 30000 },
  async (t) => {
    await version("dnsx");
    const socket = createSocket("udp4");
    let queries = 0;
    socket.on("message", (message, remote) => {
      queries++;
      let end = 12;
      while (message[end] && end < message.length) end += message[end] + 1;
      end++;
      const type = message.readUInt16BE(end);
      const question = message.subarray(12, end + 4);
      const header = Buffer.alloc(12);
      message.copy(header, 0, 0, 2);
      header.writeUInt16BE(0x8180, 2);
      header.writeUInt16BE(1, 4);
      header.writeUInt16BE(type === 1 ? 1 : 0, 6);
      const answer =
        type === 1
          ? Buffer.from([
              0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1,
            ])
          : Buffer.alloc(0);
      socket.send(
        Buffer.concat([header, question, answer]),
        remote.port,
        remote.address,
      );
    });
    socket.bind(0, "127.0.0.1");
    await once(socket, "listening");
    t.after(() => new Promise((resolve) => socket.close(resolve)));
    const plan = commandFor("dnsx", "lab.example.test", config.limits);
    const output = await runProcess(
      binary("dnsx"),
      [...plan.args, "-r", `127.0.0.1:${socket.address().port}`],
      config.limits,
      plan.stdin,
    );
    const parsed = parse("dnsx", output, scope);
    assert.equal(queries > 0, true);
    assert.equal(
      parsed.items.some(
        (item) => item.type === "ip" && item.value === "127.0.0.1",
      ),
      true,
    );
  },
);
test(
  "pinned naabu TCP-connect observes only the configured loopback port",
  { skip: !enabled || process.platform === "win32", timeout: 30000 },
  async (t) => {
    await version("naabu");
    const port = await server(t);
    const limits = { ...config.limits, ports: [port] };
    const plan = commandFor("naabu", "127.0.0.1", limits);
    const output = await runProcess(binary("naabu"), plan.args, limits);
    const parsed = parse("naabu", output, scope);
    assert.equal(
      parsed.items.some((item) => item.evidence.port === port),
      true,
    );
    assert.equal(
      parsed.items.every((item) => item.evidence.port === port),
      true,
    );
  },
);
