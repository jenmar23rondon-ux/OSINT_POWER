import test from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

test(
  "real stdio MCP: handshake, discovery, import, query, evidence and validation",
  { timeout: 20_000 },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "osint-mcp-"));
    const config = join(dir, "config.json");
    writeFileSync(
      config,
      readFileSync(new URL("../config.example.json", import.meta.url)),
    );
    const client = new Client({ name: "osint-power-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../src/mcp.js", import.meta.url))],
      env: { ...process.env, OSINT_POWER_CONFIG: config },
      stderr: "pipe",
    });
    let stderr = "";
    transport.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    t.after(async () => {
      await client.close();
      rmSync(dir, { recursive: true, force: true });
    });
    await client.connect(transport);
    const list = await client.listTools();
    assert.equal(list.tools.length, 8);
    const call = (name, args = {}) =>
      client.callTool({ name, arguments: args });
    assert.equal(
      (await call("capabilities")).structuredContent.result.network,
      false,
    );
    assert.equal(
      (
        await call("import_findings", {
          adapter: "subfinder",
          data: "api.example.com",
        })
      ).structuredContent.result.inserted,
      1,
    );
    const page = (await call("query_findings", { limit: 1 })).structuredContent
      .result;
    assert.equal(page.items[0].value, "api.example.com");
    assert.equal(
      (await call("get_evidence", { entity_id: page.items[0].id }))
        .structuredContent.result.items[0].untrusted,
      true,
    );
    assert.equal(
      (await call("collect", { adapter: "crtsh", target: "example.com" }))
        .isError,
      true,
    );
    assert.equal(
      (await call("query_findings", { limit: 10000 })).isError,
      true,
    );
    assert.equal(
      (await call("get_report")).structuredContent.result.next_actions.length,
      3,
    );
    assert.equal(stderr.includes("SyntaxError"), false);
  },
);
