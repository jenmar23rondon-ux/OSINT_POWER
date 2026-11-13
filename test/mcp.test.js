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
    assert.equal(list.tools.length, 51);
    for (const tool of list.tools) {
      assert.equal(tool.outputSchema.additionalProperties, false);
      assert.equal(tool.outputSchema.properties.schema_version.const, "0.4");
      assert.equal(tool.outputSchema.properties.result.anyOf.length, 2);
    }
    const call = (name, args = {}) =>
      client.callTool({ name, arguments: args });
    const url = "https://github.com/example-researcher";
    const imported = (
      await call("import_external_osint", {
        adapter: "maigret",
        observed_at: "2026-11-10T23:00:00Z",
        data: JSON.stringify({
          GitHub: {
            url_user: url,
            status: {
              username: "example-researcher",
              site_name: "GitHub",
              url,
              status: "Claimed",
            },
          },
        }),
      })
    ).structuredContent;
    assert.equal(imported.result.inserted, 2);
    assert.equal(imported.coverage.complete, false);
    const overlap = (
      await call("correlate_osint_results", { run_id: imported.result.run_id })
    ).structuredContent;
    assert.equal(overlap.result.items.length, 2);
    assert.ok(
      overlap.result.items.every(
        (item) => item.other_observations.length === 0,
      ),
    );
    const spiderfoot = (
      await call("import_external_osint", {
        adapter: "spiderfoot-json",
        source_utc_offset: "Z",
        data: JSON.stringify([
          {
            data: "api.example.com",
            scan_target: "example.com",
            module: "sfp_crt",
            event_type: "INTERNET_NAME",
            false_positive: 0,
            last_seen: "2026-11-10 23:00:00",
          },
        ]),
      })
    ).structuredContent;
    assert.equal(spiderfoot.result.inserted, 1);
    assert.equal(spiderfoot.coverage.complete, false);
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
    const page = (await call("query_findings", { type: "domain", limit: 1 }))
      .structuredContent.result;
    assert.equal(page.items[0].value, "api.example.com");
    assert.equal(
      (await call("doctor", { probe: false })).structuredContent.result
        .network_probe,
      false,
    );
    const queued = (
      await call("start_workflow", {
        workflow: "correlation",
        target: "example.com",
      })
    ).structuredContent.result;
    assert.equal(queued.status, "queued");
    assert.equal(
      (await call("get_job", { id: queued.id })).structuredContent.result
        .status,
      "queued",
    );
    assert.equal(
      (await call("resume_run", { id: queued.id })).structuredContent.result
        .status,
      "completed",
    );
    assert.equal(
      (await call("explain_entity", { entity_id: page.items[0].id }))
        .structuredContent.result.history.length,
      2,
    );
    assert.equal(
      (
        await call("plan_investigation", {
          workflow: "company",
          target: "example.com",
        })
      ).structuredContent.result.network,
      false,
    );
    const workflow = await call("workflow", {
      workflow: "empresa",
      target: "example.com",
    });
    assert.equal(workflow.structuredContent.result.status, "planned");
    assert.equal(
      (await call("query_findings", {})).structuredContent.result.total,
      3,
    );
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
    const checked = async (name, args = {}) => {
      const response = await call(name, args);
      assert.notEqual(
        response.structuredContent?.result.code,
        "INTERNAL_OUTPUT_VALIDATION",
        name,
      );
      assert.equal(response.isError, undefined, name);
      return response.structuredContent;
    };
    await checked("get_graph");
    const image = await checked("analyze_image", {
      data_base64:
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aF9sAAAAASUVORK5CYII=",
    });
    assert.equal(image.result.format, "png");
    assert.equal(image.result.network, false);
    const png =
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAADElEQVQImWP4//8/AAX+Av5Y8msOAAAAAElFTkSuQmCC";
    const comparison = await checked("compare_images", {
      left_base64: png,
      right_base64: png,
    });
    assert.equal(comparison.result.match, "exact");
    const copies = await checked("search_image_copies", {
      query_base64: png,
      candidates: [{ id: "copy", data_base64: png }],
    });
    assert.equal(copies.result.network, false);
    assert.equal(copies.result.matches[0].id, "copy");
    assert.equal(copies.result.matches[0].match, "exact");
    const recorded = await checked("import_findings", {
      adapter: "dnsx",
      data: JSON.stringify({ host: "api.example.com", a: ["192.0.2.10"] }),
    });
    const cutoff = Date.now();
    const history = await checked("temporal_graph", {
      host: "api.example.com",
      since: new Date(cutoff - 60_000).toISOString(),
      until: new Date(cutoff + 60_000).toISOString(),
      as_of: new Date(cutoff).toISOString(),
    });
    assert.equal(history.result.items[0].run_id, recorded.result.run_id);
    assert.equal(history.result.items[0].to, "192.0.2.10");
    await checked("list_jobs");
    await checked("source_health");
    const before = (
      await checked("import_findings", {
        adapter: "subfinder",
        data: "before.example.com",
      })
    ).result.run_id;
    const after = (
      await checked("import_findings", {
        adapter: "subfinder",
        data: "after.example.com",
      })
    ).result.run_id;
    await checked("compare_runs", { before, after });
    const exported = await checked("export_evidence", { run_id: after });
    assert.equal(exported.result.page.complete, true);
    const partial = await checked("import_findings", {
      adapter: "subfinder",
      data: "valid.example.com\n--invalid",
    });
    assert.equal(partial.ok, true);
    assert.equal(partial.collection_status, "partial");
    assert.equal(partial.coverage.complete, false);
    const pipeline = await checked("passive_pipeline", {
      target: "example.com",
    });
    assert.equal(pipeline.collection_status, "partial");
    const job2 = (
      await checked("start_workflow", {
        workflow: "correlation",
        target: "example.com",
      })
    ).result;
    await checked("cancel_run", { id: job2.id });
    await checked("get_job", { id: queued.id });
    assert.equal(stderr.includes("SyntaxError"), false);
  },
);
