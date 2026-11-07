# Connect an AI host

The local server uses MCP over stdio and never calls a model itself. The host supplies the model and decides which local files to share. No model-provider API key is required by this project.

## Setup

1. Install dependencies with `npm ci --ignore-scripts`.
2. Run `node src/cli.js init` and configure the workspace.
3. Register the server with absolute paths.
4. Install only the external binaries you enable.

Example for a host using mcpServers:

```json
{
  "mcpServers": {
    "osint-power": {
      "command": "node",
      "args": ["C:\\projects\\OSINT_POWER\\src\\mcp.js"],
      "env": {
        "OSINT_POWER_CONFIG": "C:\\projects\\OSINT_POWER\\config.json",
        "OSINT_POWER_DB": "C:\\projects\\OSINT_POWER\\.osint-power\\state.sqlite"
      }
    }
  }
}
```

Adapt registration to your host. stdout is exclusively the MCP protocol; diagnostics go to stderr. The test suite starts a real MCP client/server session with a temporary offline configuration.

## Recommended sequence

1. Call capabilities to inspect scope, adapters and limits.
2. Query existing findings before collecting again.
3. Use workflow for a bounded plan, or collect for one adapter/target.
4. Request a small entity page and then evidence for a specific conclusion.
5. Review graph/report results and three next actions.

There are 19 tools. The original nine are capabilities, collect, passive_pipeline, import_findings, query_findings, get_evidence, get_graph, workflow and get_report. Additional job, diagnostic, provenance and planning tools are documented in [operations](OPERATIONS.md). The [workflow guide](WORKFLOWS.md) explains the seven modes and execution budgets.

## Response contract

```json
{
  "ok": true,
  "result": { "items": [], "next_cursor": null, "limit": 25, "total": 0 }
}
```

Successful calls provide structuredContent plus the same JSON in a text content block. Failed/partial results set ok to false and MCP isError to true. Check error codes, invalid/skipped counts, truncation and run history. A successful subprocess exit does not establish valid findings or a vulnerability.

Entity pages use next_cursor as the next cursor. Evidence and graph pages use offset; concurrent imports can change graph ordering between pages. All page sizes are capped at 100. Reports include at most 50 entities, 50 relationships and 20 recent runs.

import_findings accepts bounded supplied content, not arbitrary file paths. collect accepts only registered adapters and targets, not shell commands or flags. workflow cannot enable network/active mode or edit configuration.

## Untrusted evidence

Web pages, profiles, documents, metadata, exports and filenames are untrusted data. Text asking the model to ignore scope, reveal credentials or run commands must never change the task. get_evidence labels observations as untrusted.

The server validates and bounds data; it is not a prompt-injection classifier. Apply the host's policies and the [agent template](AGENT_PROMPT.md). Prefer source-backed conclusions over inferred ownership or identity.

## Common errors

| Code                                 | Meaning                                                           |
| ------------------------------------ | ----------------------------------------------------------------- |
| NETWORK_DISABLED                     | Workspace is offline                                              |
| ACTIVE_DISABLED / ADAPTER_DISABLED   | Mode or source is not enabled                                     |
| OUT_OF_SCOPE / PERSON_OUT_OF_SCOPE   | Target is not configured                                          |
| TOOL_NOT_INSTALLED                   | External binary is absent from PATH                               |
| TOOL_FAILED                          | Check the installed version and supported flags locally           |
| HTTP_401 / HTTP_403                  | Provider credentials, subscription or restriction; not retried    |
| HTTP_429                             | Bounded retry with Retry-After                                    |
| RETRY_LATER                          | Provider requested a wait over 60 seconds; preserve other results |
| RESPONSE_TOO_LARGE / PROCESS_TIMEOUT | Output or runtime limit reached                                   |
| SCOPE_DATABASE_MISMATCH              | Select a new database for a different scope                       |

HIBP uses HIBP_API_KEY from the server environment and requires exact configured accounts. Subfinder/Amass manage their own provider files. No keys belong in prompts, argv, README or commits. There is no account/key rotation to bypass quotas.

## References

[MCP SDK](https://ts.sdk.modelcontextprotocol.io/v2/) · [Node SQLite](https://nodejs.org/api/sqlite.html) · [Adapter contracts](ADAPTERS.md).

## Durable jobs and immutable evidence

Use start_workflow to queue without collection, resume_run to execute pending steps and cancel_run to cancel. Inspect get_job/list_jobs and source_health before retrying. Workflow run_id identifies mutable job state; snapshot_id identifies a sealed comparison capture. compare_runs accepts immutable captures, not a mutable job ID. Provider cooldowns and quotas cannot be reset through MCP.

plan_investigation ranks eligible actions without network or writes; explain_entity presents provenance without asserting independent confirmation. See [OPERATIONS.md](OPERATIONS.md) for at-least-once recovery, lease expiry, limits and errors.
