# Import and compare external OSINT reports

## Maigret

Maigret v0.6.6 is the supported upstream report format. The producer is installed and operated separately. Import and comparison use the local SQLite workspace without launching external processes or contacting sites. [Maigret v0.6.6](https://github.com/soxoj/maigret/releases/tag/v0.6.6)

Review a single-username `simple` JSON export before sharing it with an MCP host. Keep the raw export in the operator's workspace. Maigret can include raw responses and extracted identifiers. The importer accepts only aliases listed explicitly in `scope.usernames` and direct public profile paths on GitHub, GitLab, or Codeberg. It drops query strings, fragments, extracted identifiers, and raw response content before storage.

```powershell
node src/cli.js import --adapter maigret --file reviewed-maigret.json --observed-at "2026-11-10T18:00:00-05:00"
node src/cli.js correlate-osint --id IMPORT_UUID
```

Use the actual observation time with a time zone. Maigret's native simple JSON includes claimed results and provides no complete coverage record. An empty export yields no candidates and leaves coverage unknown. An imported match stays a candidate. Overlap means the exact username or profile URL appears in another stored observation. It can occur when multiple tools read the same site. The response includes evidence IDs for review and keeps identity decisions independent.

In MCP, call `import_external_osint` with `adapter: "maigret"`, `data` containing the reviewed JSON, and `observed_at`. Then pass the returned `run_id` to `correlate_osint_results`. Use `next_cursor` to read subsequent pages. The existing CLI `evidence` command and MCP `get_evidence` can read the observations for a returned entity ID.

## SpiderFoot

Import a reviewed JSON event array from the SpiderFoot v4.0 web export. SpiderFoot runs separately. The adapter accepts `sfp_crt` domain and hostname events for explicitly configured scan targets. It drops analyst-flagged false positives, out-of-scope names, unrelated modules, and free-text fields. These observations document certificate names, and their upstream is crt.sh even if a direct crt.sh import recorded the same name. [SpiderFoot v4.0 export format](https://github.com/smicallef/spiderfoot/blob/v4.0/sfwebui.py#L496)

```powershell
node src/cli.js import --adapter spiderfoot-json --file reviewed-spiderfoot.json --source-utc-offset=-05:00
node src/cli.js correlate-osint --id IMPORT_UUID
```

Supply the UTC offset that applied to the export's `last_seen` values on the SpiderFoot host. Use `Z` for UTC. If the export spans an offset change, split it before import. The MCP arguments are `adapter: "spiderfoot-json"`, `data`, and `source_utc_offset`. The existing normalized `spiderfoot` bridge still accepts its original input.
