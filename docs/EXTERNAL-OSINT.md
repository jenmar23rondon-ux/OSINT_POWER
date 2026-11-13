# Import and compare external OSINT reports

Maigret v0.6.6 is the supported upstream report format. The producer is installed and operated separately. Import and comparison use the local SQLite workspace without launching external processes or contacting sites. [Maigret v0.6.6](https://github.com/soxoj/maigret/releases/tag/v0.6.6)

Review a single-username `simple` JSON export before sharing it with an MCP host. Keep the raw export in the operator's workspace. Maigret can include raw responses and extracted identifiers. The importer accepts only aliases listed explicitly in `scope.usernames` and direct public profile paths on GitHub, GitLab, or Codeberg. It drops query strings, fragments, extracted identifiers, and raw response content before storage.

```powershell
node src/cli.js import --adapter maigret --file reviewed-maigret.json --observed-at "2026-11-10T18:00:00-05:00"
node src/cli.js correlate-osint --id IMPORT_UUID
```

Use the actual observation time with a time zone. Maigret's native simple JSON includes claimed results and provides no complete coverage record. An empty export yields no candidates and leaves coverage unknown. An imported match stays a candidate. Overlap means the exact username or profile URL appears in another stored observation. It can occur when multiple tools read the same site. The response includes evidence IDs for review and keeps identity decisions independent.

In MCP, call `import_external_osint` with `adapter: "maigret"`, `data` containing the reviewed JSON, and `observed_at`. Then pass the returned `run_id` to `correlate_osint_results`. Use `next_cursor` to read subsequent pages. The existing CLI `evidence` command and MCP `get_evidence` can read the observations for a returned entity ID.
