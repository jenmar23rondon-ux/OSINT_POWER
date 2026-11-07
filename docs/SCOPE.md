# Scope and data handling

Use a separate workspace per investigation and record assets, exclusions and applicable limits. Public availability and passive access do not imply universal permission for every use of the data.

## Enforced controls

- Configured domains include descendants; excluded domains and descendants take priority.
- Suffix confusion is rejected: example.com.evil.invalid does not belong to example.com.
- Active IP targets require exact configured addresses; CIDR target ranges are not implemented.
- Discovered IPs may receive passive registry/routing enrichment without authorizing active scanning.
- Email imports need a scoped domain or exact account. HIBP always needs the exact configured account.
- Professional subjects and aliases are explicit. Derived aliases remain candidates.
- Office context requires public_office and a source; no residential-location inference.
- Document/metadata/secret imports require allowed document basenames.
- Unresolved observations require a related scoped host.
- API redirects are disabled; httpx is not given redirect-following flags.

Upstream binaries can use native configuration and internal requests the wrapper does not intercept. Review them and impose host egress policies when connection-level control is required. This project is not a firewall.

## Local state

SQLite, cache, configuration and run history are local, ignored by Git and not encrypted. History records adapter, target, timing, status and summaries. Imports record an input hash. Raw subprocess stdout/stderr is not stored in reports.

The database is bound to its initial scope fingerprint. Select a new database for different subjects or assets. Empty people defaults preserve v0.1 scope fingerprints. Stop processes before backup and apply your retention policy to the complete workspace.

HIBP stores breach metadata. Secret importers discard raw values and keep locations/rules. Before publishing, review source documents, personal data, filenames and exports; sanitization is best effort for arbitrary free text.

## Boundaries

No exploitation, credential-validity testing, account actions, password retrieval, automatic identity confirmation or employee attack-target scoring is implemented. Public professional context is not proof of employment or identity. IP location and registry country do not establish an office.

The Docker image runs as an unprivileged user. Set CPU, memory and egress restrictions on the host. External binaries are not automatically installed or considered sandboxed merely because Node launches them.
