# Adapter contracts

A closed registry defines available collectors. Targets pass scope validation before arguments are constructed. Clients cannot supply executables, arbitrary flags, provider URLs or shell commands.

## Execution

| Adapter        | Contract                                                                                                  |
| -------------- | --------------------------------------------------------------------------------------------------------- |
| crtsh          | Fixed crt.sh API, name_value array                                                                        |
| certspotter    | Fixed CT Search v1 issuance API; one page, persistent after cursor, optional environment key              |
| wayback        | Fixed HTTPS CDX index; four-column JSON, one page, persistent resume key, historical hostname/URL records |
| subfinder      | Passive domain input, silent output, rate and timeout flags                                               |
| amass          | Legacy enum -passive -nocolor interface; verify installed compatibility                                   |
| dnsx           | One host on stdin, JSON A/AAAA, one worker and rate limit                                                 |
| httpx          | One host on stdin, JSON status/technology/title/TLS, no redirects                                         |
| naabu          | One host, explicit ports, TCP connect, bounded workers/rate                                               |
| mx             | Native Node DNS MX resolver; no SMTP validation                                                           |
| rdap           | IANA bootstrap followed by an allowlisted RIR; no redirects                                               |
| routing        | Fixed RIPEstat Network Info API                                                                           |
| github-profile | Fixed public GitHub profile API for a scoped alias                                                        |
| sherlock       | One alias, local catalog, configured professional sites, temporary CSV                                    |
| theharvester   | crtsh/certspotter source selection, bounded result request and temporary JSON                             |
| hibp           | Fixed breachedaccount endpoint, names and dates only                                                      |

Arguments are defined in source and verified by contract tests. Native rate behavior depends on the upstream version. Amass/Sherlock/theHarvester do not expose one universal HTTP limit through these wrappers: configure source quotas and check installed behavior. Wrapper timeout/byte limits are not a firewall or a per-request sandbox.

Subprocesses use shell-free argument arrays only. The command must be an allowlisted binary name (`subfinder`, `amass`, `dnsx`, `httpx`, `naabu`, `sherlock`, `theHarvester`) or an absolute path whose basename is on that list. User-supplied targets are rejected when they start with `-`, contain `..`, or contain shell metacharacters; other arguments are rejected when they contain shell metacharacters or do not match a simple flag shape. Windows consoles are hidden. The child environment keeps path and per-user configuration variables only, not API keys.

On timeout, cancellation, or output overflow the wrapper kills the process tree. POSIX starts the child in its own process group and signals that group with SIGTERM, then SIGKILL. Windows runs `taskkill /T` and then `taskkill /T /F`. stdout and stderr share the configured byte cap; the captured text keeps the prefix that fits and ends with `[OSINT_POWER_OUTPUT_TRUNCATED]`, and the run fails with `RESPONSE_TOO_LARGE`. One OS process runs at most four native binaries at a time. That cap is in-process; SQLite provider quotas remain the cross-process control.

CPU niceness (`os.setPriority`) and, on Linux when `/usr/bin/prlimit` exists, a CPU-time rlimit a little above the wall-clock timeout are best-effort backstops. They do not preempt a run that finishes within the timeout, because CPU time cannot exceed wall time. Memory address-space limits are not applied: Go recon tools reserve large virtual ranges, and `RLIMIT_AS` breaks them. Use a cgroup, Windows job object, or container for a hard memory cap. A grandchild that calls `setsid` leaves the POSIX process group; this wrapper is not a sandbox or a firewall.

Credentials stay in native provider files or the documented HIBP/Cert Spotter environment variables. Processes sharing one SQLite workspace coordinate provider reservations; separate databases or machines require external coordination. Native quotas count invocations, not internal requests. Before a native tool is launched, collection calls the existing `Scope.target` check again. Network, active-mode, and adapter gates are unchanged.

Historical APIs also support imports using their documented projected response formats. Imports never modify live continuation state. Wayback expects timestamp/original/statuscode/digest columns, optionally followed by an empty row and a one-field resume-key row. See [v0.4 formats and recovery](V0.4.md).

## Imports

- subfinder/amass: plain names or JSONL host/name fields, not full Amass graph exports.
- dnsx: host, a and aaaa.
- httpx: url, status_code, tech, title and optional TLS subject/issuer.
- naabu: host/ip and port.
- sherlock: native CSV with username, url_user and exists=Claimed. The debug dump-response option is not a JSON export.
- theharvester: JSON emails/hosts lists.
- exiftool: JSON array with SourceFile and selected Author/Creator/Producer/Software/Title fields.
- gitleaks/trufflehog: native report locations and detector/rule identifiers; no raw secret values.
- whatsmyname: bridge objects with username, url and found/not_found/unknown status.
- business-context: strict sourced professional/office assertions.
- breach-summary: strict provider/email/breach/date metadata.
- recon-ng/spiderfoot/jsonl: this project's normalized observation schema; native conversion may be necessary.

```bash
node src/cli.js import --adapter sherlock --file reviewed.csv
node src/cli.js import --adapter gitleaks --file reviewed-report.json
node src/cli.js import --adapter business-context --file examples/business-context.jsonl
```

Only configured document basenames are accepted for document/secret imports. Identical basenames are ambiguous; use distinct names or workspaces. Sanitization is not a universal detector for arbitrary secrets in free text: minimize exports before sharing them.

Generic imported confidence is capped at 0.7. Evidence keys and values are bounded. URL query strings/fragments are removed. Secret entity values are reconstructed from location metadata and marked unverified.

## Add a source

1. Define strict input schemas and a fixed provider or known binary interface.
2. Register its collection mode without accepting arbitrary commands.
3. Bound responses and keep stdout exclusively MCP.
4. Normalize observations and apply scope filtering.
5. Test success, malformed data, exclusions, failures, redirects and quota handling using synthetic fixtures.
6. Document formats, credentials, compatibility and confidence.
7. Run tests, lint, schema generation and dependency audit without external target traffic.

HTTP network errors, 429 and 5xx are retried at most three attempts total with backoff and Retry-After. Permanent errors and subprocess failures are not automatically retried. A failed source preserves findings from other stages.

## Primary references

[ProjectDiscovery tools](https://projectdiscovery.io/open-source) · [httpx options](https://docs.projectdiscovery.io/opensource/httpx/usage) · [naabu options](https://docs.projectdiscovery.io/opensource/naabu/usage) · [Amass guide](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md) · [Sherlock source](https://github.com/sherlock-project/sherlock/blob/master/sherlock_project/sherlock.py) · [theHarvester source](https://github.com/laramies/theHarvester/blob/master/theHarvester/__main__.py) · [HIBP API](https://haveibeenpwned.com/API/v3).

See [workflows](WORKFLOWS.md) for execution modes, context schemas and limitations.
