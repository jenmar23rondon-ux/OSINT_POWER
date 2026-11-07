# Investigation quality benchmark

Run `npm run benchmark` or `node benchmarks/runner.js --output benchmark.json`. The optional output path must not exist. The benchmark uses real parsers, normalization, scope validation, SQLite ingestion, graph construction and mocked API collection. It makes no external requests or model calls.

`benchmarks/cases.json` contains 17 labeled scenarios with explicit expected entities and relationships. Cases cover deduplication, IDNs, exclusions/suffix confusion, overlapping CT sources, certificate wildcards, historical versus live URLs, shared IP infrastructure, username collisions, unknown accounts, mismatched profiles, public emails, breach-only associations, secret references, invalid calendar dates, stale evidence and conflicting public-company assertions.

The runner reports true/false positives and false negatives for entities and relationships, precision/recall against the fixture labels, semantic failures, mocked HTTP request counts and elapsed runtime. Per-source yield reports new entities in fixture order. CI fails if a case introduces an unexpected finding/relationship, loses an expected one, or violates a labeled semantic check. Runtime is informational and has no platform-dependent threshold.

The initial corpus expects 24 entity findings and 8 distinct relationships across its independent workspaces. A perfect score on this small synthetic corpus is not an estimate of real-world precision or recall. No statistical confidence calibration is claimed. Add reviewed, legally redistributable examples and independently maintained gold labels before using benchmark scores to make production accuracy claims.

To extend the corpus, add a case with descriptive tags, collection/import steps, explicit expected entity/relationship tuples and optional assessment expectations. Confirm that labels express the evidence available in the fixture. Keep historical assets, uncertain identity links and ownership assertions separate. Never add real passwords, tokens or personal investigation data.
