# Visual and identity evidence roadmap

OSINT_POWER already imports selected ExifTool metadata and stores scoped professional profiles, alias candidates, review decisions, and source provenance. The investigation graph and temporal query expose stored relationships. MX checks describe mail routing at the domain level.

## Inspect an image locally

```bash
node src/cli.js analyze-image --file authorized-photo.jpg
```

The CLI accepts regular files up to 16 MiB. MCP clients call `analyze_image` with `data_base64` for supplied bytes up to 2 MiB. Both paths recognize JPEG, PNG, WebP, and TIFF from the container bytes and return SHA-256, dimensions, and selected EXIF, XMP, and IPTC fields. Reports include a GPS presence flag and two consistency checks for dimensions and EXIF dates.

The SHA-256 digest identifies exact file bytes. Dimensions and selected fields come from header and metadata inspection. Pixel decoding, full container validation, and C2PA credential verification require separate processing. Metadata is untrusted and can be edited. Treat timing and dimension disagreements as review leads. Review reports before sharing because even allowed text fields can contain sensitive values.

`src/image-forensics.js` controls file reads, request size, concurrency, and the MCP response contract. `src/image-worker.js` parses the buffer in a worker with a five-second deadline and V8 heap limits. OS-level sandboxing would add controls for total memory and file or network permissions. Image bytes are handled in memory and the inspector returns JSON. The parser dependency is pinned in the lockfile. [ExifReader documentation](https://github.com/mattiasw/ExifReader)

## Prioritized pull requests

| Priority | Change                                           | Reusable components                           | Acceptance                                                                                                                                            |
| -------- | ------------------------------------------------ | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| P0       | Local image metadata and SHA-256                 | JSON CLI and MCP contracts                    | Recover expected dimensions and metadata from synthetic containers, match exact digests, reject malformed inputs, omit GPS values, and enforce limits |
| P0       | Corroboration for existing account links         | Review resolver and observation provenance    | Keep ambiguous links as candidates when individual identifiers lack independent support                                                               |
| P1       | Compare images in an authorized local collection | Image digest and case evidence                | Test exact duplicates and measure false matches for crops and edits on labeled images                                                                 |
| P1       | Account and domain control evidence              | Analyst decisions and the temporal graph      | Bind consented proofs to a subject and timestamp, then distinguish account or domain control from personal identity                                   |
| P1       | Public-scene evidence and local video frames     | Case review and temporal evidence             | Use public landmarks and labeled synthetic cases, record alternatives, and measure wrong-location rates                                               |
| P2       | Visual analyst and workbench                     | Reports, typed MCP contracts, and review plan | Keep raw media in the authorized workspace and cite each observation in analyst review                                                                |

Future media changes should measure parsing accuracy, processing time, resource use, and accidental disclosure on synthetic fixtures. Identity changes should measure false links on independently labeled cases with reused names, recycled accounts, and mirrored sources. Public professional claims and content can be represented as sourced observations, with personal identity reserved for reviewed evidence.
