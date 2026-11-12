# Visual and identity evidence roadmap

OSINT_POWER already imports selected ExifTool metadata and stores scoped professional profiles, alias candidates, review decisions, and source provenance. The investigation graph and temporal query expose stored relationships. MX checks describe mail routing at the domain level.

## Inspect an image locally

```bash
node src/cli.js analyze-image --file authorized-photo.jpg
```

The CLI accepts regular files up to 16 MiB. MCP clients call `analyze_image` with `data_base64` for supplied bytes up to 2 MiB. Both paths recognize JPEG, PNG, WebP, and TIFF from the container bytes and return SHA-256, dimensions, and selected EXIF, XMP, and IPTC fields. Reports include a GPS presence flag and two consistency checks for dimensions and EXIF dates.

The SHA-256 digest identifies exact file bytes. Dimensions and selected fields come from header and metadata inspection. Pixel decoding, full container validation, and C2PA credential verification require separate processing. Metadata is untrusted and can be edited. Treat timing and dimension disagreements as review leads. Review reports before sharing because even allowed text fields can contain sensitive values.

`src/image-forensics.js` controls file reads, request size, concurrency, and the MCP response contract. `src/image-worker.js` parses the buffer in a worker with a five-second deadline and V8 heap limits. OS-level sandboxing would add controls for total memory and file or network permissions. Image bytes are handled in memory and the inspector returns JSON. The parser dependency is pinned in the lockfile. [ExifReader documentation](https://github.com/mattiasw/ExifReader)

## Compare images and extract text

```bash
node src/cli.js compare-images --file original.png --other candidate.webp
node src/cli.js ocr-image --file authorized-scan.png --language spa
```

MCP `compare_images` takes `left_base64` and `right_base64`. MCP `ocr_image` takes `data_base64` and optional `language`. CLI files are limited to 16 MiB and each MCP image is limited to 2 MiB. OCR uses a Tesseract executable from an absolute directory on PATH. Install the default English data (`eng`) or Spanish data (`spa`) in the engine's normal language directory. GitHub CI checks English OCR on a generated image. [Tesseract command-line documentation](https://tesseract-ocr.github.io/tessdoc/Command-Line-Usage.html)

The comparison reports SHA-256, exact-byte equality, and a 63-bit grayscale perceptual distance. Whole images within 8 bits are similarity candidates. For crops, the search tests 50% and 75% regions at fixed positions in either image and reports the best candidate within 6 bits. Crop coordinates refer to the auto-oriented source image. Flat images can be inconclusive, grayscale hashes can miss color-only differences, and the fixed search can miss arbitrary crops. Synthetic fixtures establish expected behavior for known transforms. Use an independent labeled corpus to calibrate thresholds for a real collection.

JPEG, PNG, WebP, and TIFF pixels are decoded by a bounded subprocess. Comparison and OCR accept single-frame images up to 20 million pixels. The decoder uses a fixed loader allowlist and the existing process runner enforces deadlines and output limits. OCR receives a normalized grayscale PNG with a maximum side of 1600 pixels. It returns up to 8000 characters as untrusted text, with redaction of common credential patterns. Review text before sharing. [Sharp input controls](https://sharp.pixelplumbing.com/api-constructor/)

## Prioritized pull requests

| Priority | Change                                       | Reusable components                           | Acceptance                                                                                                                                            |
| -------- | -------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| P0       | Local image metadata and SHA-256             | JSON CLI and MCP contracts                    | Recover expected dimensions and metadata from synthetic containers, match exact digests, reject malformed inputs, omit GPS values, and enforce limits |
| P0       | Corroboration for existing account links     | Review resolver and observation provenance    | Keep ambiguous links as candidates when individual identifiers lack independent support                                                               |
| P1       | Search an authorized local image collection  | Pairwise similarity and case evidence         | Measure false matches and retrieval coverage on independently labeled crops and edits                                                                 |
| P1       | Account and domain control evidence          | Analyst decisions and the temporal graph      | Bind consented proofs to a subject and timestamp, then distinguish account or domain control from personal identity                                   |
| P1       | Public-scene evidence and local video frames | Case review and temporal evidence             | Use public landmarks and labeled synthetic cases, record alternatives, and measure wrong-location rates                                               |
| P2       | Visual analyst and workbench                 | Reports, typed MCP contracts, and review plan | Keep raw media in the authorized workspace and cite each observation in analyst review                                                                |

Future media changes should measure parsing accuracy, processing time, resource use, and accidental disclosure on synthetic fixtures. Identity changes should measure false links on independently labeled cases with reused names, recycled accounts, and mirrored sources. Public professional claims and content can be represented as sourced observations, with personal identity reserved for reviewed evidence.
