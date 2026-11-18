# Visual and identity evidence roadmap

OSINT_POWER already imports selected ExifTool metadata and stores scoped professional profiles, alias candidates, review decisions, and source provenance. The investigation graph and temporal query expose stored relationships. MX checks describe mail routing at the domain level.

## Inspect an image locally

```bash
node src/cli.js analyze-image --file authorized-photo.jpg
```

The CLI accepts regular files up to 16 MiB. MCP clients call `analyze_image` with `data_base64` for supplied bytes up to 2 MiB. Both paths recognize JPEG, PNG, WebP, and TIFF from the container bytes and return SHA-256, dimensions, and selected EXIF, XMP, and IPTC fields. Reports include a GPS presence flag and two consistency checks for dimensions and EXIF dates.

The SHA-256 digest identifies exact file bytes. Dimensions and selected fields come from header and metadata inspection. Pixel decoding, full container validation, and C2PA credential verification require separate processing. Metadata is untrusted and can be edited. Treat timing and dimension disagreements as review leads. Review reports before sharing because even allowed text fields can contain sensitive values.

`analyze-image` and `analyze_image` are the investigation view. They set `gps_tags_present` and omit coordinates, altitude, serial numbers, and owner names. That omission stays in place for investigation reports.

## Check your own photo before publishing

```bash
node src/cli.js privacy-check-image --file my-photo.jpg
node src/cli.js privacy-check-image --dir ./my-photos
node src/cli.js privacy-check-image --file my-photo.jpg --scrub --output my-photo-public.jpg
```

`privacy-check-image` is an explicit own-photo check. It does not open the workspace database, including when `--db` is set, and it does not use the network. The report can include exact latitude, longitude, and altitude. Camera make and model, serial numbers, Artist, CameraOwnerName, Copyright, software, and timestamps are listed with a rating: GPS is high, serial and owner or copyright tags are medium, and dates, software, and make/model are low.

`--scrub` writes a new file and then reads that file back. The command fails if GPS or any reported identifying tag remains. It does not open the original for writing. The built-in stripper removes JPEG, PNG, and WebP metadata segments. TIFF scrub needs `exiftool` or `mat2` on PATH (`--backend exiftool` or `--backend mat2`). `doctor` reports those optional binaries. A missing optional binary does not fail `doctor`. The ExifTool JSON import still drops GPS; it is not this command.

MCP `privacy_check_image` takes `data_base64` and optional `scrub`. It reads no path. `scrub: true` returns `scrubbed_base64` after the same recheck. Supplied image bytes follow the 2 MiB MCP limit. CLI files follow the 16 MiB limit. A folder check reads at most 64 regular files and skips non-images.

```json
{
  "purpose": "own-photo-privacy-check",
  "network": false,
  "persisted": false,
  "rating": "high",
  "gps": {
    "present": true,
    "latitude": 10.5,
    "longitude": -20.25,
    "altitude_meters": 42.5
  },
  "findings": [
    { "group": "exif", "tag": "GPSLatitude", "risk": "high", "value": "10.5" },
    {
      "group": "exif",
      "tag": "BodySerialNumber",
      "risk": "medium",
      "value": "SN-FIXTURE-001"
    },
    {
      "group": "exif",
      "tag": "Software",
      "risk": "low",
      "value": "FixtureEdit 1.0"
    }
  ]
}
```

The sample values above come from a generated fixture, not a real photograph.

`src/image-forensics.js` controls file reads, request size, concurrency, and the MCP response contract. `src/image-worker.js` parses the buffer in a worker with a five-second deadline and V8 heap limits. OS-level sandboxing would add controls for total memory and file or network permissions. Image bytes are handled in memory and the inspector returns JSON. The parser dependency is pinned in the lockfile. [ExifReader documentation](https://github.com/mattiasw/ExifReader)

## Compare images and extract text

```bash
node src/cli.js compare-images --file original.png --other candidate.webp
node src/cli.js ocr-image --file authorized-scan.png --language spa
```

MCP `compare_images` takes `left_base64` and `right_base64`. MCP `ocr_image` takes `data_base64` and optional `language`. CLI files are limited to 16 MiB and each MCP image is limited to 2 MiB. OCR uses a Tesseract executable from an absolute directory on PATH. Install the default English data (`eng`) or Spanish data (`spa`) in the engine's normal language directory. GitHub CI checks English OCR on a generated image. [Tesseract command-line documentation](https://tesseract-ocr.github.io/tessdoc/Command-Line-Usage.html)

The comparison reports SHA-256, exact-byte equality, and a 63-bit grayscale perceptual distance. Whole images within 8 bits are similarity candidates. For crops, the search tests 50% and 75% regions at fixed positions in either image and reports the best candidate within 6 bits. Crop coordinates refer to the auto-oriented source image. Flat images can be inconclusive, grayscale hashes can miss color-only differences, and the fixed search can miss arbitrary crops. Synthetic fixtures establish expected behavior for known transforms. Use an independent labeled corpus to calibrate thresholds for a real collection.

### Find copies in a collection

```powershell
node src/cli.js search-image-copies --file .\reference.jpg --dir .\reviewed-images
```

The CLI compares the reference with up to 24 JPEG, PNG, WebP, or TIFF files in the supplied folder. It scans one folder level, checks at most 256 entries, and returns basenames for matches and rejected candidates. Put the reference outside that folder to avoid a self-match. The per-file limit is 16 MiB.

To attach reviewed page links, add `--manifest .\sources.json` to the CLI command. The manifest maps exact basenames in the supplied folder to source pages.

```json
[
  {
    "file": "candidate.jpg",
    "source_url": "https://example.com/gallery/photo-12"
  }
]
```

MCP `search_image_copies` accepts `query_base64` and an array of up to eight `{id, data_base64, source_url?}` candidates. Pass image bytes and short unique labels. The limit is 2 MiB per image and about 8 MiB before base64 encoding per call. The tool reads no filesystem paths.

Matching images with a link include `source_status: "supplied_unverified"`. HTTP and HTTPS links are treated as labels. The search strips query strings and fragments and rejects embedded credentials. Page addresses are supplied by the operator. Image comparison verifies the supplied bytes and makes no claim about the current page content or account ownership.

### Verify a copy at an external image URL

With `network: true` in your workspace configuration, supply one direct public HTTPS image URL that you have reviewed. Replace the example URL with the one you want to check.

```powershell
node src/cli.js verify-photo-source --file .\reference.jpg --image-url https://example.com/images/photo.jpg --approve-source
```

The command downloads the candidate image and compares it with the reference on your machine. It reports the image URL, retrieval time, both SHA-256 digests, and an exact, perceptual, or crop result. The reference stays local. The command accepts JPEG, PNG, WebP, and TIFF responses up to 2 MiB or your workspace byte limit, whichever is smaller. Use a direct link without redirects, credentials, or query parameters.

An exact match establishes that the supplied URL served identical bytes during the check. A resize or crop is a candidate for review. Page URLs in the offline manifest still carry `supplied_unverified`. The external check handles one image URL per operator-run command.

Results rank exact copies first, then similar images and common crop candidates. The search compares the composition of the images and returns results without network access or database writes. Review perceptual matches as possible copies. They establish neither identity nor who posted an image. Searches run one at a time and time out after 45 seconds.

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
