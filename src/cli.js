#!/usr/bin/env node
import {
  silenceSqliteWarning,
  supportedNode,
  writeNodeVersionError,
} from "./runtime-check.js";

if (!supportedNode()) {
  writeNodeVersionError();
  process.exit(1);
}

const OFFLINE_COMMANDS = new Set([
  "help",
  "analyze-image",
  "privacy-check-image",
  "compare-images",
  "search-image-copies",
  "ocr-image",
  "validate-stix",
  "verify-bundle",
  "init",
]);

if (OFFLINE_COMMANDS.has(process.argv[2] ?? "help")) silenceSqliteWarning();

await import("./cli-main.js");
