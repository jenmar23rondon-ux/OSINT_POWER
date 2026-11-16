#!/usr/bin/env node
import { supportedNode, writeNodeVersionError } from "./runtime-check.js";

if (!supportedNode()) {
  writeNodeVersionError(process.stderr);
  process.exit(1);
}

await import("./mcp-server.js");
