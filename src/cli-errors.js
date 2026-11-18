const messages = {
  INVALID_INPUT: [
    "An argument is missing or invalid.",
    "Run node src/cli.js help and check the command arguments.",
  ],
  UNKNOWN_COMMAND: [
    "The command is unknown.",
    "Run node src/cli.js help to list supported commands.",
  ],
  UNEXPECTED_ARGUMENT: [
    "The command received an unexpected positional argument.",
    "Pass options by name and consult the CLI help.",
  ],
  FILE_NOT_FOUND: [
    "A required file could not be found.",
    "Check the path and the working directory.",
  ],
  CONFIG_EXISTS: [
    "The configuration already exists.",
    "Use the existing file or pass a different path with --config.",
  ],
  SCOPE_DATABASE_MISMATCH: [
    "The database belongs to a different workspace scope.",
    "Use the original configuration or select a new database with --db.",
  ],
  INVALID_IMPORT_FILE: [
    "The import file is missing, is not a regular file, or exceeds the size limit.",
    "Pass a readable file with --file and check the workspace byte limit.",
  ],
  IMPORT_PARSE_ERROR: [
    "The import could not be parsed.",
    "Check the file format and select the matching --adapter.",
  ],
  TOOL_NOT_INSTALLED: [
    "A required external executable was not found.",
    "Install the selected adapter's dependency on PATH and run the doctor command.",
  ],
  HIBP_KEY_MISSING: [
    "The HIBP provider key is missing.",
    "Set HIBP_API_KEY in the environment before using the HIBP adapter. The key is not read from the configuration file.",
  ],
  NETWORK_DISABLED: [
    "Network collection is turned off for this workspace.",
    'Set "network": true in the workspace configuration. Active DNS, HTTP, and port checks also need "active": true and the adapter listed in enabledAdapters.',
  ],
  ACTIVE_DISABLED: [
    "Active collection is turned off for this workspace.",
    'Set "active": true before DNS, HTTP, or port checks. HTTP probing also needs --probe-http and --authorized.',
  ],
  ADAPTER_DISABLED: [
    "The adapter is not enabled in this workspace.",
    "Add the adapter to enabledAdapters. ProjectDiscovery httpx also needs active mode plus --probe-http and --authorized.",
  ],
  HTTP_PROBE_DISABLED: [
    "Active HTTP probing is off.",
    "Pass --probe-http and --authorized. Passive collection never runs httpx.",
  ],
  HTTP_PROBE_NOT_AUTHORIZED: [
    "Active HTTP probing was not authorized.",
    "Pass --authorized together with --probe-http. Only hosts already inside the workspace scope are contacted.",
  ],
  HTTPX_NOT_PROJECTDISCOVERY: [
    "The httpx program on PATH is not ProjectDiscovery httpx.",
    "Python's httpx command uses the same name. Install ProjectDiscovery httpx and put that binary first on PATH: https://github.com/projectdiscovery/httpx",
  ],
  SECURITYTRAILS_API_KEY_MISSING: [
    "The SecurityTrails API key is missing.",
    "Set SECURITYTRAILS_API_KEY in the environment. The source is reported as a coverage gap, not as an empty result.",
  ],
  VIRUSTOTAL_API_KEY_MISSING: [
    "The VirusTotal API key is missing.",
    "Set VIRUSTOTAL_API_KEY in the environment. The source is reported as a coverage gap, not as an empty result.",
  ],
  RATE_LIMITED: [
    "The source asked the workspace to slow down.",
    "The unfinished check is a coverage gap. It is not a negative result. Wait for the provider window and try that source again.",
  ],
  OCR_TOOL_NOT_INSTALLED: [
    "Tesseract is unavailable.",
    "Install Tesseract on PATH and check that the selected language data is installed.",
  ],
  IMPORT_TOO_LARGE: [
    "The import exceeds the workspace byte limit.",
    "Split the export into smaller files and import each separately.",
  ],
  SCRUB_OUTPUT_REQUIRED: [
    "Scrub needs a destination path.",
    "Pass --output PATH. The original file is not modified.",
  ],
  OUTPUT_REQUIRES_SCRUB: [
    "An output path was given without scrubbing.",
    "Add --scrub to write a metadata-stripped copy, or omit --output to only print the report.",
  ],
  OUTPUT_IS_INPUT: [
    "The scrub output path is the original file.",
    "Choose a different --output path. The original is left unchanged.",
  ],
  OUTPUT_EXISTS: [
    "The scrub output already exists.",
    "Choose a new --output path. Existing files are not overwritten.",
  ],
  OUTPUT_IS_DIRECTORY: [
    "The scrub output path is a directory.",
    "Pass a file path with --file, or a directory with --dir.",
  ],
  SCRUB_INCOMPLETE: [
    "The stripped copy still contains GPS or identifying tags.",
    "Do not publish that copy. Try --backend exiftool or --backend mat2 when doctor shows it is installed.",
  ],
  SCRUB_UNSUPPORTED: [
    "This image cannot be stripped with the selected backend.",
    "Built-in scrub supports JPEG, PNG, and WebP. TIFF can use exiftool or mat2 when that tool is on PATH.",
  ],
  SCRUB_FAILED: [
    "The selected scrub backend could not write a cleaned copy.",
    "Check doctor for exiftool or mat2, or omit --backend to use the built-in stripper.",
  ],
  INVALID_PRIVACY_BACKEND: [
    "The scrub backend is not recognized.",
    "Use builtin, exiftool, or mat2.",
  ],
  DIRECTORY_REQUIRED: [
    "The path is not a directory.",
    "Pass a folder of your own photos with --dir.",
  ],
  TOO_MANY_IMAGES: [
    "The folder contains too many files.",
    "Check at most 64 regular files per call.",
  ],
  DOCUMENT_OUT_OF_SCOPE: [
    "The image name is not in the workspace document scope.",
    "Add the file basename to scope.documents, then run ocr-image --save again. The extracted text is still in this result.",
  ],
  DOCUMENT_REQUIRED: [
    "Saving OCR text needs the document basename.",
    "Pass document as the basename listed in scope.documents.",
  ],
  INVESTIGATION_NOT_FOUND: [
    "No investigation exists with that id.",
    "Run investigate --execute --target VALUE, then pass that id to --resume.",
  ],
  INVESTIGATION_ID_REQUIRED: [
    "Resume needs an investigation id.",
    "Pass --resume --id UUID from a previous investigate --execute result.",
  ],
  TARGET_REQUIRED: [
    "The command needs a target.",
    "Pass --target with a domain, email, username, or IP that is inside the workspace scope.",
  ],
  USERNAME_OUT_OF_SCOPE: [
    "The username is not in this workspace.",
    "Add it to scope.usernames or to a configured person's aliases.",
  ],
  OUT_OF_SCOPE: [
    "The target is outside the configured scope.",
    "Choose a domain, email, or IP the workspace already allows.",
  ],
  ORIGINAL_MODIFIED: [
    "The original file changed while the privacy check was running.",
    "The command does not write to the original. Run it again on a stable file.",
  ],
};

const scopedMessages = {
  privacy: {
    TOOL_NOT_INSTALLED: [
      "The selected scrub backend is not on PATH.",
      "Install exiftool or mat2, or omit --backend to use the built-in stripper. doctor lists those optional tools.",
    ],
    IMAGE_FILE_REQUIRED: [
      "The image path is missing or is not a regular file.",
      "Pass --file PATH for one of your own photos, or --dir PATH for a folder.",
    ],
    FILE_NOT_FOUND: [
      "The photo or folder could not be found.",
      "Check the path passed to --file or --dir.",
    ],
  },
  config: {
    FILE_NOT_FOUND: [
      "The workspace configuration file could not be found.",
      "Run node src/cli.js init or select an existing configuration with --config.",
    ],
    INVALID_INPUT: [
      "The workspace configuration could not be loaded.",
      "Check that the configuration is readable JSON and follows schema/config.schema.json.",
    ],
  },
  httpx: {
    TOOL_NOT_INSTALLED: [
      "ProjectDiscovery httpx was not found on PATH.",
      "Install the ProjectDiscovery httpx binary, not the Python package named httpx. See https://github.com/projectdiscovery/httpx. One installer is: go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ],
  },
  import: {
    FILE_NOT_FOUND: [
      "The import file could not be found.",
      "Pass an existing local file with --file.",
    ],
    INVALID_INPUT: [
      "The import file could not be read.",
      "Check the file path and read permissions.",
    ],
  },
};

export function cliError(code, stage) {
  const [message, hint] = scopedMessages[stage]?.[code] ??
    messages[code] ?? [
      "The command could not be completed.",
      "Check the error code and consult the CLI help or doctor command.",
    ];
  return { code, message, hint };
}

export function cliException(error, stage) {
  const code =
    error.code === "ENOENT"
      ? "FILE_NOT_FOUND"
      : error.code === "EEXIST"
        ? "CONFIG_EXISTS"
        : /^[A-Z][A-Z_0-9]{1,79}$/.test(error.message)
          ? error.message
          : "INVALID_INPUT";
  return cliError(code, stage);
}
