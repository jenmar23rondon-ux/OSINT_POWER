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
    "Set the provider key in the environment before using the HIBP adapter.",
  ],
  OCR_TOOL_NOT_INSTALLED: [
    "Tesseract is unavailable.",
    "Install Tesseract on PATH and check that the selected language data is installed.",
  ],
  IMPORT_TOO_LARGE: [
    "The import exceeds the workspace byte limit.",
    "Split the export into smaller files and import each separately.",
  ],
};

const scopedMessages = {
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
