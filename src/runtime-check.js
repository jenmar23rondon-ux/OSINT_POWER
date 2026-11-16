const REQUIRED = "24.14.0";

export function supportedNode(version = process.versions.node) {
  const [major, minor = 0, patch = 0] = String(version)
    .replace(/^v/, "")
    .split(".")
    .map((part) => Number(part) || 0);
  if (major !== 24) return major > 24;
  if (minor !== 14) return minor > 14;
  return patch >= 0;
}

export function nodeVersionError() {
  return {
    ok: false,
    error: {
      code: "NODE_VERSION",
      message: `OSINT_POWER requires Node.js ${REQUIRED} or newer because it uses node:sqlite. This process is Node.js ${process.versions.node}.`,
      hint: "Install Node.js 24.14 or newer from https://nodejs.org/ and run the command again.",
    },
  };
}

export function writeNodeVersionError(stream = process.stdout) {
  stream.write(JSON.stringify(nodeVersionError()) + "\n");
}

export function isSqliteExperimentalWarning(warning, type) {
  const name = typeof warning === "string" ? type : warning?.name;
  const message =
    typeof warning === "string" ? warning : (warning?.message ?? "");
  return name === "ExperimentalWarning" && /sqlite/i.test(String(message));
}

export function silenceSqliteWarning() {
  if (process.emitWarning.__osintPowerSqliteFilter) return;
  const emit = process.emitWarning.bind(process);
  const filtered = function silenceSqliteExperimentalWarning(
    warning,
    type,
    code,
    ctor,
    ...rest
  ) {
    if (isSqliteExperimentalWarning(warning, type)) return;
    return emit(warning, type, code, ctor, ...rest);
  };
  filtered.__osintPowerSqliteFilter = true;
  process.emitWarning = filtered;
}
