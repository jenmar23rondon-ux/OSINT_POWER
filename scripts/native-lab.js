import { spawn } from "node:child_process";
const child = spawn(process.execPath, ["--test", "test/native-lab.test.js"], {
  stdio: "inherit",
  shell: false,
  windowsHide: true,
  env: { ...process.env, OSINT_POWER_NATIVE_LAB: "1" },
});
child.on("error", () => {
  process.exitCode = 1;
});
child.on("exit", (code) => {
  process.exitCode = code ?? 1;
});
