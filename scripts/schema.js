import { mkdirSync, writeFileSync } from "node:fs";
import { z } from "zod";
import { Config, Observation } from "../src/schema.js";

mkdirSync(new URL("../schema/", import.meta.url), { recursive: true });
for (const [name, schema] of Object.entries({
  config: Config,
  observation: Observation,
}))
  writeFileSync(
    new URL(`../schema/${name}.schema.json`, import.meta.url),
    JSON.stringify(z.toJSONSchema(schema), null, 2) + "\n",
  );
