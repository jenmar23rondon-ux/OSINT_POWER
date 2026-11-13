import { mkdirSync, writeFileSync } from "node:fs";
import { z } from "zod";
import { Config, Observation, WorkflowInput } from "../src/schema.js";
import { BusinessRecord, BreachSummary } from "../src/context.js";
import { CompareInput } from "../src/state.js";
import { ResumeInput, JobInput } from "../src/schema.js";
import { DoctorInput } from "../src/doctor.js";
import { RESULT_SCHEMAS, outputSchema } from "../src/contracts.js";
import { BundleInput } from "../src/bundles.js";
import { StixExportInput } from "../src/stix.js";
import { TemporalGraphInput } from "../src/temporal-graph.js";
import { AnalyzeImageInput } from "../src/image-forensics.js";
import { PrivacyCheckImageInput } from "../src/image-privacy.js";
import {
  CompareImagesInput,
  OcrImageInput,
  SearchImageCopiesInput,
} from "../src/visual-evidence.js";

mkdirSync(new URL("../schema/", import.meta.url), { recursive: true });
for (const [name, schema] of Object.entries({
  config: Config,
  observation: Observation,
  workflow: WorkflowInput,
  "business-context": BusinessRecord,
  "breach-summary": BreachSummary,
  compare: CompareInput,
  resume: ResumeInput,
  job: JobInput,
  doctor: DoctorInput,
  bundle: BundleInput,
  "stix-export": StixExportInput,
  "temporal-graph": TemporalGraphInput,
  "analyze-image": AnalyzeImageInput,
  "privacy-check-image": PrivacyCheckImageInput,
  "compare-images": CompareImagesInput,
  "search-image-copies": SearchImageCopiesInput,
  "ocr-image": OcrImageInput,
}))
  writeFileSync(
    new URL(`../schema/${name}.schema.json`, import.meta.url),
    JSON.stringify(z.toJSONSchema(schema), null, 2) + "\n",
  );
writeFileSync(
  new URL("../schema/mcp-output.schema.json", import.meta.url),
  JSON.stringify(
    Object.fromEntries(
      Object.keys(RESULT_SCHEMAS).map((name) => [
        name,
        z.toJSONSchema(outputSchema(name)),
      ]),
    ),
    null,
    2,
  ) + "\n",
);
