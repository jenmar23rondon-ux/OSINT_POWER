import { basename } from "node:path";
import { z } from "zod";

const sha = z.string().regex(/^[a-f0-9]{64}$/);

export const OcrStorage = z
  .object({
    saved: z.boolean(),
    reason: z.enum(["not_requested", "stored", "DOCUMENT_OUT_OF_SCOPE"]),
    entity_id: sha.nullable(),
    observation_id: sha.nullable(),
  })
  .strict();

export const OCR_NOT_STORED = OcrStorage.parse({
  saved: false,
  reason: "not_requested",
  entity_id: null,
  observation_id: null,
});

function documentName(value) {
  const document = basename(String(value ?? "").replaceAll("\\", "/"));
  if (
    !document ||
    document === "." ||
    document === ".." ||
    document.length > 240
  )
    throw new Error("INVALID_INPUT");
  return document;
}

export function persistOcr(store, scope, ocr, name) {
  const document = documentName(name);
  if (!scope.config.scope.documents.includes(document))
    return OcrStorage.parse({
      saved: false,
      reason: "DOCUMENT_OUT_OF_SCOPE",
      entity_id: null,
      observation_id: null,
    });
  const evidence = {
    document,
    field: "ocr_text",
    sha256: sha.parse(ocr.sha256),
    language: ocr.language,
    engine: "tesseract",
    text: String(ocr.text ?? "").slice(0, 8000),
    text_truncated: Boolean(ocr.text_truncated),
    text_trust: "untrusted",
    inferred: false,
  };
  store.ingest([
    {
      type: "document",
      value: document,
      source: "tesseract",
      confidence: 0.35,
      timestamp: new Date().toISOString(),
      evidence,
    },
  ]);
  const entity = store
    .query({ type: "document", limit: 100 })
    .items.find((item) => item.value === document);
  const observation = store
    .evidence(entity.id, 50)
    .items.find(
      (item) =>
        item.source === "tesseract" && item.evidence.sha256 === evidence.sha256,
    );
  return OcrStorage.parse({
    saved: true,
    reason: "stored",
    entity_id: entity.id,
    observation_id: observation.id,
  });
}
