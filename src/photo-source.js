import { parsePublicHttpsUrl, pinnedHttpsRequest } from "./public-https.js";
import { compareImageWithSource } from "./visual-evidence.js";

const types = new Set(["image/jpeg", "image/png", "image/webp", "image/tiff"]);

async function imageBody(response, limit) {
  try {
    if (response.statusCode !== 200)
      throw new Error("PHOTO_SOURCE_HTTP_REJECTED");
    const type = response.headers["content-type"]
      ?.split(";")[0]
      .trim()
      .toLowerCase();
    if (
      !types.has(type) ||
      (response.headers["content-encoding"] ?? "identity").toLowerCase() !==
        "identity"
    )
      throw new Error("PHOTO_SOURCE_NOT_IMAGE");
    if (Number(response.headers["content-length"]) > limit)
      throw new Error("PHOTO_SOURCE_TOO_LARGE");
    let size = 0;
    const chunks = [];
    for await (const chunk of response) {
      size += chunk.length;
      if (size > limit) throw new Error("PHOTO_SOURCE_TOO_LARGE");
      chunks.push(chunk);
    }
    if (!size) throw new Error("PHOTO_SOURCE_NOT_IMAGE");
    return Buffer.concat(chunks, size);
  } finally {
    response.destroy();
  }
}

export async function verifyPhotoSource(engine, { file, imageUrl, approved }) {
  if (!approved) throw new Error("PHOTO_SOURCE_APPROVAL_REQUIRED");
  if (!engine.config.network) throw new Error("NETWORK_DISABLED");
  let source;
  try {
    if (typeof imageUrl !== "string" || imageUrl.length > 2048)
      throw new Error();
    source = parsePublicHttpsUrl(imageUrl);
    if (source.search) throw new Error();
  } catch {
    throw new Error("INVALID_REMOTE_PHOTO_URL");
  }
  const { maxBytes, timeoutMs } = engine.config.limits;
  const signal = AbortSignal.timeout(Math.min(timeoutMs, 15000));
  const comparison = await compareImageWithSource(
    file,
    async () => {
      await engine.providers.before(source.hostname, signal);
      try {
        const bytes = await pinnedHttpsRequest(
          source,
          {
            method: "GET",
            headers: {
              accept: [...types].join(", "),
              "accept-encoding": "identity",
            },
            signal,
          },
          (response) =>
            imageBody(response, Math.min(maxBytes, 2 * 1024 * 1024)),
          {
            resolve: engine.dependencies.photoSourceResolve,
            send: engine.dependencies.photoSourceRequest,
          },
        );
        engine.providers.success(source.hostname);
        return bytes;
      } catch (error) {
        engine.providers.failure(
          source.hostname,
          "PHOTO_SOURCE_REQUEST_FAILED",
        );
        if (signal.aborted) throw new Error("PHOTO_SOURCE_TIMEOUT");
        if (
          /^(PUBLIC_HTTPS_ADDRESS_REJECTED|PHOTO_SOURCE_[A-Z_]+)$/.test(
            error.message,
          )
        )
          throw error;
        throw new Error("PHOTO_SOURCE_REQUEST_FAILED");
      }
    },
    signal,
  );
  return {
    ...comparison,
    network: true,
    image_url: source.href,
    checked_at: new Date().toISOString(),
    source_status: "image_retrieved",
  };
}
