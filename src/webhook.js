import { parsePublicHttpsUrl, pinnedHttpsRequest } from "./public-https.js";
export function parseWebhookUrl(value) {
  try {
    return parsePublicHttpsUrl(value);
  } catch {
    throw new Error("WEBHOOK_URL_REJECTED");
  }
}

export function allowedWebhook(value, allowedUrls) {
  const url = parseWebhookUrl(value);
  if (!allowedUrls.some((allowed) => new URL(allowed).href === url.href))
    throw new Error("WEBHOOK_DESTINATION_NOT_ALLOWED");
  return url;
}

export async function postWebhook(url, options, dependencies = {}) {
  try {
    return await pinnedHttpsRequest(
      url,
      {
        ...options,
        method: "POST",
        headers: {
          ...options.headers,
          "content-length": Buffer.byteLength(options.body),
        },
      },
      (response) => {
        const status = response.statusCode;
        const retry = response.headers["retry-after"];
        response.destroy();
        return {
          status,
          ok: status >= 200 && status < 300,
          headers: new Headers(
            typeof retry === "string" ? { "retry-after": retry } : {},
          ),
        };
      },
      {
        resolve: dependencies.webhookResolve,
        send: dependencies.webhookRequest,
      },
    );
  } catch (error) {
    if (error.message === "PUBLIC_HTTPS_ADDRESS_REJECTED")
      throw new Error("WEBHOOK_ADDRESS_REJECTED");
    throw error;
  }
}
