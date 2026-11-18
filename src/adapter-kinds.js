export const DISCOVERED_IP_ADAPTERS = [
  "rdap",
  "routing",
  "shodan-internetdb",
  "virustotal",
];

export const PASSIVE_ADAPTERS = {
  domain: [
    "crtsh",
    "certspotter",
    "wayback",
    "subfinder",
    "amass",
    "theharvester",
    "domain-rdap",
    "doh",
    "otx",
    "hackertarget",
    "urlscan",
    "securitytrails",
    "virustotal",
  ],
  ip: ["rdap", "routing", "shodan-internetdb", "virustotal"],
  email: ["gravatar", "emailrep", "hibp"],
  username: [
    "sherlock",
    "github-profile",
    "github-keys",
    "github-events",
    "keybase",
  ],
};

export function gapReason(code) {
  const value = String(code ?? "");
  if (
    value === "API_KEY_MISSING" ||
    value.endsWith("_API_KEY_MISSING") ||
    value === "HTTP_401" ||
    value === "HTTP_403" ||
    value === "HIBP_KEY_MISSING"
  )
    return "missing_key";
  if (
    value === "HTTP_429" ||
    value === "RATE_LIMITED" ||
    value === "RETRY_LATER" ||
    value.startsWith("PROVIDER_")
  )
    return "rate_limited";
  if (
    value === "OUT_OF_SCOPE" ||
    value === "USERNAME_OUT_OF_SCOPE" ||
    value === "DOMAIN_REQUIRED" ||
    value === "IP_REQUIRED" ||
    value === "HACKERTARGET_ERROR"
  )
    return "error";
  return "failed";
}
