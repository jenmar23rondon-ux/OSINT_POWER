import { domainToASCII } from "node:url";
import { isIP } from "node:net";

export function domain(value) {
  const name = domainToASCII(
    String(value).trim().toLowerCase().replace(/\.$/, ""),
  );
  if (
    !name ||
    name.length > 253 ||
    isIP(name) ||
    !name.includes(".") ||
    !name
      .split(".")
      .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  )
    throw new Error("INVALID_DOMAIN");
  return name;
}
export function normalized(type, value) {
  const v = String(value).trim();
  if (type === "domain") return domain(v.replace(/^\*\./, ""));
  if (type === "ip") {
    if (!isIP(v)) throw new Error("INVALID_IP");
    return v.includes(":") ? new URL(`http://[${v}]`).hostname.slice(1, -1) : v;
  }
  if (["url", "profile"].includes(type)) {
    const u = new URL(v);
    if (!["https:", "http:"].includes(u.protocol) || u.username || u.password)
      throw new Error("INVALID_URL");
    u.hash = "";
    // Never persist tokens in query strings from untrusted exports.
    u.search = "";
    return u.href;
  }
  if (type === "email") {
    if (!/^[^\s@]+@[^\s@]+$/.test(v)) throw new Error("INVALID_EMAIL");
    const at = v.lastIndexOf("@");
    return `${v.slice(0, at).toLowerCase()}@${domain(v.slice(at + 1))}`;
  }
  return v;
}
const childOf = (value, parent) =>
  value === parent || value.endsWith(`.${parent}`);
export class Scope {
  constructor(config) {
    this.config = config;
    this.domains = config.scope.domains.map(domain);
    this.excluded = config.scope.excludeDomains.map(domain);
    this.ips = config.scope.ips.map((v) => normalized("ip", v));
    this.emails = config.scope.emails.map((v) => normalized("email", v));
  }
  host(value) {
    if (isIP(value)) return this.ips.includes(normalized("ip", value));
    const name = domain(value);
    return (
      !this.excluded.some((x) => childOf(name, x)) &&
      this.domains.some((x) => childOf(name, x))
    );
  }
  allows(type, value, evidence = {}) {
    try {
      if (type === "domain") return this.host(value);
      if (type === "ip")
        return this.host(value) || (evidence.host && this.host(evidence.host));
      if (type === "url")
        return this.host(new URL(value).hostname.replace(/^\[|\]$/g, ""));
      if (type === "email")
        return (
          this.emails.includes(normalized("email", value)) ||
          this.host(value.split("@")[1])
        );
      if (type === "username")
        return this.config.scope.usernames.includes(value);
      if (type === "profile")
        return this.config.scope.usernames.includes(evidence.username);
      if (type === "breach") return this.allows("email", evidence.account);
      if (["document", "metadata", "secret"].includes(type))
        return this.config.scope.documents.includes(evidence.document);
      if (type === "service") return this.host(evidence.host);
      if (type === "unresolved")
        return Boolean(evidence.host && this.host(evidence.host));
      return false;
    } catch {
      return false;
    }
  }
  target(adapter, input) {
    if (adapter === "hibp") {
      const account = normalized("email", input);
      // Breach lookups always require an exact configured account.
      if (!this.emails.includes(account)) throw new Error("OUT_OF_SCOPE");
      return account;
    }
    const value = isIP(input) ? normalized("ip", input) : domain(input);
    if (["subfinder", "amass", "crtsh"].includes(adapter) && isIP(value))
      throw new Error("DOMAIN_REQUIRED");
    if (!this.host(value)) throw new Error("OUT_OF_SCOPE");
    return value;
  }
}
