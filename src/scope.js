import { domainToASCII } from "node:url";
import { isIP } from "node:net";
import { nameKey, usernameVariants, employeeValue } from "./identity.js";

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
  if (["domain", "company", "mail_domain"].includes(type))
    return domain(v.replace(/^\*\./, ""));
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
    this.people = config.scope.people.map((p) => ({
      ...p,
      companyDomain: domain(p.companyDomain),
    }));
    if (this.people.some((p) => !this.host(p.companyDomain)))
      throw new Error("PERSON_COMPANY_OUT_OF_SCOPE");
    if (
      new Set(this.people.map((p) => nameKey(p.name))).size !==
      this.people.length
    )
      throw new Error("DUPLICATE_PERSON");
  }
  person(name) {
    const matches = this.people.filter(
      (p) =>
        nameKey(p.name) === nameKey(name) ||
        p.aliases.some((alias) => nameKey(alias) === nameKey(name)),
    );
    return matches.length === 1 ? matches[0] : undefined;
  }
  username(value) {
    return (
      this.config.scope.usernames.includes(value) ||
      this.people.some((p) =>
        usernameVariants(
          p.name,
          p.aliases,
          this.config.collectors.usernameSuffixes,
        ).includes(value),
      )
    );
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
      if (["domain", "company", "mail_domain"].includes(type))
        return this.host(value);
      if (type === "employee") {
        const p = this.person(evidence.person);
        return Boolean(
          p &&
          p.companyDomain === evidence.company &&
          value === employeeValue(p),
        );
      }
      if (["place", "technology", "job", "role"].includes(type))
        return Boolean(
          evidence.company &&
          this.host(evidence.company) &&
          (type !== "place" || evidence.place_kind === "public_office") &&
          (type !== "role" ||
            this.person(evidence.person)?.companyDomain === evidence.company),
        );
      if (["network", "asn"].includes(type))
        return Boolean(
          (evidence.ip && this.host(evidence.ip)) ||
          (evidence.host && this.host(evidence.host)),
        );
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
        return (
          this.username(value) ||
          Boolean(
            evidence.account &&
            this.allows("email", evidence.account) &&
            value === evidence.account.split("@")[0],
          )
        );
      if (type === "profile")
        return (
          this.username(evidence.username) ||
          Boolean(
            evidence.person &&
            this.person(evidence.person)?.companyDomain === evidence.company,
          )
        );
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
    if (["sherlock", "github-profile"].includes(adapter)) {
      if (
        !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(input) ||
        !this.username(input)
      )
        throw new Error("USERNAME_OUT_OF_SCOPE");
      return input;
    }
    if (adapter === "hibp") {
      const account = normalized("email", input);
      // Breach lookups always require an exact configured account.
      if (!this.emails.includes(account)) throw new Error("OUT_OF_SCOPE");
      return account;
    }
    const value = isIP(input) ? normalized("ip", input) : domain(input);
    if (
      [
        "subfinder",
        "amass",
        "crtsh",
        "certspotter",
        "wayback",
        "mx",
        "theharvester",
      ].includes(adapter) &&
      isIP(value)
    )
      throw new Error("DOMAIN_REQUIRED");
    if (["rdap", "routing"].includes(adapter) && !isIP(value))
      throw new Error("IP_REQUIRED");
    if (!this.host(value)) throw new Error("OUT_OF_SCOPE");
    return value;
  }
}
