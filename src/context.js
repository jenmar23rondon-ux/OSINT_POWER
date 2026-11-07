import { z } from "zod";
import { employeeValue } from "./identity.js";
import { domain } from "./scope.js";

const httpsURL = z.url().refine((v) => {
  const u = new URL(v);
  return u.protocol === "https:" && !u.username && !u.password;
});
export const BusinessRecord = z
  .object({
    company_domain: z.string(),
    kind: z.enum([
      "employee",
      "role",
      "technology",
      "place",
      "profile",
      "email",
      "job",
    ]),
    value: z.string().min(1).max(500),
    person: z.string().min(1).max(160).optional(),
    username: z
      .string()
      .regex(/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/)
      .optional(),
    source_url: httpsURL,
    status: z.enum(["observed", "inferred"]).default("observed"),
    place_kind: z.literal("public_office").optional(),
    timestamp: z.iso.datetime(),
  })
  .strict();
export const BreachSummary = z
  .object({
    email: z.string().email(),
    provider: z.enum(["DeHashed", "LeakCheck", "HIBP"]),
    breach: z.string().min(1).max(160),
    date: z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/)
      .optional(),
    timestamp: z.iso.datetime(),
  })
  .strict();

export function parseBusiness(record, scope, emit) {
  const r = BusinessRecord.parse(record);
  r.company_domain = domain(r.company_domain);
  if (!scope.host(r.company_domain)) throw new Error("OUT_OF_SCOPE");
  const person = r.person ? scope.person(r.person) : null;
  if (r.person && (!person || person.companyDomain !== r.company_domain))
    throw new Error("PERSON_OUT_OF_SCOPE");
  if (["employee", "role"].includes(r.kind) && !person)
    throw new Error("PERSON_REQUIRED");
  if (r.kind === "place" && r.place_kind !== "public_office")
    throw new Error("PUBLIC_OFFICE_REQUIRED");
  const confidence = r.status === "inferred" ? 0.25 : 0.65;
  const evidence = {
    company: r.company_domain,
    host: r.company_domain,
    source_url: r.source_url,
    inferred: r.status === "inferred",
    verification: "source_assertion",
    ...(person ? { person: person.name } : {}),
    ...(r.username ? { username: r.username } : {}),
    ...(r.place_kind ? { place_kind: r.place_kind } : {}),
  };
  emit(
    "company",
    r.company_domain,
    { host: r.company_domain },
    confidence,
    "business-context",
    r.timestamp,
  );
  if (person)
    emit(
      "employee",
      employeeValue(person),
      evidence,
      confidence,
      "business-context",
      r.timestamp,
    );
  const types = {
    role: "role",
    technology: "technology",
    place: "place",
    profile: "profile",
    email: "email",
    job: "job",
  };
  if (r.kind !== "employee")
    emit(
      types[r.kind],
      r.kind === "role" ? `${employeeValue(person)}: ${r.value}` : r.value,
      evidence,
      confidence,
      "business-context",
      r.timestamp,
    );
}
