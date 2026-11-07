export function nameKey(value) {
  return String(value)
    .normalize("NFKC")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();
}
export function usernameVariants(name, aliases = [], suffixes = ["1", "01"]) {
  const words =
    String(name)
      .normalize("NFKD")
      .replace(/\p{M}/gu, "")
      .toLowerCase()
      .match(/[a-z0-9]+/g) ?? [];
  const first = words[0] ?? "";
  const last = words.at(-1) ?? "";
  const bases =
    words.length > 1
      ? [
          `${first}.${last}`,
          `${first[0]}${last}`,
          `${last}${first[0]}`,
          `${first}${last}`,
          `${first}_${last}`,
        ]
      : [first];
  return [
    ...new Set([
      ...aliases,
      ...bases,
      ...bases.flatMap((base) => suffixes.map((n) => base + n)),
    ]),
  ]
    .filter((v) => /^[a-z0-9_][a-z0-9_.-]{0,63}$/i.test(v))
    .slice(0, 20);
}
export const employeeValue = (person) =>
  `${person.name} @ ${person.companyDomain}`;
