// Offline checks for the STIX 2.1 objects this project exports.
// No schema library and no network. Unknown object types are rejected.
// This is not a full substitute for the OASIS STIX 2.1 schema suite.

const TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3,})Z$/;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const SCO_TYPES = new Set([
  "domain-name",
  "ipv4-addr",
  "ipv6-addr",
  "email-addr",
  "url",
  "x509-certificate",
]);
const OPINIONS = new Set([
  "strongly-disagree",
  "disagree",
  "neutral",
  "agree",
  "strongly-agree",
]);
const COMMON_SDO = [
  "type",
  "spec_version",
  "id",
  "created",
  "modified",
  "created_by_ref",
  "revoked",
  "labels",
  "confidence",
  "lang",
  "external_references",
  "object_marking_refs",
  "granular_markings",
  "extensions",
];
const SCO_COMMON = [
  "type",
  "spec_version",
  "id",
  "object_marking_refs",
  "granular_markings",
  "defanged",
  "extensions",
];
const ALLOWED = {
  identity: new Set([
    ...COMMON_SDO,
    "name",
    "description",
    "roles",
    "identity_class",
    "sectors",
    "contact_information",
  ]),
  indicator: new Set([
    ...COMMON_SDO,
    "name",
    "description",
    "indicator_types",
    "pattern",
    "pattern_type",
    "pattern_version",
    "valid_from",
    "valid_until",
  ]),
  "observed-data": new Set([
    ...COMMON_SDO,
    "first_observed",
    "last_observed",
    "number_observed",
    "object_refs",
  ]),
  relationship: new Set([
    ...COMMON_SDO,
    "relationship_type",
    "description",
    "source_ref",
    "target_ref",
    "start_time",
    "stop_time",
  ]),
  note: new Set([
    ...COMMON_SDO,
    "abstract",
    "content",
    "authors",
    "object_refs",
  ]),
  opinion: new Set([
    ...COMMON_SDO,
    "explanation",
    "authors",
    "opinion",
    "object_refs",
  ]),
  "domain-name": new Set([...SCO_COMMON, "value", "resolves_to_refs"]),
  "ipv4-addr": new Set([
    ...SCO_COMMON,
    "value",
    "resolves_to_refs",
    "belongs_to_refs",
  ]),
  "ipv6-addr": new Set([
    ...SCO_COMMON,
    "value",
    "resolves_to_refs",
    "belongs_to_refs",
  ]),
  "email-addr": new Set([
    ...SCO_COMMON,
    "value",
    "display_name",
    "belongs_to_ref",
  ]),
  url: new Set([...SCO_COMMON, "value"]),
  "x509-certificate": new Set([
    ...SCO_COMMON,
    "is_self_signed",
    "hashes",
    "version",
    "serial_number",
    "signature_algorithm",
    "issuer",
    "validity_not_before",
    "validity_not_after",
    "subject",
    "subject_public_key_algorithm",
    "subject_public_key_modulus",
    "subject_public_key_exponent",
    "x509_v3_extensions",
  ]),
};

function error(errors, code, path) {
  if (errors.length < 100) errors.push({ code, path });
}
function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
export function validStixTimestamp(value) {
  if (typeof value !== "string") return false;
  const match = TIMESTAMP.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 60)
    return false;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return false;
  if (second === 60) return true;
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() + 1 === month &&
    date.getUTCDate() === day &&
    date.getUTCHours() === hour &&
    date.getUTCMinutes() === minute &&
    date.getUTCSeconds() === second
  );
}
function splitIdentifier(id) {
  const index = typeof id === "string" ? id.indexOf("--") : -1;
  if (index < 1) return null;
  const type = id.slice(0, index);
  const uuid = id.slice(index + 2);
  if (!/^[a-z0-9-]+$/.test(type) || !UUID.test(uuid)) return null;
  return { type, uuid };
}
function checkTimestamp(errors, value, path, required) {
  if (value === undefined) {
    if (required) error(errors, "MISSING_PROPERTY", path);
    return;
  }
  if (!validStixTimestamp(value)) error(errors, "INVALID_TIMESTAMP", path);
}
function queueRef(pending, ownerId, id, path, kind) {
  pending.push({ ownerId, id, path, kind });
}
function checkRef(errors, pending, ownerId, value, path, kind, required) {
  if (value === undefined) {
    if (required) error(errors, "MISSING_PROPERTY", path);
    return;
  }
  if (typeof value !== "string" || !splitIdentifier(value)) {
    error(errors, "INVALID_ID", path);
    return;
  }
  queueRef(pending, ownerId, value, path, kind);
}
function checkRefList(errors, pending, ownerId, value, path, kind, required) {
  if (value === undefined) {
    if (required) error(errors, "MISSING_PROPERTY", path);
    return;
  }
  if (!Array.isArray(value) || (required && value.length < 1)) {
    error(errors, "INVALID_PROPERTY", path);
    return;
  }
  value.forEach((item, index) =>
    checkRef(errors, pending, ownerId, item, `${path}[${index}]`, kind, true),
  );
}
function checkCommon(errors, object, path, sdo) {
  if (object.spec_version !== "2.1")
    error(errors, "SPEC_VERSION", `${path}.spec_version`);
  checkTimestamp(errors, object.created, `${path}.created`, sdo);
  checkTimestamp(errors, object.modified, `${path}.modified`, sdo);
  if (
    validStixTimestamp(object.created) &&
    validStixTimestamp(object.modified) &&
    object.modified < object.created
  )
    error(errors, "TIMESTAMP_ORDER", `${path}.modified`);
  if (
    object.confidence !== undefined &&
    (!Number.isInteger(object.confidence) ||
      object.confidence < 0 ||
      object.confidence > 100)
  )
    error(errors, "INVALID_CONFIDENCE", `${path}.confidence`);
  if (object.revoked !== undefined && typeof object.revoked !== "boolean")
    error(errors, "INVALID_PROPERTY", `${path}.revoked`);
  if (object.defanged !== undefined && typeof object.defanged !== "boolean")
    error(errors, "INVALID_PROPERTY", `${path}.defanged`);
  if (
    object.labels !== undefined &&
    (!Array.isArray(object.labels) ||
      object.labels.some((item) => typeof item !== "string" || !item))
  )
    error(errors, "INVALID_PROPERTY", `${path}.labels`);
  if (object.external_references !== undefined) {
    if (!Array.isArray(object.external_references))
      error(errors, "INVALID_PROPERTY", `${path}.external_references`);
    else
      object.external_references.forEach((item, itemIndex) => {
        if (
          !isObject(item) ||
          typeof item.source_name !== "string" ||
          !item.source_name
        )
          error(
            errors,
            "INVALID_PROPERTY",
            `${path}.external_references[${itemIndex}].source_name`,
          );
      });
  }
  if (
    object.granular_markings !== undefined &&
    !Array.isArray(object.granular_markings)
  )
    error(errors, "INVALID_PROPERTY", `${path}.granular_markings`);
  if (object.extensions !== undefined && !isObject(object.extensions))
    error(errors, "INVALID_PROPERTY", `${path}.extensions`);
  if (object.lang !== undefined && typeof object.lang !== "string")
    error(errors, "INVALID_PROPERTY", `${path}.lang`);
  if (object.authors !== undefined) {
    if (
      !Array.isArray(object.authors) ||
      object.authors.some((item) => typeof item !== "string" || !item)
    )
      error(errors, "INVALID_PROPERTY", `${path}.authors`);
  }
}
function requireString(errors, object, path, key) {
  if (typeof object[key] !== "string" || !object[key])
    error(errors, "MISSING_PROPERTY", `${path}.${key}`);
}
function checkIPv4(value) {
  const [address, prefix] = String(value).split("/");
  const octets = address.split(".");
  if (String(value).split("/").length > 2) return false;
  const octetsOk =
    octets.length === 4 &&
    octets.every((item) => /^(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$/.test(item));
  if (!octetsOk) return false;
  return (
    prefix === undefined || (/^\d{1,2}$/.test(prefix) && Number(prefix) <= 32)
  );
}
function checkSpecific(errors, pending, object, path) {
  const type = object.type;
  const owner = object.id;
  if (type === "identity") {
    requireString(errors, object, path, "name");
    if (
      typeof object.identity_class !== "string" ||
      !/^[a-z0-9-]+$/.test(object.identity_class)
    )
      error(errors, "MISSING_PROPERTY", `${path}.identity_class`);
  } else if (type === "indicator") {
    requireString(errors, object, path, "pattern");
    requireString(errors, object, path, "pattern_type");
    if (
      !Array.isArray(object.indicator_types) ||
      object.indicator_types.length < 1 ||
      object.indicator_types.some((item) => typeof item !== "string" || !item)
    )
      error(errors, "MISSING_PROPERTY", `${path}.indicator_types`);
    checkTimestamp(errors, object.valid_from, `${path}.valid_from`, true);
    checkTimestamp(errors, object.valid_until, `${path}.valid_until`, false);
    if (
      validStixTimestamp(object.valid_from) &&
      validStixTimestamp(object.valid_until) &&
      object.valid_until < object.valid_from
    )
      error(errors, "TIMESTAMP_ORDER", `${path}.valid_until`);
    if (
      object.pattern_type === "stix" &&
      (typeof object.pattern !== "string" || !object.pattern.startsWith("["))
    )
      error(errors, "INVALID_PROPERTY", `${path}.pattern`);
  } else if (type === "observed-data") {
    checkTimestamp(
      errors,
      object.first_observed,
      `${path}.first_observed`,
      true,
    );
    checkTimestamp(errors, object.last_observed, `${path}.last_observed`, true);
    if (
      validStixTimestamp(object.first_observed) &&
      validStixTimestamp(object.last_observed) &&
      object.last_observed < object.first_observed
    )
      error(errors, "TIMESTAMP_ORDER", `${path}.last_observed`);
    if (
      !Number.isInteger(object.number_observed) ||
      object.number_observed < 1 ||
      object.number_observed > 999_999_999
    )
      error(errors, "MISSING_PROPERTY", `${path}.number_observed`);
    checkRefList(
      errors,
      pending,
      owner,
      object.object_refs,
      `${path}.object_refs`,
      "sco",
      true,
    );
  } else if (type === "relationship") {
    if (
      typeof object.relationship_type !== "string" ||
      !/^[a-z0-9-]+$/.test(object.relationship_type)
    )
      error(errors, "MISSING_PROPERTY", `${path}.relationship_type`);
    checkRef(
      errors,
      pending,
      owner,
      object.source_ref,
      `${path}.source_ref`,
      "any",
      true,
    );
    checkRef(
      errors,
      pending,
      owner,
      object.target_ref,
      `${path}.target_ref`,
      "any",
      true,
    );
    checkTimestamp(errors, object.start_time, `${path}.start_time`, false);
    checkTimestamp(errors, object.stop_time, `${path}.stop_time`, false);
  } else if (type === "note") {
    requireString(errors, object, path, "content");
    checkRefList(
      errors,
      pending,
      owner,
      object.object_refs,
      `${path}.object_refs`,
      "any",
      true,
    );
  } else if (type === "opinion") {
    if (!OPINIONS.has(object.opinion))
      error(errors, "MISSING_PROPERTY", `${path}.opinion`);
    checkRefList(
      errors,
      pending,
      owner,
      object.object_refs,
      `${path}.object_refs`,
      "any",
      true,
    );
  } else if (SCO_TYPES.has(type) && type !== "x509-certificate")
    requireString(errors, object, path, "value");
  if (type === "x509-certificate") {
    checkTimestamp(
      errors,
      object.validity_not_before,
      `${path}.validity_not_before`,
      false,
    );
    checkTimestamp(
      errors,
      object.validity_not_after,
      `${path}.validity_not_after`,
      false,
    );
    if (
      object.x509_v3_extensions !== undefined &&
      !isObject(object.x509_v3_extensions)
    )
      error(errors, "INVALID_PROPERTY", `${path}.x509_v3_extensions`);
    if (object.hashes !== undefined && !isObject(object.hashes))
      error(errors, "INVALID_PROPERTY", `${path}.hashes`);
    if (
      object.is_self_signed !== undefined &&
      typeof object.is_self_signed !== "boolean"
    )
      error(errors, "INVALID_PROPERTY", `${path}.is_self_signed`);
  }
  if (type === "ipv4-addr" && !checkIPv4(object.value))
    error(errors, "INVALID_VALUE", `${path}.value`);
  if (
    type === "ipv6-addr" &&
    (typeof object.value !== "string" || !object.value.includes(":"))
  )
    error(errors, "INVALID_VALUE", `${path}.value`);
  if (
    type === "email-addr" &&
    (typeof object.value !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(object.value))
  )
    error(errors, "INVALID_VALUE", `${path}.value`);
  if (type === "url" && typeof object.value === "string") {
    try {
      const url = new URL(object.value);
      if (!["http:", "https:"].includes(url.protocol))
        error(errors, "INVALID_VALUE", `${path}.value`);
    } catch {
      error(errors, "INVALID_VALUE", `${path}.value`);
    }
  }
  if (
    type === "domain-name" &&
    typeof object.value === "string" &&
    (object.value.length > 253 || /\s/.test(object.value))
  )
    error(errors, "INVALID_VALUE", `${path}.value`);
  checkRef(
    errors,
    pending,
    owner,
    object.created_by_ref,
    `${path}.created_by_ref`,
    "identity",
    false,
  );
  checkRef(
    errors,
    pending,
    owner,
    object.belongs_to_ref,
    `${path}.belongs_to_ref`,
    "any",
    false,
  );
  for (const key of [
    "resolves_to_refs",
    "belongs_to_refs",
    "object_marking_refs",
  ])
    if (object[key] !== undefined)
      checkRefList(
        errors,
        pending,
        owner,
        object[key],
        `${path}.${key}`,
        "any",
        true,
      );
}
export function validateStixBundle(bundle) {
  const errors = [];
  if (!isObject(bundle) || bundle.type !== "bundle") {
    error(errors, "BUNDLE_TYPE", "type");
    return errors;
  }
  const bundleId = splitIdentifier(bundle.id);
  if (!bundleId || bundleId.type !== "bundle") error(errors, "BUNDLE_ID", "id");
  for (const key of Object.keys(bundle))
    if (!["type", "id", "objects"].includes(key))
      error(errors, "INVALID_PROPERTY", key);
  if (!Array.isArray(bundle.objects)) {
    error(errors, "OBJECTS_TYPE", "objects");
    return errors;
  }
  const byId = new Map();
  const pending = [];
  bundle.objects.forEach((object, index) => {
    const path = `objects[${index}]`;
    if (!isObject(object) || typeof object.type !== "string") {
      error(errors, "OBJECT_TYPE", path);
      return;
    }
    const id = splitIdentifier(object.id);
    if (!id) error(errors, "OBJECT_ID", `${path}.id`);
    else if (id.type !== object.type)
      error(errors, "ID_TYPE_MISMATCH", `${path}.id`);
    if (id && byId.has(object.id)) error(errors, "DUPLICATE_ID", `${path}.id`);
    if (typeof object.id === "string") byId.set(object.id, object);
    const allowed = ALLOWED[object.type];
    if (!allowed) {
      error(errors, "UNKNOWN_TYPE", `${path}.type`);
      return;
    }
    for (const key of Object.keys(object))
      if (!allowed.has(key))
        error(errors, "INVALID_PROPERTY", `${path}.${key}`);
    checkCommon(errors, object, path, !SCO_TYPES.has(object.type));
    checkSpecific(errors, pending, object, path);
  });
  for (const ref of pending) {
    if (ref.ownerId && ref.id === ref.ownerId) {
      error(errors, "SELF_REF", ref.path);
      continue;
    }
    const target = byId.get(ref.id);
    if (!target) {
      error(errors, "UNRESOLVED_REF", ref.path);
      continue;
    }
    if (ref.kind === "identity" && target.type !== "identity")
      error(errors, "INVALID_REF_TYPE", ref.path);
    if (ref.kind === "sco" && !SCO_TYPES.has(target.type))
      error(errors, "INVALID_REF_TYPE", ref.path);
  }
  return errors;
}
