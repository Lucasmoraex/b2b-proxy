import crypto from "node:crypto";
import { normalizeBrazilianPhone, normalizeCnpj, normalizeEmail } from "../validation.js";

export const AUDIT_CATEGORIES = Object.freeze([
  "duplicate_emails",
  "duplicate_cnpjs",
  "duplicate_phones",
  "invalid_emails",
  "invalid_cnpjs",
  "invalid_phones",
  "missing_cnpj",
  "missing_cnpj_status",
  "approved_tag_without_valid_cnpj",
  "approved_tag_without_approved_status",
  "approved_status_without_approved_tag",
  "pending_and_approved_tags",
  "cnpj_source_divergence",
  "official_phone_note_divergence",
]);

const valueOf = (metafield) => typeof metafield?.value === "string" ? metafield.value.trim() : "";
const present = (value) => typeof value === "string" && value.trim() !== "";
const KNOWN_CNPJ_STATUSES = new Set(["pending", "approved", "rejected"]);

const normalizeCnpjStatus = (value) => {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!normalized) return "missing";
  return KNOWN_CNPJ_STATUSES.has(normalized) ? normalized : "other";
};

export function extractLegacyNote(note) {
  if (typeof note !== "string" || note.length > 100_000) return null;
  const match = note.match(/^\s*CNPJ:\s*([^|\r\n]{1,64})\s*\|\s*CEL:\s*([^\r\n]{1,64})\s*$/i);
  if (!match) return null;
  return { cnpj: match[1].trim(), phone: match[2].trim() };
}

const fingerprint = (value, key) => crypto.createHmac("sha256", key).update(value).digest("hex").slice(0, 24);

const normalizeCandidate = (value, normalizer, key) => {
  try {
    const normalized = normalizer(value);
    const valueHash = fingerprint(normalized, key);
    return { valid: true, normalized, fingerprint: valueHash, comparison: `valid:${valueHash}` };
  } catch {
    const trimmed = typeof value === "string" ? value.trim() : "";
    return { valid: false, normalized: null, comparison: `invalid:${fingerprint(trimmed, key)}` };
  }
};

const addDuplicateValue = (map, normalized, customerId, hashKey) => {
  const valueHash = fingerprint(normalized, hashKey);
  if (!map.has(valueHash)) map.set(valueHash, new Set());
  map.get(valueHash).add(customerId);
};

const duplicateFindings = (map) => [...map.entries()]
  .filter(([, customerIds]) => customerIds.size > 1)
  .map(([valueHash, customerIds]) => ({
    value_hash: valueHash,
    customer_ids: [...customerIds].sort(),
  }))
  .sort((left, right) => left.value_hash.localeCompare(right.value_hash));

const addCustomerFinding = (findings, category, customerId, details = {}) => {
  findings[category].push({ customer_id: customerId, ...details });
};

export async function auditShopifyCustomers({
  client,
  shopDomain,
  apiVersion,
  clock = () => new Date(),
  hashKey = crypto.randomBytes(32),
}) {
  const findings = Object.fromEntries(AUDIT_CATEGORIES.map((category) => [category, []]));
  const duplicateEmails = new Map();
  const duplicateCnpjs = new Map();
  const duplicatePhones = new Map();
  const customerIndicators = [];
  let customersScanned = 0;
  let pagesScanned = 0;

  for await (const customers of client.customerPages()) {
    pagesScanned += 1;
    for (const customer of customers) {
      if (typeof customer?.id !== "string" || !customer.id || customer.id.length > 256) {
        throw new Error("invalid_shopify_customer_id");
      }
      customersScanned += 1;
      const customerId = customer.id;

      const emailPresent = present(customer.email);
      let emailValid = false;
      try {
        addDuplicateValue(duplicateEmails, normalizeEmail(customer.email), customerId, hashKey);
        emailValid = true;
      } catch {
        addCustomerFinding(findings, "invalid_emails", customerId);
      }

      const legacy = extractLegacyNote(customer.note);
      const cnpjRawSources = [
        ["custom.cnpj", valueOf(customer.cnpj)],
        ["custom.cjnpj", valueOf(customer.cjnpj)],
        ["note", legacy?.cnpj || ""],
      ];

      if (!present(valueOf(customer.cnpj))) addCustomerFinding(findings, "missing_cnpj", customerId);
      const invalidCnpjSources = [];
      const cnpjComparisons = new Set();
      const cnpjIndicators = [];
      let validCanonicalCnpj = false;
      for (const [source, value] of cnpjRawSources) {
        if (!present(value)) {
          cnpjIndicators.push({ source, state: "absent" });
          continue;
        }
        const result = normalizeCandidate(value, normalizeCnpj, hashKey);
        cnpjComparisons.add(result.comparison);
        if (result.valid) {
          addDuplicateValue(duplicateCnpjs, result.normalized, customerId, hashKey);
          cnpjIndicators.push({ source, state: "valid", fingerprint: result.fingerprint });
          if (source === "custom.cnpj") validCanonicalCnpj = true;
        } else {
          invalidCnpjSources.push(source);
          cnpjIndicators.push({ source, state: "invalid" });
        }
      }
      if (invalidCnpjSources.length) {
        addCustomerFinding(findings, "invalid_cnpjs", customerId, { sources: invalidCnpjSources });
      }
      const presentCnpjSources = cnpjIndicators.filter((source) => source.state !== "absent");
      if (presentCnpjSources.length > 1 && cnpjComparisons.size > 1) {
        addCustomerFinding(findings, "cnpj_source_divergence", customerId, {
          sources: presentCnpjSources.map(({ source }) => source),
        });
      }

      const phoneRawSources = [
        ["customer.phone", present(customer.phone) ? customer.phone.trim() : ""],
        ["note", legacy?.phone || ""],
      ];
      const invalidPhoneSources = [];
      const phoneComparisons = new Set();
      const phoneIndicators = {};
      for (const [source, value] of phoneRawSources) {
        const key = source === "customer.phone" ? "official" : "note";
        if (!present(value)) {
          phoneIndicators[key] = { state: "absent" };
          continue;
        }
        const result = normalizeCandidate(value, normalizeBrazilianPhone, hashKey);
        phoneComparisons.add(result.comparison);
        if (result.valid) {
          addDuplicateValue(duplicatePhones, result.normalized, customerId, hashKey);
          phoneIndicators[key] = { state: "valid", fingerprint: result.fingerprint };
        } else {
          invalidPhoneSources.push(source);
          phoneIndicators[key] = { state: "invalid" };
        }
      }
      if (invalidPhoneSources.length) {
        addCustomerFinding(findings, "invalid_phones", customerId, { sources: invalidPhoneSources });
      }
      const presentPhoneSources = Object.values(phoneIndicators).filter((source) => source.state !== "absent");
      if (presentPhoneSources.length === 2 && phoneComparisons.size > 1) {
        addCustomerFinding(findings, "official_phone_note_divergence", customerId);
      }

      const phoneState = phoneIndicators.official.state === "valid" && phoneIndicators.note.state === "valid"
        ? "both"
        : phoneIndicators.official.state === "valid"
          ? "official"
          : phoneIndicators.note.state === "valid"
            ? "note"
            : presentPhoneSources.length
              ? "invalid"
              : "absent";

      const statusRaw = valueOf(customer.cnpjStatus);
      const status = normalizeCnpjStatus(statusRaw);
      if (status === "missing") addCustomerFinding(findings, "missing_cnpj_status", customerId);
      const tags = new Set(Array.isArray(customer.tags)
        ? customer.tags.filter((tag) => typeof tag === "string").map((tag) => tag.trim().toLowerCase())
        : []);
      const approvedTag = tags.has("b2b-approved");
      const pendingTag = tags.has("b2b-pending");
      if (approvedTag && !validCanonicalCnpj) {
        addCustomerFinding(findings, "approved_tag_without_valid_cnpj", customerId);
      }
      if (approvedTag && status !== "approved") {
        addCustomerFinding(findings, "approved_tag_without_approved_status", customerId);
      }
      if (status === "approved" && !approvedTag) {
        addCustomerFinding(findings, "approved_status_without_approved_tag", customerId);
      }
      if (approvedTag && pendingTag) {
        addCustomerFinding(findings, "pending_and_approved_tags", customerId);
      }
      customerIndicators.push({
        customer_id: customerId,
        email: { present: emailPresent, valid: emailValid },
        cnpj_sources: cnpjIndicators,
        phone: { state: phoneState, ...phoneIndicators },
        cnpj_status: status,
        has_b2b_approved: approvedTag,
        has_b2b_pending: pendingTag,
      });
    }
  }

  findings.duplicate_emails = duplicateFindings(duplicateEmails);
  findings.duplicate_cnpjs = duplicateFindings(duplicateCnpjs);
  findings.duplicate_phones = duplicateFindings(duplicatePhones);

  const affectedCustomers = new Set();
  let findingCount = 0;
  for (const entries of Object.values(findings)) {
    findingCount += entries.length;
    for (const entry of entries) {
      if (entry.customer_id) affectedCustomers.add(entry.customer_id);
      for (const customerId of entry.customer_ids || []) affectedCustomers.add(customerId);
    }
  }

  return {
    report_version: 1,
    generated_at: clock().toISOString(),
    source: {
      shop_domain_hash: fingerprint(shopDomain, hashKey),
      api_version: apiVersion,
      access: "read_only_graphql",
    },
    totals: {
      pages_scanned: pagesScanned,
      customers_scanned: customersScanned,
      findings: findingCount,
      affected_customers: affectedCustomers.size,
    },
    categories: Object.fromEntries(AUDIT_CATEGORIES.map((category) => [category, findings[category].length])),
    findings,
    customer_indicators: customerIndicators,
  };
}

export function auditSummary(report) {
  return { totals: report.totals, categories: report.categories };
}
