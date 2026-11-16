import { AppError } from "./errors.js";

const MAX_EMAIL = 254;
const MAX_CNPJ_INPUT = 32;
const MAX_PHONE_INPUT = 32;
const MAX_ATTRIBUTION_VALUE = 512;
const MAX_LANDING_PAGE = 2048;
const ATTRIBUTION_KEYS = Object.freeze([
  "src",
  "utm_source",
  "utm_medium",
  "utm_campaign",
  "utm_term",
  "utm_content",
]);
const ATTRIBUTION_TOUCH_KEYS = new Set([...ATTRIBUTION_KEYS, "captured_at", "landing_page"]);
export const EMPLOYEE_RANGES = Object.freeze([
  "1-9",
  "10-29",
  "30-49",
  "50-99",
  "100-249",
  "250+",
]);
const EMPLOYEE_RANGE_SET = new Set(EMPLOYEE_RANGES);

export function normalizeEmail(value) {
  if (typeof value !== "string" || value.length > MAX_EMAIL) throw new AppError("invalid_email", 422);
  const email = value.trim().toLowerCase();
  if (!email || email.length > MAX_EMAIL || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new AppError("invalid_email", 422);
  }
  return email;
}

export function normalizeCnpj(value) {
  if (typeof value !== "string" || value.length > MAX_CNPJ_INPUT) throw new AppError("invalid_cnpj", 422);
  if (/[^\d.\/-]/.test(value)) throw new AppError("invalid_cnpj", 422);
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 14 || !isValidCnpjDigits(digits)) throw new AppError("invalid_cnpj", 422);
  return digits;
}

export function isValidCnpjDigits(cnpj) {
  if (!/^\d{14}$/.test(cnpj) || /^(\d)\1{13}$/.test(cnpj)) return false;
  const calculate = (base) => {
    let sum = 0;
    let factor = base.length - 7;
    for (const digit of base) {
      sum += Number(digit) * factor--;
      if (factor < 2) factor = 9;
    }
    const remainder = sum % 11;
    return remainder < 2 ? 0 : 11 - remainder;
  };
  const first = calculate(cnpj.slice(0, 12));
  const second = calculate(`${cnpj.slice(0, 12)}${first}`);
  return cnpj === `${cnpj.slice(0, 12)}${first}${second}`;
}

export function normalizeBrazilianPhone(value) {
  if (typeof value !== "string" || value.length > MAX_PHONE_INPUT) throw new AppError("invalid_phone", 422);
  if (/[^\d()+.\-\s]/.test(value)) throw new AppError("invalid_phone", 422);
  let digits = value.replace(/\D/g, "");
  if (digits.startsWith("00")) digits = digits.slice(2);
  if (digits.length === 10 || digits.length === 11) digits = `55${digits}`;
  if (!/^55[1-9]\d(?:\d{8}|\d{9})$/.test(digits)) throw new AppError("invalid_phone", 422);
  return `+${digits}`;
}

export function normalizeEmployeeRange(value) {
  if (typeof value !== "string" || !EMPLOYEE_RANGE_SET.has(value)) {
    throw new AppError("invalid_employee_range", 422);
  }
  return value;
}

function normalizeAttributionTouch(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) throw new AppError("invalid_attribution", 422);
  if (Object.keys(value).some((key) => !ATTRIBUTION_TOUCH_KEYS.has(key))) {
    throw new AppError("invalid_attribution", 422);
  }
  const result = {};
  for (const key of ATTRIBUTION_KEYS) {
    if (value[key] === undefined || value[key] === null) continue;
    if (typeof value[key] !== "string") throw new AppError("invalid_attribution", 422);
    const normalized = value[key].trim();
    if (!normalized || normalized.length > MAX_ATTRIBUTION_VALUE) throw new AppError("invalid_attribution", 422);
    result[key] = normalized;
  }
  if (!Object.keys(result).length) throw new AppError("invalid_attribution", 422);
  if (value.captured_at !== undefined && value.captured_at !== null) {
    if (typeof value.captured_at !== "string" || value.captured_at.length > 64) {
      throw new AppError("invalid_attribution", 422);
    }
    const capturedAt = new Date(value.captured_at);
    if (Number.isNaN(capturedAt.getTime())) throw new AppError("invalid_attribution", 422);
    result.captured_at = capturedAt.toISOString();
  }
  if (value.landing_page !== undefined && value.landing_page !== null) {
    if (typeof value.landing_page !== "string" || value.landing_page.length > MAX_LANDING_PAGE
      || !value.landing_page.startsWith("/") || value.landing_page.startsWith("//")) {
      throw new AppError("invalid_attribution", 422);
    }
    result.landing_page = value.landing_page;
  }
  return result;
}

export function normalizeAttribution(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new AppError("invalid_attribution", 422);
  const allowed = new Set(["first_touch", "last_touch"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new AppError("invalid_attribution", 422);
  const firstTouch = normalizeAttributionTouch(value.first_touch);
  const lastTouch = normalizeAttributionTouch(value.last_touch);
  if (!firstTouch && !lastTouch) throw new AppError("invalid_attribution", 422);
  return { first_touch: firstTouch, last_touch: lastTouch };
}

export function validateUuid(value, errorCode = "invalid_idempotency_key") {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new AppError(errorCode, 422);
  }
  return value.toLowerCase();
}

export const FIELD_LIMITS = { MAX_EMAIL, MAX_CNPJ_INPUT, MAX_PHONE_INPUT };
