import { AppError } from "./errors.js";

const MAX_EMAIL = 254;
const MAX_CNPJ_INPUT = 32;
const MAX_PHONE_INPUT = 32;

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

export function validateUuid(value, errorCode = "invalid_idempotency_key") {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new AppError(errorCode, 422);
  }
  return value.toLowerCase();
}

export const FIELD_LIMITS = { MAX_EMAIL, MAX_CNPJ_INPUT, MAX_PHONE_INPUT };
