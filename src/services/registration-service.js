import { AppError, ExternalServiceError } from "../errors.js";
import { digest, signRegistrationToken } from "../security.js";
import { normalizeBrazilianPhone, normalizeCnpj, normalizeEmail, validateUuid } from "../validation.js";

export class RegistrationService {
  constructor({ store, registryClient, clock, reservationTtlMs, registrationTokenSecret }) {
    this.store = store;
    this.registryClient = registryClient;
    this.clock = clock;
    this.reservationTtlMs = reservationTtlMs;
    this.registrationTokenSecret = registrationTokenSecret;
  }

  response(registration) {
    return {
      ok: true,
      registration_id: registration.id,
      registration_token: signRegistrationToken(registration, this.registrationTokenSecret),
      status: registration.status,
      expires_at: new Date(registration.expires_at).toISOString(),
    };
  }

  async create(body, idempotencyHeader) {
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new AppError("invalid_request", 422);
    const allowed = new Set(["email", "cnpj", "phone"]);
    if (Object.keys(body).some((key) => !allowed.has(key))) throw new AppError("invalid_request", 422);
    const idempotencyKey = validateUuid(idempotencyHeader);
    const email = normalizeEmail(body?.email);
    const cnpj = normalizeCnpj(body?.cnpj);
    const phone = normalizeBrazilianPhone(body?.phone);
    const requestDigest = digest(JSON.stringify({ email, cnpj, phone }));
    const now = this.clock();

    const previous = await this.store.findByIdempotencyKey(idempotencyKey);
    if (previous && new Date(previous.expires_at) > now) {
      if (previous.request_digest !== requestDigest) throw new AppError("idempotency_conflict", 409);
      return this.response(previous);
    }

    let fiscal;
    try {
      fiscal = await this.registryClient.checkCnpj(cnpj);
    } catch (error) {
      if (error instanceof ExternalServiceError) throw error;
      throw new ExternalServiceError("registry", "registry_unavailable", { cause: error });
    }
    if (!fiscal.found || !fiscal.active || fiscal.status !== "ATIVA") throw new AppError("inactive_cnpj", 422);

    const expiresAt = new Date(now.getTime() + this.reservationTtlMs);
    const result = await this.store.reserve({
      email, cnpj, phone, idempotencyKey, requestDigest,
      fiscalStatus: "ATIVA", now, expiresAt,
    });
    return this.response(result.registration);
  }
}
