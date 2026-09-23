import { AppError } from "../errors.js";
import { verifyShopifyHmac } from "../security.js";
import { normalizeEmail } from "../validation.js";
import { DATA_DIGEST_VERSION, webhookPayloadDigest } from "../data-digests.js";
import { registrationIdentityHash, REGISTRATION_IDENTITY_KEY_VERSION } from "../registration-identities.js";

export class WebhookService {
  constructor({ store, webhookSecret, dataDigestSecret, clock }) {
    this.store = store;
    this.webhookSecret = webhookSecret;
    this.dataDigestSecret = dataDigestSecret;
    this.clock = clock;
  }

  async customersCreate({ rawBody, hmac, webhookIdHeader, eventIdHeader, topicHeader, shopHeader }) {
    if (!verifyShopifyHmac(rawBody, hmac, this.webhookSecret)) throw new AppError("unauthorized", 401);
    let payload;
    try { payload = JSON.parse(rawBody.toString("utf8")); } catch { throw new AppError("invalid_payload", 400); }
    const email = normalizeEmail(payload?.email);
    const emailClaim = {
      type: "email",
      keyVersion: REGISTRATION_IDENTITY_KEY_VERSION,
      valueHash: registrationIdentityHash({ type: "email", normalized: email, secret: this.dataDigestSecret }),
    };
    const customerId = payload?.id === undefined || payload?.id === null ? "" : String(payload.id);
    if (!customerId || customerId.length > 128) throw new AppError("invalid_payload", 400);
    const topic = String(topicHeader || "customers/create").slice(0, 100);
    const payloadDigest = webhookPayloadDigest(rawBody, this.dataDigestSecret);
    const eventId = String(webhookIdHeader || eventIdHeader || `${topic}:${shopHeader || "unknown"}:${customerId}`).slice(0, 255);
    return this.store.associateWebhook({
      eventId,
      topic,
      payloadDigest,
      payloadDigestVersion: DATA_DIGEST_VERSION,
      email,
      emailClaim,
      customerId,
      now: this.clock(),
    });
  }
}
