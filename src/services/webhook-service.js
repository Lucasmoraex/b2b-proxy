import { AppError } from "../errors.js";
import { digest, verifyShopifyHmac } from "../security.js";
import { normalizeEmail } from "../validation.js";

export class WebhookService {
  constructor({ store, webhookSecret, clock }) {
    this.store = store;
    this.webhookSecret = webhookSecret;
    this.clock = clock;
  }

  async customersCreate({ rawBody, hmac, eventIdHeader, topicHeader, shopHeader }) {
    if (!verifyShopifyHmac(rawBody, hmac, this.webhookSecret)) throw new AppError("unauthorized", 401);
    let payload;
    try { payload = JSON.parse(rawBody.toString("utf8")); } catch { throw new AppError("invalid_payload", 400); }
    const email = normalizeEmail(payload?.email);
    const customerId = payload?.id === undefined || payload?.id === null ? "" : String(payload.id);
    if (!customerId || customerId.length > 128) throw new AppError("invalid_payload", 400);
    const topic = String(topicHeader || "customers/create").slice(0, 100);
    const payloadDigest = digest(rawBody);
    const eventId = String(eventIdHeader || `${topic}:${shopHeader || "unknown"}:${customerId}`).slice(0, 255);
    return this.store.associateWebhook({ eventId, topic, payloadDigest, email, customerId, now: this.clock() });
  }
}
