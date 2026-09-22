import crypto from "node:crypto";
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { AppError, publicError } from "./errors.js";
import { signRegistrationToken, timingSafeEqualText } from "./security.js";
import { normalizeCnpj, validateUuid } from "./validation.js";
import { RegistrationService } from "./services/registration-service.js";
import { WebhookService } from "./services/webhook-service.js";

const errorBody = (code) => ({ ok: false, error: { code, message: "Request could not be completed." } });

export function createApp(dependencies) {
  const { config, store, registryClient, logger, clock = () => new Date(), legacyMutationHandler } = dependencies;
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.set("etag", false);

  const registrationService = new RegistrationService({
    store, registryClient, clock,
    reservationTtlMs: config.reservationTtlMs,
    registrationTokenSecret: config.registrationTokenSecret,
  });
  const webhookService = new WebhookService({ store, webhookSecret: config.shopifyWebhookSecret, clock });

  app.use((req, res, next) => {
    req.requestId = crypto.randomUUID();
    const started = Date.now();
    res.on("finish", () => logger.info("http_request", {
      requestId: req.requestId, method: req.method, path: req.path,
      status: res.statusCode, elapsedMs: Date.now() - started,
    }));
    next();
  });

  app.use(cors({
    origin(origin, callback) {
      if (!origin || config.allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new AppError("origin_not_allowed", 403));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Idempotency-Key", "X-B2B-Admin-Secret", "X-Shopify-Hmac-Sha256", "X-Shopify-Event-Id", "X-Shopify-Topic", "X-Shopify-Shop-Domain"],
    credentials: false,
  }));

  const limiter = rateLimit({
    windowMs: config.rateLimitWindowMs,
    max: config.rateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => res.status(429).json(errorBody("rate_limited")),
  });
  app.use(["/v1/registrations", "/precheck-cnpj", "/register-cnpj", "/validate-cnpj", "/validate-login", "/admin"], limiter);

  app.post("/webhooks/shopify/customers-create", express.raw({ type: "application/json", limit: "256kb" }), async (req, res, next) => {
    try {
      const result = await webhookService.customersCreate({
        rawBody: req.body,
        hmac: req.get("X-Shopify-Hmac-Sha256"),
        eventIdHeader: req.get("X-Shopify-Event-Id"),
        topicHeader: req.get("X-Shopify-Topic"),
        shopHeader: req.get("X-Shopify-Shop-Domain"),
      });
      res.status(202).json({ ok: true, accepted: true, duplicate: Boolean(result.duplicate), matched: Boolean(result.found) });
    } catch (error) { next(error); }
  });

  app.use(express.json({ limit: "16kb", strict: true }));

  const requireAdmin = (req, _res, next) => {
    if (!timingSafeEqualText(req.get("X-B2B-Admin-Secret"), config.adminSecret)) return next(new AppError("unauthorized", 401));
    next();
  };

  app.get(["/", "/health"], (_req, res) => res.json({ ok: true }));

  app.post("/v1/registrations", async (req, res, next) => {
    try {
      const response = await registrationService.create(req.body, req.get("Idempotency-Key"));
      res.status(201).json(response);
    } catch (error) { next(error); }
  });

  app.get("/v1/registrations/:id", async (req, res, next) => {
    try {
      const id = validateUuid(req.params.id, "invalid_registration_id");
      const registration = await store.getRegistration(id);
      if (!registration) throw new AppError("registration_not_found", 404);
      const supplied = String(req.get("Authorization") || "").replace(/^Bearer\s+/i, "") || req.get("X-B2B-Registration-Token");
      const expected = signRegistrationToken(registration, config.registrationTokenSecret);
      if (!timingSafeEqualText(supplied, expected)) throw new AppError("unauthorized", 401);
      res.json({ ok: true, registration_id: registration.id, status: registration.status, expires_at: new Date(registration.expires_at).toISOString() });
    } catch (error) { next(error); }
  });

  app.post("/precheck-cnpj", async (req, res, next) => {
    try {
      const cnpj = normalizeCnpj(req.body?.cnpj);
      const result = await registryClient.checkCnpj(cnpj);
      res.json({ ok: true, found: Boolean(result.found), active: Boolean(result.active) });
    } catch (error) { next(error); }
  });

  app.post("/register-cnpj", async (req, res, next) => {
    if (!config.enableLegacyMutations) return res.status(410).json(errorBody("legacy_endpoint_disabled"));
    try {
      await new Promise((resolve, reject) => requireAdmin(req, res, (error) => error ? reject(error) : resolve()));
      if (!legacyMutationHandler) throw new AppError("legacy_endpoint_unavailable", 503);
      const result = await legacyMutationHandler.register(req.body);
      res.json(result);
    } catch (error) { next(error); }
  });

  app.post("/validate-cnpj", async (req, res, next) => {
    if (!config.enableLegacyMutations) return res.status(410).json(errorBody("legacy_endpoint_disabled"));
    try {
      await new Promise((resolve, reject) => requireAdmin(req, res, (error) => error ? reject(error) : resolve()));
      const cnpj = normalizeCnpj(req.body?.cnpj);
      const result = await registryClient.checkCnpj(cnpj);
      res.json({ ok: true, found: Boolean(result.found), active: Boolean(result.active) });
    } catch (error) { next(error); }
  });

  app.all("/validate-login", (_req, res) => res.status(410).json(errorBody("legacy_login_removed")));

  const adminOperation = (action) => async (req, res, next) => {
    try {
      const registrationId = req.body?.registration_id ? validateUuid(req.body.registration_id, "invalid_registration_id") : null;
      const customerId = req.body?.shopify_customer_id === undefined ? null : String(req.body.shopify_customer_id);
      if (!registrationId && (!customerId || customerId.length > 128)) throw new AppError("invalid_target", 422);
      const result = await store.requestAdminOperation({ action, registrationId, customerId, now: clock() });
      res.status(result.idempotent || result.completed ? 200 : 202).json({ ok: true, registration_id: result.registration.id, status: result.registration.status, queued: !result.idempotent && !result.completed });
    } catch (error) { next(error); }
  };

  app.post("/admin/approve", requireAdmin, adminOperation("approve"));
  app.post("/admin/reject", requireAdmin, adminOperation("reject"));
  app.post("/admin/reconcile", requireAdmin, async (req, res, next) => {
    try {
      const id = validateUuid(req.body?.registration_id, "invalid_registration_id");
      await store.enqueueReconciliation(id);
      res.status(202).json({ ok: true, registration_id: id, queued: true });
    } catch (error) { next(error); }
  });

  app.use((_req, res) => res.status(404).json(errorBody("not_found")));
  app.use((error, req, res, _next) => {
    const exposed = publicError(error);
    logger.warn("request_failed", { requestId: req.requestId, path: req.path, code: exposed.code, status: exposed.status, error });
    res.status(exposed.status).json(errorBody(exposed.code));
  });
  return app;
}
