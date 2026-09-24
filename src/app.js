import crypto from "node:crypto";
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { AppError, publicError } from "./errors.js";
import { isOriginAllowed } from "./http-security.js";
import { hashClientIp } from "./rate-limit.js";
import { timingSafeEqualText, verifyRegistrationToken } from "./security.js";
import { normalizeCnpj, validateUuid } from "./validation.js";
import { RegistrationService } from "./services/registration-service.js";
import { WebhookService } from "./services/webhook-service.js";

const errorBody = (code) => ({ ok: false, error: { code, message: "Request could not be completed." } });

export function createApp(dependencies) {
  const {
    config, store, registryClient, logger, piiKeyring,
    clock = () => new Date(), legacyMutationHandler, simulationController,
  } = dependencies;
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", config.trustProxyHops > 0 ? config.trustProxyHops : false);
  app.set("etag", false);

  const registrationService = new RegistrationService({
    store, registryClient, clock,
    reservationTtlMs: config.reservationTtlMs,
    fiscalCacheTtlMs: config.fiscalCacheTtlMs,
    fiscalCacheEnabled: !config.simulationMode,
    registrationTokenSecret: config.registrationTokenSecret,
    dataDigestSecret: config.dataDigestSecret,
    piiKeyring,
    historicalIdentityLookupEnabled: config.enableHistoricalIdentityLookup,
    historicalIdentityShopDomain: config.shop,
    historicalIdentityIndexSecret: config.identityIndexSecret,
    rateLimitKeySecret: config.rateLimitKeySecret,
    sharedRateLimitWindowMs: config.sharedRateLimitWindowMs,
    sharedRateLimitMax: config.sharedRateLimitMax,
    identityRateLimitWindowMs: config.identityRateLimitWindowMs,
    identityRateLimitMax: config.identityRateLimitMax,
    activeReservationsPerIpMax: config.activeReservationsPerIpMax,
    rateLimitStateRetentionMs: config.rateLimitStateRetentionMs,
    rateLimitCleanupBatchSize: config.rateLimitCleanupBatchSize,
  });
  const webhookService = new WebhookService({
    store,
    webhookSecret: config.shopifyWebhookSecret,
    dataDigestSecret: config.dataDigestSecret,
    clock,
  });

  const logPath = (req) => {
    const routePath = req.route?.path;
    return typeof routePath === "string" ? routePath : "/unmatched";
  };

  app.use((req, res, next) => {
    req.requestId = crypto.randomUUID();
    const started = Date.now();
    res.on("finish", () => logger.info("http_request", {
      requestId: req.requestId, method: req.method, path: logPath(req),
      status: res.statusCode, elapsedMs: Date.now() - started,
    }));
    next();
  });

  app.use(cors({
    origin(origin, callback) {
      if (!origin) return callback(null, false);
      if (isOriginAllowed(origin, config)) return callback(null, true);
      return callback(new AppError("origin_not_allowed", 403));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-B2B-Registration-Token",
      "Idempotency-Key",
      "X-B2B-Admin-Secret",
      "X-Shopify-Hmac-Sha256",
      "X-Shopify-Webhook-Id",
      "X-Shopify-Event-Id",
      "X-Shopify-Topic",
      "X-Shopify-Shop-Domain",
    ],
    credentials: false,
  }));

  const limiter = rateLimit({
    windowMs: config.rateLimitWindowMs,
    max: config.rateLimitMax,
    standardHeaders: false,
    legacyHeaders: false,
    validate: false,
    keyGenerator: (req) => hashClientIp(req.ip, config.rateLimitKeySecret),
    handler: (_req, res) => res.status(429).json(errorBody("rate_limited")),
  });
  app.use(["/v1/registrations", "/precheck-cnpj", "/register-cnpj", "/validate-cnpj", "/validate-login", "/admin"], limiter);

  app.use((req, _res, next) => {
    if (Object.keys(req.query || {}).some((key) => /(secret|token|authorization)/i.test(key))) {
      return next(new AppError("invalid_request", 400));
    }
    next();
  });

  const requireJson = (req, _res, next) => {
    if (!req.is("application/json")) return next(new AppError("unsupported_media_type", 415));
    next();
  };
  const jsonParser = express.json({ limit: config.jsonBodyLimitBytes, strict: true });
  const requireRegistrationOrigin = (req, _res, next) => {
    if (config.environment === "production" && !req.get("Origin")) {
      return next(new AppError("origin_required", 403));
    }
    next();
  };

  app.post("/webhooks/shopify/customers-create", requireJson,
    express.raw({ type: "application/json", limit: config.webhookBodyLimitBytes }), async (req, res, next) => {
    try {
      const result = await webhookService.customersCreate({
        rawBody: req.body,
        hmac: req.get("X-Shopify-Hmac-Sha256"),
        webhookIdHeader: req.get("X-Shopify-Webhook-Id"),
        eventIdHeader: req.get("X-Shopify-Event-Id"),
        topicHeader: req.get("X-Shopify-Topic"),
        shopHeader: req.get("X-Shopify-Shop-Domain"),
      });
      res.status(202).json({ ok: true, accepted: true, duplicate: Boolean(result.duplicate), matched: Boolean(result.found) });
    } catch (error) { next(error); }
    });

  const requireAdmin = (req, _res, next) => {
    if (!timingSafeEqualText(req.get("X-B2B-Admin-Secret"), config.adminSecret)) return next(new AppError("unauthorized", 401));
    next();
  };

  app.get(["/", "/health"], (_req, res) => res.json({ ok: true }));

  app.post("/v1/registrations", requireRegistrationOrigin, requireJson, jsonParser, async (req, res, next) => {
    try {
      const response = await registrationService.create(req.body, req.get("Idempotency-Key"), {
        ipHash: hashClientIp(req.ip, config.rateLimitKeySecret),
      });
      res.status(201).json(response);
    } catch (error) { next(error); }
  });

  app.get("/v1/registrations/:id", async (req, res, next) => {
    try {
      const id = validateUuid(req.params.id, "invalid_registration_id");
      const registration = await store.getRegistration(id);
      const supplied = String(req.get("Authorization") || "").replace(/^Bearer\s+/i, "") || req.get("X-B2B-Registration-Token");
      const authenticated = verifyRegistrationToken({
        registration,
        suppliedToken: supplied,
        secret: config.registrationTokenSecret,
        now: clock(),
        clockToleranceMs: config.registrationTokenClockToleranceMs,
      });
      if (!authenticated) throw new AppError("unauthorized", 401);
      res.json({ ok: true, registration_id: registration.id, status: registration.status, expires_at: new Date(registration.expires_at).toISOString() });
    } catch (error) { next(error); }
  });

  app.post("/precheck-cnpj", requireJson, jsonParser, async (req, res, next) => {
    try {
      const cnpj = normalizeCnpj(req.body?.cnpj);
      const result = await registryClient.checkCnpj(cnpj);
      res.json({ ok: true, found: Boolean(result.found), active: Boolean(result.active) });
    } catch (error) { next(error); }
  });

  const requireLegacyMutations = (_req, res, next) => {
    if (!config.enableLegacyMutations) return res.status(410).json(errorBody("legacy_endpoint_disabled"));
    next();
  };

  app.post("/register-cnpj", requireLegacyMutations, requireJson, jsonParser, requireAdmin, async (req, res, next) => {
    try {
      if (!legacyMutationHandler) throw new AppError("legacy_endpoint_unavailable", 503);
      const result = await legacyMutationHandler.register(req.body);
      res.json(result);
    } catch (error) { next(error); }
  });

  app.post("/validate-cnpj", requireLegacyMutations, requireJson, jsonParser, requireAdmin, async (req, res, next) => {
    try {
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

  app.post("/admin/approve", requireJson, jsonParser, requireAdmin, adminOperation("approve"));
  app.post("/admin/reject", requireJson, jsonParser, requireAdmin, adminOperation("reject"));
  app.post("/admin/reconcile", requireJson, jsonParser, requireAdmin, async (req, res, next) => {
    try {
      const id = validateUuid(req.body?.registration_id, "invalid_registration_id");
      await store.enqueueReconciliation(id);
      res.status(202).json({ ok: true, registration_id: id, queued: true });
    } catch (error) { next(error); }
  });

  if (config.simulationMode) {
    app.get("/admin/simulation", requireAdmin, (_req, res) => {
      res.json({ ok: true, simulation: true, registry_scenario: simulationController.getRegistryScenario() });
    });
    app.post("/admin/simulation/registry", requireJson, jsonParser, requireAdmin, (req, res, next) => {
      try {
        simulationController.setRegistryScenario(String(req.body?.scenario || ""));
        res.json({ ok: true, registry_scenario: simulationController.getRegistryScenario() });
      } catch (error) { next(new AppError("invalid_simulation_scenario", 422, { cause: error })); }
    });
    app.get("/admin/simulation/shopify/:customerId", requireAdmin, async (req, res, next) => {
      try {
        const customerId = String(req.params.customerId || "");
        if (!customerId || customerId.length > 128) throw new AppError("invalid_target", 422);
        const customer = await store.getSimulationCustomer(customerId);
        if (!customer) throw new AppError("simulation_customer_not_found", 404);
        res.json({ ok: true, customer });
      } catch (error) { next(error); }
    });
  }

  app.use((_req, res) => res.status(404).json(errorBody("not_found")));
  app.use((error, req, res, _next) => {
    const exposed = publicError(error);
    logger.warn("request_failed", {
      requestId: req.requestId,
      path: logPath(req),
      code: exposed.code,
      category: exposed.status >= 500 ? "internal" : "request",
      status: exposed.status,
    });
    res.status(exposed.status).json(errorBody(exposed.code));
  });
  return app;
}
