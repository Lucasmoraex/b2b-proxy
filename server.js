import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();

/* ======== ENVs ======== */
const SHOP  = process.env.SHOPIFY_SHOP || "elementsparaempresas.myshopify.com";
const TOKEN = process.env.SHOPIFY_ADMIN_TOKEN || "";

const ORIGINS_ENV =
  process.env.B2B_ALLOWED_ORIGIN ||
  "https://corporativo.elements.com.br,https://elementsparaempresas.myshopify.com";

const ADMIN_SECRET = process.env.B2B_ADMIN_SECRET || "";

// ===== ReceitaWS =====
const RECEITAWS_TOKEN = process.env.B2B_RECEITAWS_TOKEN || "";
const RECEITAWS_BASE  = (process.env.B2B_RECEITAWS_BASE || "https://www.receitaws.com.br/v1").replace(/\/$/, "");
const RECEITAWS_TOKEN_MODE = (process.env.B2B_RECEITAWS_TOKEN_MODE || "bearer").toLowerCase();

// Auto-approve quando ReceitaWS retornar empresa ATIVA
const AUTO_APPROVE =
  String(process.env.B2B_AUTO_APPROVE || "true").toLowerCase() === "true";

// Cache TTL para consultas de CNPJ (ms)
const CNPJ_CACHE_TTL_MS = Number(process.env.B2B_CNPJ_CACHE_TTL_MS || 1000 * 60 * 60 * 24); // 24h
/* ====================== */

/* ======== Helpers de log ======== */
function rid() { return Math.random().toString(36).slice(2, 8) + Date.now().toString(36).slice(-6); }
function nowMS() { return Date.now(); }
function fmt(obj) { try { return JSON.stringify(obj); } catch { return String(obj); } }
function logStart(req, tag = "START") {
  const id = rid();
  req._reqId = id; req._t0 = nowMS();
  const ip = req.headers["x-forwarded-for"] || req.ip || "";
  const ua = req.headers["user-agent"] || "";
  const origin = req.headers.origin || "";
  console.log(`[${tag}] ${req.method} ${req.path} reqId=${id} ip="${ip}" ua="${ua}" origin="${origin}" path="${req.originalUrl || req.url}"`);
}
function logEnd(req, statusCode, extra = "") {
  const elapsed = req._t0 ? (nowMS() - req._t0) : -1;
  console.log(`[END]   ${req.method} ${req.path} reqId=${req._reqId} elapsedMS=${elapsed} -> ${statusCode}${extra ? " " + extra : ""}`);
}
function logInfo(req, msg, obj) { console.log(`[INFO]  reqId=${req._reqId} ${msg}${obj !== undefined ? " " + fmt(obj) : ""}`); }
function logWarn(req, msg, obj) { console.warn(`[WARN]  reqId=${req._reqId} ${msg}${obj !== undefined ? " " + fmt(obj) : ""}`); }
function logErr(req, msg, err) { console.error(`[ERROR] reqId=${req._reqId} ${msg}`, err && err.stack ? err.stack : err); }

/* ======== App / Middlewares ======== */
app.set("trust proxy", 1);
app.set("etag", false);

app.use(rateLimit({ windowMs: 60_000, max: 60 }));
app.use(express.json());

// -------- CORS robusto --------
const ALLOWED_ORIGINS = ORIGINS_ENV.split(",").map(s => s.trim()).filter(Boolean);
function isAllowedOrigin(origin) {
  if (!origin) return true;
  try {
    const { hostname } = new URL(origin);
    if (ALLOWED_ORIGINS.includes(origin)) return true;
    if (hostname.endsWith(".myshopify.com")) return true;
    if (hostname.endsWith(".shopifypreview.com")) return true;
    if (hostname === "admin.shopify.com") return true;
  } catch {}
  return false;
}

app.use((req, _res, next) => { logStart(req); next(); });

app.use(cors({
  origin: (origin, cb) => cb(null, isAllowedOrigin(origin)),
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-B2B-Admin-Secret"],
  credentials: false,
}));

app.options("*", (req, res) => {
  if (!isAllowedOrigin(req.headers.origin || "")) {
    logWarn(req, "CORS forbidden origin", { origin: req.headers.origin });
    logEnd(req, 403);
    return res.sendStatus(403);
  }
  res.set("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type, X-B2B-Admin-Secret");
  logEnd(req, 204);
  res.sendStatus(204);
});

/* ======== Helper REST Admin ======== */
const api = async (path, opts = {}, req = null) => {
  if (req) logInfo(req, "Shopify REST ->", { path, method: opts.method || "GET" });
  const res = await fetch(`https://${SHOP}/admin/api/2024-07${path}`, {
    method: opts.method || "GET",
    headers: { "X-Shopify-Access-Token": TOKEN, "Content-Type": "application/json" },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) {
    const msg = text.slice(0, 400);
    if (req) logErr(req, `Shopify REST error ${res.status} ${path}: ${msg}`);
    throw new Error(`REST ${res.status} ${msg}`);
  }
  try {
    const json = JSON.parse(text);
    if (req) logInfo(req, "Shopify REST <- OK", { path });
    return json;
  } catch {
    if (req) logInfo(req, "Shopify REST <- (no-json)", { path });
    return {};
  }
};

const onlyDigits = (s = "") => s.replace(/\D/g, "").slice(0, 14);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ======== Validador rápido de CNPJ ======== */
function isValidCNPJ(v) {
  const c = onlyDigits(v);
  if (c.length !== 14) return false;
  if (/^(\d)\1{13}$/.test(c)) return false;
  const calc = (base) => {
    let sum = 0, factor = base.length - 7;
    for (let i = 0; i < base.length; i++) {
      sum += Number(base[i]) * factor--;
      if (factor < 2) factor = 9;
    }
    const mod = sum % 11;
    return mod < 2 ? 0 : 11 - mod;
  };
  const d1 = calc(c.slice(0, 12));
  const d2 = calc(c.slice(0, 12) + d1);
  return c.endsWith(`${d1}${d2}`);
}

/* ======== Cache simples em memória ======== */
const cnpjCache = new Map();
function getFromCache(cnpj) {
  const k = onlyDigits(cnpj);
  const hit = cnpjCache.get(k);
  if (hit && hit.exp > Date.now()) return hit.data;
  if (hit) cnpjCache.delete(k);
  return null;
}
function saveToCache(cnpj, data) {
  cnpjCache.set(onlyDigits(cnpj), { exp: Date.now() + CNPJ_CACHE_TTL_MS, data });
}

/* ======== ReceitaWS ======== */
async function fetchCnpjReceitaWS(cnpj, req) {
  const num = onlyDigits(cnpj);
  const cached = getFromCache(num);
  if (cached) {
    logInfo(req, "ReceitaWS cache HIT", { cnpj: num, active: cached.active, found: cached.found });
    return cached;
  }

  let url = `${RECEITAWS_BASE}/cnpj/${num}`;
  const headers = {};
  if (RECEITAWS_TOKEN) {
    if (RECEITAWS_TOKEN_MODE === "bearer") headers["Authorization"] = `Bearer ${RECEITAWS_TOKEN}`;
    else url += (url.includes("?") ? "&" : "?") + `token=${encodeURIComponent(RECEITAWS_TOKEN)}`;
  }

  logInfo(req, "ReceitaWS ->", { url: url.replace(/\/cnpj\/\d+/, "/cnpj/************") });
  const res = await fetch(url, { headers });
  const json = await res.json().catch(() => ({}));
  logInfo(req, "ReceitaWS <-", { status: res.status, keys: Object.keys(json || {}) });

  if (json && json.status === "OK") {
    const result = {
      provider: "receitaws",
      found: true,
      active: String(json.situacao || "").toUpperCase() === "ATIVA",
      razao: json.nome || "",
      fantasia: json.fantasia || "",
      abertura: json.abertura || "",
      uf: json.uf || "",
      raw: json,
    };
    saveToCache(num, result);
    return result;
  }

  if (json && (json.nome || json.razao || json.razao_social)) {
    const result = {
      provider: "receitaws",
      found: true,
      active: String(json.situacao || json.situacao_cadastral || "").toUpperCase().includes("ATIV"),
      razao: json.nome || json.razao || json.razao_social || "",
      fantasia: json.fantasia || json.nome_fantasia || "",
      abertura: json.abertura || json.data_abertura || "",
      uf: json.uf || (json.endereco && json.endereco.uf) || "",
      raw: json,
    };
    saveToCache(num, result);
    return result;
  }

  const notFound = { provider: "receitaws", found: false, active: false, err: (json && (json.message || json.error || json.status)) || "not_found", raw: json };
  saveToCache(num, notFound);
  return notFound;
}

/* ======== Helpers Shopify ======== */
async function findCustomerByEmail(email, req) {
  logInfo(req, "findCustomerByEmail", { email });
  const q = encodeURIComponent(`email:${email}`);
  const cs = await api(`/customers/search.json?query=${q}`, {}, req);
  const found = (cs.customers || [])[0] || null;
  logInfo(req, "findCustomerByEmail result", { found: !!found, id: found?.id });
  return found;
}

async function getCustomerById(id, req) {
  logInfo(req, "getCustomerById", { id });
  const json = await api(`/customers/${id}.json`, {}, req);
  const c = json && json.customer ? json.customer : null;
  logInfo(req, "getCustomerById result", { found: !!c, id: c?.id });
  return c;
}

async function waitForCustomerByEmail(email, retries = 8, delayMs = 800, req) {
  for (let i = 0; i < retries; i++) {
    const c = await findCustomerByEmail(email, req);
    if (c) return c;
    logInfo(req, "waitForCustomer retry", { i: i + 1 });
    await sleep(delayMs);
  }
  return null;
}

async function setCustomerTags(customerId, tagsArray, req) {
  const tags = [...new Set(tagsArray.map(t => t.trim()).filter(Boolean))].join(", ");
  logInfo(req, "setCustomerTags ->", { customerId, tags });
  await api(`/customers/${customerId}.json`, { method: "PUT", body: { customer: { id: customerId, tags } } }, req);
}

async function upsertCustomerMetafield(customerId, key, value, type = "single_line_text_field", namespace = "custom", req) {
  logInfo(req, "upsert metafield ->", { customerId, namespace, key, value, type });
  const metas = await api(`/customers/${customerId}/metafields.json?namespace=${namespace}`, {}, req);
  const existing = (metas.metafields || []).find(m => String(m.key).toLowerCase() === String(key).toLowerCase());

  if (existing) {
    await api(`/metafields/${existing.id}.json`, { method: "PUT", body: { metafield: { id: existing.id, value, type } } }, req);
  } else {
    await api(`/metafields.json`, {
      method: "POST",
      body: { metafield: { namespace, key, owner_id: customerId, owner_resource: "customer", type, value } },
    }, req);
  }
  logInfo(req, "upsert metafield <- OK", { key });
}

/* ======== Validar e aprovar se ATIVA ======== */
async function validateAndMaybeApprove(customer, cnpjNum, req) {
  const num = onlyDigits(cnpjNum);
  const result = await fetchCnpjReceitaWS(num, req);

  await upsertCustomerMetafield(customer.id, "cnpj_exists", String(!!result.found), "boolean", "custom", req);
  await upsertCustomerMetafield(customer.id, "cnpj_situacao", result.active ? "ATIVA" : "INATIVA", "single_line_text_field", "custom", req);
  if (result.razao)    await upsertCustomerMetafield(customer.id, "cnpj_razao", result.razao, "single_line_text_field", "custom", req);
  if (result.fantasia) await upsertCustomerMetafield(customer.id, "cnpj_fantasia", result.fantasia, "single_line_text_field", "custom", req);
  await upsertCustomerMetafield(customer.id, "cnpj_checked_at", new Date().toISOString(), "date_time", "custom", req);

  let approved = false;
  if (AUTO_APPROVE && result.found && result.active) {
    logInfo(req, "auto-approve ON", { found: result.found, active: result.active });
    const currentTags = (customer.tags || "").split(",").map(t => t.trim()).filter(Boolean);
    if (!currentTags.includes("b2b-approved")) currentTags.push("b2b-approved");
    const tags = currentTags.filter(t => t !== "b2b-pending");
    await setCustomerTags(customer.id, tags, req);
    await upsertCustomerMetafield(customer.id, "cnpj_status", "approved", "single_line_text_field", "custom", req);
    approved = true;
  } else {
    // Remover b2b-approved por segurança e manter pendente
    const current = (customer.tags || "").split(",").map(t => t.trim()).filter(Boolean);
    const tags = current.filter(t => t !== "b2b-approved");
    await setCustomerTags(customer.id, tags, req);
    await upsertCustomerMetafield(customer.id, "cnpj_status", "pending", "single_line_text_field", "custom", req);
    logInfo(req, "not auto-approved", { found: result.found, active: result.active, AUTO_APPROVE });
  }

  return { approved, result };
}

/* ======== Guard admin ======== */
function hasSecret(req) { const header = req.header("X-B2B-Admin-Secret"); const qp = req.query.secret; return ADMIN_SECRET && (header === ADMIN_SECRET || qp === ADMIN_SECRET); }
function guard(req, res) {
  if (!hasSecret(req)) { logWarn(req, "admin unauthorized"); res.status(401).json({ ok: false, error: "unauthorized" }); return false; }
  return true;
}

/* ======== Public: validação de login ======== */
app.get("/validate-login", async (req, res) => {
  res.set({ "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Expires": "0", "Surrogate-Control": "no-store", "Vary": "Origin" });

  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    const cnpj  = onlyDigits(String(req.query.cnpj || ""));

    logInfo(req, "validate-login payload", { email, cnpj_len: cnpj.length });

    if (!email || cnpj.length !== 14) { logWarn(req, "validate-login invalid params"); logEnd(req, 400); return res.status(400).json({ ok: false, exists: false }); }

    const customer = await findCustomerByEmail(email, req);
    if (!customer) { logInfo(req, "validate-login no customer"); logEnd(req, 200); return res.json({ ok: true, exists: false }); }

    const metas = await api(`/customers/${customer.id}/metafields.json?namespace=custom`, {}, req);
    const mfCnpjField = (metas.metafields || []).find(m => m.key?.toLowerCase() === "cnpj" || m.key?.toLowerCase() === "cjnpj");
    const mfStatusField = (metas.metafields || []).find(m => m.key?.toLowerCase() === "cnpj_status");

    const mfCnpj = mfCnpjField ? String(mfCnpjField.value || "") : "";
    const cnpj_status = (mfStatusField ? String(mfStatusField.value || "") : "").toLowerCase();
    const cnpj_match = onlyDigits(mfCnpj) === cnpj;

    const hasApprovedTag = (customer.tags || "").split(",").map(t => t.trim()).includes("b2b-approved");
    const approved = hasApprovedTag && cnpj_status === "approved";

    const payload = { ok: true, exists: true, cnpj_match, approved, cnpj_status };
    logInfo(req, "validate-login response", payload);
    logEnd(req, 200);
    res.json(payload);
  } catch (e) {
    logErr(req, "validate-login error", e);
    logEnd(req, 500);
    res.status(500).json({ ok: false, exists: false });
  }
});

/* ======== Public: PRECHECK (não mexe no Shopify) ======== */
app.post("/precheck-cnpj", async (req, res) => {
  res.set({ "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Expires": "0", "Vary": "Origin" });

  try {
    const { cnpj } = req.body || {};
    const num = onlyDigits(cnpj || "");

    logInfo(req, "precheck-cnpj payload", { cnpj_tail: num.slice(-4), len: num.length });

    if (num.length !== 14 || !isValidCNPJ(num)) {
      logWarn(req, "precheck-cnpj invalid_params");
      logEnd(req, 400, "invalid_params");
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    const result = await fetchCnpjReceitaWS(num, req);
    const payload = { ok: true, found: !!result.found, active: !!result.active };
    logInfo(req, "precheck-cnpj response", payload);
    logEnd(req, 200);
    res.json(payload);
  } catch (e) {
    logErr(req, "precheck-cnpj error", e);
    logEnd(req, 500);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

/* ======== Public: registrar CNPJ (grava/aprova após criação do cliente) ======== */
app.post("/register-cnpj", async (req, res) => {
  res.set({ "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Expires": "0", "Vary": "Origin" });

  try {
    const { email, cnpj } = req.body || {};
    const mail = String(email || "").trim().toLowerCase();
    const num  = onlyDigits(cnpj || "");

    logInfo(req, "register-cnpj payload", { email: maskEmail(mail), cnpj_tail: num.slice(-4), len: num.length });

    if (!mail || num.length !== 14 || !isValidCNPJ(num)) {
      logWarn(req, "register-cnpj invalid_params");
      logEnd(req, 400, "invalid_params");
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    // cliente precisa existir (acabou de ser criado pela Shopify)
    const customer = await waitForCustomerByEmail(mail, 10, 700, req);
    if (!customer) {
      logWarn(req, "register-cnpj customer_not_found (timeout)");
      logEnd(req, 404, "customer_not_found");
      return res.status(404).json({ ok: false, error: "customer_not_found" });
    }
    logInfo(req, "register-cnpj found customer", { id: customer.id });

    // Metafields básicos
    await upsertCustomerMetafield(customer.id, "cnpj", num, "single_line_text_field", "custom", req);
    await upsertCustomerMetafield(customer.id, "cnpj_status", "pending", "single_line_text_field", "custom", req);

    // Tag pendência
    const tags = (customer.tags || "").split(",").map(t => t.trim()).filter(Boolean);
    if (!tags.includes("b2b-pending")) {
      tags.push("b2b-pending");
      await setCustomerTags(customer.id, tags, req);
    }

    // Valida e, se ATIVA, aprova e aplica b2b-approved
    const { approved, result } = await validateAndMaybeApprove(customer, num, req);

    const payload = {
      ok: true,
      validated: true,
      autoApproved: approved,
      provider: result.provider,
      found: result.found,
      active: result.active,
      razao: result.razao || null,
      fantasia: result.fantasia || null,
    };
    logInfo(req, "register-cnpj response", payload);
    logEnd(req, 200);
    res.json(payload);
  } catch (e) {
    logErr(req, "register-cnpj error", e);
    logEnd(req, 500);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

/* ======== Public: validar CNPJ isoladamente ======== */
app.post("/validate-cnpj", async (req, res) => {
  res.set({ "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Expires": "0", "Vary": "Origin" });

  try {
    const { email, cnpj } = req.body || {};
    const mail = String(email || "").trim().toLowerCase();
    const num  = onlyDigits(cnpj || "");

    logInfo(req, "validate-cnpj payload", { email: maskEmail(mail), cnpj_tail: num.slice(-4), len: num.length });

    if (!mail || num.length !== 14 || !isValidCNPJ(num)) {
      logWarn(req, "validate-cnpj invalid_params");
      logEnd(req, 400, "invalid_params");
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    const customer = await findCustomerByEmail(mail, req);
    if (!customer) {
      logWarn(req, "validate-cnpj customer_not_found");
      logEnd(req, 404, "customer_not_found");
      return res.status(404).json({ ok: false, error: "customer_not_found" });
    }

    const { approved, result } = await validateAndMaybeApprove(customer, num, req);

    const payload = {
      ok: true,
      autoApproved: approved,
      provider: result.provider,
      found: result.found,
      active: result.active,
      razao: result.razao || null,
      fantasia: result.fantasia || null,
    };
    logInfo(req, "validate-cnpj response", payload);
    logEnd(req, 200);
    res.json(payload);
  } catch (e) {
    logErr(req, "validate-cnpj error", e);
    logEnd(req, 500);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

/* ======== Flow: pós-criação do cliente ======== */
app.post("/flow/after-customer-created", async (req, res) => {
  if (!hasSecret(req)) {
    logWarn(req, "flow/after-customer-created unauthorized");
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  try {
    const body = req.body || {};
    const idFromBody = body.customer_id ? Number(body.customer_id) : null;
    const emailFromBody = String(body.email || "").trim().toLowerCase();
    const cnpjFromBody  = String(body.cnpj || "");

    logInfo(req, "flow/after-customer-created payload", {
      customer_id: idFromBody || null,
      email: emailFromBody || null,
      cnpj_tail: (cnpjFromBody || "").replace(/\D/g, "").slice(-4) || null
    });

    // 1) Resolve cliente por ID (preferência) ou por email
    let customer = null;
    if (idFromBody) {
      customer = await getCustomerById(idFromBody, req);
    }
    if (!customer && emailFromBody) {
      customer = await findCustomerByEmail(emailFromBody, req);
    }
    if (!customer) {
      logWarn(req, "flow: customer_not_found");
      return res.status(404).json({ ok: false, error: "customer_not_found" });
    }

    // 2) Ler metafield custom.cnpj se body não trouxe/estiver vazio
    let num = (cnpjFromBody || "").replace(/\D/g, "").slice(0, 14);
    if (!num || num.length !== 14) {
      const metas = await api(`/customers/${customer.id}/metafields.json?namespace=custom`, {}, req);
      const mfCnpjField = (metas.metafields || []).find(
        (m) => String(m.key || "").toLowerCase() === "cnpj"
      );
      if (mfCnpjField && mfCnpjField.value) {
        num = String(mfCnpjField.value).replace(/\D/g, "").slice(0, 14);
      }
    }

    if (!num || num.length !== 14 || !isValidCNPJ(num)) {
      logWarn(req, "flow: invalid or missing CNPJ");
      // mantém pendente
      await upsertCustomerMetafield(customer.id, "cnpj_status", "pending", "single_line_text_field", "custom", req);
      return res.status(400).json({ ok: false, error: "invalid_cnpj" });
    }

    // 3) Grava/garante o metafield CNPJ antes de validar
    await upsertCustomerMetafield(customer.id, "cnpj", num, "single_line_text_field", "custom", req);

    // 4) Valida e aprova se ATIVA (isso também seta cnpj_status, tags, informativos)
    const { approved, result } = await validateAndMaybeApprove(customer, num, req);

    // 5) Se NÃO aprovado, já garantimos pending e sem b2b-approved dentro de validateAndMaybeApprove
    const payload = {
      ok: true,
      approved,
      found: !!result.found,
      active: !!result.active
    };
    logInfo(req, "flow/after-customer-created response", payload);
    return res.json(payload);
  } catch (e) {
    logErr(req, "flow/after-customer-created error", e);
    return res.status(500).json({ ok: false, error: "internal_error" });
  }
});

/* ======== Admin: aprovar / reprovar ======== */
app.post("/admin/approve", async (req, res) => {
  if (!guard(req, res)) return;
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    logInfo(req, "admin/approve payload", { email: maskEmail(email) });
    if (!email) { logWarn(req, "admin/approve missing email"); logEnd(req, 400); return res.status(400).json({ ok: false, error: "missing email" }); }

    const c = await findCustomerByEmail(email, req);
    if (!c) { logInfo(req, "admin/approve not found"); logEnd(req, 200); return res.json({ ok: true, found: false }); }

    const currentTags = (c.tags || "").split(",").map(t => t.trim()).filter(Boolean);
    if (!currentTags.includes("b2b-approved")) currentTags.push("b2b-approved");
    const tags = currentTags.filter(t => t !== "b2b-pending");

    await setCustomerTags(c.id, tags, req);
    await upsertCustomerMetafield(c.id, "cnpj_status", "approved", "single_line_text_field", "custom", req);

    const payload = { ok: true, found: true, tags, cnpj_status: "approved" };
    logInfo(req, "admin/approve response", payload);
    logEnd(req, 200);
    res.json(payload);
  } catch (e) {
    logErr(req, "approve error", e);
    logEnd(req, 500);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});
app.get("/admin/approve", (req, res) => app._router.handle({ ...req, method: "POST" }, res));

app.post("/admin/reject", async (req, res) => {
  if (!guard(req, res)) return;
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    logInfo(req, "admin/reject payload", { email: maskEmail(email) });
    if (!email) { logWarn(req, "admin/reject missing email"); logEnd(req, 400); return res.status(400).json({ ok: false, error: "missing email" }); }

    const c = await findCustomerByEmail(email, req);
    if (!c) { logInfo(req, "admin/reject not found"); logEnd(req, 200); return res.json({ ok: true, found: false }); }

    const currentTags = (c.tags || "").split(",").map(t => t.trim()).filter(Boolean);
    const tags = currentTags.filter(t => t !== "b2b-approved");

    await setCustomerTags(c.id, tags, req);
    await upsertCustomerMetafield(c.id, "cnpj_status", "rejected", "single_line_text_field", "custom", req);

    const payload = { ok: true, found: true, tags, cnpj_status: "rejected" };
    logInfo(req, "admin/reject response", payload);
    logEnd(req, 200);
    res.json(payload);
  } catch (e) {
    logErr(req, "reject error", e);
    logEnd(req, 500);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});
app.get("/admin/reject", (req, res) => app._router.handle({ ...req, method: "POST" }, res));

/* ======== Root ======== */
app.get("/", (req, res) => { logEnd(req, 200); res.send("ok"); });

/* ======== Start ======== */
app.listen(process.env.PORT || 3000, () => console.log("B2B API up"));

/* ======== Utils ======== */
function maskEmail(e) {
  if (!e) return "";
  const [u, d] = e.split("@");
  if (!d) return e;
  return (u.slice(0,2) + "***@" + d);
}
