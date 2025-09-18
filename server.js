// server.js (com logs)

import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();

/* ======== ENVs ======== */
// Shop/admin continuam no domínio myshopify (NÃO troque)
const SHOP  = process.env.SHOPIFY_SHOP || "elementsparaempresas.myshopify.com";
const TOKEN = process.env.SHOPIFY_ADMIN_TOKEN || "";

// Agora aceitamos várias origens, separadas por vírgula.
// Ex.: B2B_ALLOWED_ORIGIN="https://corporativo.elements.com.br,https://elementsparaempresas.myshopify.com"
const ORIGINS_ENV =
  process.env.B2B_ALLOWED_ORIGIN ||
  "https://corporativo.elements.com.br,https://elementsparaempresas.myshopify.com";

const ADMIN_SECRET = process.env.B2B_ADMIN_SECRET || ""; // secret para rotas /admin/*

// ===== ReceitaWS (somente ele) =====
const RECEITAWS_TOKEN = process.env.B2B_RECEITAWS_TOKEN || ""; // coloque via ENV (não exponha no front)
const RECEITAWS_BASE  = (process.env.B2B_RECEITAWS_BASE || "https://www.receitaws.com.br/v1").replace(/\/$/, "");
// "query" ( .../cnpj/XYZ?token=XXX ) ou "bearer" (Authorization: Bearer XXX)
const RECEITAWS_TOKEN_MODE = (process.env.B2B_RECEITAWS_TOKEN_MODE || "bearer").toLowerCase();

// Auto-approve quando ReceitaWS retornar empresa ATIVA
const AUTO_APPROVE =
  String(process.env.B2B_AUTO_APPROVE || "true").toLowerCase() === "true";

// Cache TTL para consultas de CNPJ (ms)
const CNPJ_CACHE_TTL_MS = Number(process.env.B2B_CNPJ_CACHE_TTL_MS || 1000 * 60 * 60 * 24); // 24h
/* ====================== */

// ======== Helpers de log / máscara ========
let __reqSeq = 0;
function newReqId() {
  __reqSeq = (__reqSeq + 1) % 1e9;
  return `${Date.now().toString(36)}-${__reqSeq}`;
}
function maskEmail(e = "") {
  const [u, d] = String(e).split("@");
  if (!d) return "***";
  const u2 = u.length <= 2 ? u[0] || "*" : u.slice(0, 2);
  return `${u2}***@${d}`;
}
function maskCNPJ(c = "") {
  const digits = (c || "").replace(/\D/g, "");
  if (digits.length < 4) return "***";
  return `************${digits.slice(-4)}`; // mostra só os 4 últimos
}
function logStart(req, label) {
  req.__t0 = process.hrtime.bigint();
  console.log(
    `[START] ${label} reqId=${req.__id} ip="${req.ip}" ua="${req.get("user-agent") || ""}" origin="${req.get("origin") || ""}" path="${req.originalUrl}"`
  );
}
function logEnd(req, label, extra = "") {
  try {
    const t1 = process.hrtime.bigint() - (req.__t0 || 0n);
    const ms = Number(t1) / 1e6;
    console.log(`[END]   ${label} reqId=${req.__id} elapsedMS=${ms.toFixed(1)} ${extra}`);
  } catch { console.log(`[END]   ${label} reqId=${req.__id}`); }
}

// ======== App setup ========
app.set("trust proxy", 1);
app.set("etag", false); // evita 304/ETag

app.use(rateLimit({ windowMs: 60_000, max: 60 }));
app.use(express.json());

// request logger (geral)
app.use((req, _res, next) => {
  req.__id = newReqId();
  console.log(
    `==> ${req.method} ${req.originalUrl} reqId=${req.__id} ip="${req.ip}" ua="${req.get("user-agent") || ""}" origin="${req.get("origin") || ""}"`
  );
  next();
});

// -------- CORS robusto (múltiplas origens + preview) --------
const ALLOWED_ORIGINS = ORIGINS_ENV.split(",").map(s => s.trim()).filter(Boolean);

function isAllowedOrigin(origin) {
  if (!origin) return true; // requests sem Origin (ex.: curl) – libera
  try {
    const { hostname } = new URL(origin);
    if (ALLOWED_ORIGINS.includes(origin)) return true; // lista explícita
    if (hostname.endsWith(".myshopify.com")) return true; // vitrine / preview
    if (hostname.endsWith(".shopifypreview.com")) return true; // preview
    if (hostname === "admin.shopify.com") return true; // editor do tema
  } catch {}
  return false;
}

app.use(
  cors({
    origin: (origin, cb) => {
      const ok = isAllowedOrigin(origin);
      if (!ok) console.warn(`[CORS] Blocked origin="${origin}"`);
      cb(null, ok);
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-B2B-Admin-Secret"],
    credentials: false,
  })
);

// responde preflight para tudo
app.options("*", (req, res) => {
  if (!isAllowedOrigin(req.headers.origin || "")) return res.sendStatus(403);
  res.set("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type, X-B2B-Admin-Secret");
  res.sendStatus(204);
});

/* ======== Helper REST Admin ======== */
const api = async (path, opts = {}) => {
  const url = `https://${SHOP}/admin/api/2024-07${path}`;
  console.log(`[API]   ${opts.method || "GET"} ${url}`);
  const res = await fetch(url, {
    method: opts.method || "GET",
    headers: {
      "X-Shopify-Access-Token": TOKEN,
      "Content-Type": "application/json",
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`[API]   ERROR ${res.status} on ${path} body=${text.slice(0, 400)}`);
    throw new Error(`${res.status} ${text}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
};

const onlyDigits = (s = "") => s.replace(/\D/g, "").slice(0, 14);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ======== Validador rápido de CNPJ (dígitos) ======== */
function isValidCNPJ(v) {
  const c = onlyDigits(v);
  if (c.length !== 14) return false;
  if (/^(\d)\1{13}$/.test(c)) return false; // todos iguais
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
const cnpjCache = new Map(); // key: cnpj -> { exp: ts, data: {...} }
function getFromCache(cnpj) {
  const k = onlyDigits(cnpj);
  const hit = cnpjCache.get(k);
  if (hit && hit.exp > Date.now()) {
    console.log(`[CACHE] HIT cnpj=${maskCNPJ(cnpj)}`);
    return hit.data;
  }
  if (hit) cnpjCache.delete(k);
  console.log(`[CACHE] MISS cnpj=${maskCNPJ(cnpj)}`);
  return null;
}
function saveToCache(cnpj, data) {
  cnpjCache.set(onlyDigits(cnpj), { exp: Date.now() + CNPJ_CACHE_TTL_MS, data });
  console.log(`[CACHE] SAVE cnpj=${maskCNPJ(cnpj)} ttlMS=${CNPJ_CACHE_TTL_MS}`);
}

/* ======== ReceitaWS (único provedor) ======== */
async function fetchCnpjReceitaWS(cnpj) {
  const num = onlyDigits(cnpj);
  let url = `${RECEITAWS_BASE}/cnpj/${num}`;
  const headers = {};
  if (RECEITAWS_TOKEN) {
    if (RECEITAWS_TOKEN_MODE === "bearer") {
      headers["Authorization"] = `Bearer ${RECEITAWS_TOKEN}`;
    } else {
      url += (url.includes("?") ? "&" : "?") + `token=${encodeURIComponent(RECEITAWS_TOKEN)}`;
    }
  }
  const cached = getFromCache(num);
  if (cached) return cached;

  console.log(`[CNPJ]  Fetching ReceitaWS cnpj=${maskCNPJ(num)} url=${RECEITAWS_BASE}/cnpj/<masked> mode=${RECEITAWS_TOKEN_MODE}`);
  const res = await fetch(url, { headers /* , signal: AbortSignal.timeout(12000) */ });
  const json = await res.json().catch(() => ({}));
  console.log(`[CNPJ]  ReceitaWS raw.status=${json?.status || "-"} situacao=${json?.situacao || json?.situacao_cadastral || "-"}`);

  // Formato clássico
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

  // Alguns planos não trazem "status"
  if (json && (json.nome || json.razao || json.razao_social)) {
    const result = {
      provider: "receitaws",
      found: true,
      active: String(json.situacao || json.situicao_cadastral || json.situacao_cadastral || "")
        .toUpperCase()
        .includes("ATIV"),
      razao: json.nome || json.razao || json.razao_social || "",
      fantasia: json.fantasia || json.nome_fantasia || "",
      abertura: json.abertura || json.data_abertura || "",
      uf: json.uf || (json.endereco && json.endereco.uf) || "",
      raw: json,
    };
    saveToCache(num, result);
    return result;
  }

  const notFound = {
    provider: "receitaws",
    found: false,
    active: false,
    err: (json && (json.message || json.error || json.status)) || "not_found",
    raw: json,
  };
  console.warn(`[CNPJ]  NOT FOUND/INACTIVE cnpj=${maskCNPJ(num)} err="${notFound.err}"`);
  saveToCache(num, notFound);
  return notFound;
}

/* ======== Helpers de cliente/metafield/tags ======== */
async function findCustomerByEmail(email) {
  console.log(`[SHOP]  findCustomerByEmail email=${maskEmail(email)}`);
  const q = encodeURIComponent(`email:${email}`);
  const cs = await api(`/customers/search.json?query=${q}`);
  const found = (cs.customers || [])[0] || null;
  console.log(`[SHOP]  findCustomerByEmail -> ${found ? "FOUND id="+found.id : "NOT FOUND"}`);
  return found;
}

// Aguarda o cliente “aparecer” após o cadastro na vitrine
async function waitForCustomerByEmail(email, retries = 8, delayMs = 800) {
  console.log(`[SHOP]  waitForCustomerByEmail email=${maskEmail(email)} retries=${retries} delayMS=${delayMs}`);
  for (let i = 0; i < retries; i++) {
    const c = await findCustomerByEmail(email);
    if (c) {
      console.log(`[SHOP]  waitForCustomerByEmail FOUND on attempt=${i+1}`);
      return c;
    }
    await sleep(delayMs);
  }
  console.warn(`[SHOP]  waitForCustomerByEmail TIMED OUT email=${maskEmail(email)}`);
  return null;
}

async function setCustomerTags(customerId, tagsArray) {
  const tags = [...new Set(tagsArray.map((t) => t.trim()).filter(Boolean))].join(", ");
  console.log(`[SHOP]  setCustomerTags id=${customerId} tags="${tags}"`);
  await api(`/customers/${customerId}.json`, {
    method: "PUT",
    body: { customer: { id: customerId, tags } },
  });
}

async function upsertCustomerMetafield(
  customerId,
  key,
  value,
  type = "single_line_text_field",
  namespace = "custom"
) {
  console.log(`[SHOP]  upsertCustomerMetafield id=${customerId} ${namespace}.${key}=${JSON.stringify(value)} type=${type}`);
  const metas = await api(`/customers/${customerId}/metafields.json?namespace=${namespace}`);
  const existing = (metas.metafields || []).find(
    (m) => String(m.key).toLowerCase() === String(key).toLowerCase()
  );

  if (existing) {
    await api(`/metafields/${existing.id}.json`, {
      method: "PUT",
      body: { metafield: { id: existing.id, value, type } },
    });
    console.log(`[SHOP]  metafield UPDATED id=${existing.id}`);
  } else {
    const created = await api(`/metafields.json`, {
      method: "POST",
      body: {
        metafield: {
          namespace,
          key,
          owner_id: customerId,
          owner_resource: "customer",
          type,
          value,
        },
      },
    });
    console.log(`[SHOP]  metafield CREATED key=${key} respId=${created?.metafield?.id || "-"}`);
  }
}

/* ======== Helper: validar no ReceitaWS e aprovar se ATIVA ======== */
async function validateAndMaybeApprove(customer, cnpjNum) {
  console.log(`[FLOW]  validateAndMaybeApprove customerId=${customer.id} cnpj=${maskCNPJ(cnpjNum)}`);
  const num = onlyDigits(cnpjNum);
  const result = await fetchCnpjReceitaWS(num);
  console.log(`[FLOW]  ReceitaWS -> found=${result.found} active=${result.active} razao="${result.razao || ""}"`);

  // Metacampos informativos
  await upsertCustomerMetafield(customer.id, "cnpj_exists", String(!!result.found), "boolean");
  await upsertCustomerMetafield(
    customer.id,
    "cnpj_situacao",
    result.active ? "ATIVA" : "INATIVA"
  );
  if (result.razao) await upsertCustomerMetafield(customer.id, "cnpj_razao", result.razao);
  if (result.fantasia) await upsertCustomerMetafield(customer.id, "cnpj_fantasia", result.fantasia);
  await upsertCustomerMetafield(
    customer.id,
    "cnpj_checked_at",
    new Date().toISOString(),
    "date_time"
  );

  // Auto-approve se encontrado e ATIVA
  let approved = false;
  if (AUTO_APPROVE && result.found && result.active) {
    const currentTags = (customer.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
    if (!currentTags.includes("b2b-approved")) currentTags.push("b2b-approved");
    const tags = currentTags.filter((t) => t !== "b2b-pending");
    await setCustomerTags(customer.id, tags);
    await upsertCustomerMetafield(customer.id, "cnpj_status", "approved");
    await upsertCustomerMetafield(customer.id, "approved", "true", "boolean");
    approved = true;
    console.log(`[FLOW]  AUTO-APPROVED customerId=${customer.id} -> tags="${tags}"`);
  } else {
    console.log(`[FLOW]  NOT APPROVED (found=${result.found} active=${result.active}) customerId=${customer.id}`);
  }

  return { approved, result };
}

/* ======== Guard das rotas admin ======== */
function hasSecret(req) {
  const header = req.header("X-B2B-Admin-Secret");
  const qp = req.query.secret;
  return ADMIN_SECRET && (header === ADMIN_SECRET || qp === ADMIN_SECRET);
}
function guard(req, res) {
  if (!hasSecret(req)) {
    console.warn(`[ADMIN] Unauthorized attempt reqId=${req.__id}`);
    res.status(401).json({ ok: false, error: "unauthorized" });
    return false;
  }
  return true;
}

/* ======== Public: validação de login ======== */
app.get("/validate-login", async (req, res) => {
  logStart(req, "GET /validate-login");
  res.set({
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Surrogate-Control": "no-store",
    "Vary": "Origin",
  });

  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    const cnpj = onlyDigits(String(req.query.cnpj || ""));
    console.log(`[LOGIN] email=${maskEmail(email)} cnpj=${maskCNPJ(cnpj)}`);

    if (!email || cnpj.length !== 14) {
      console.warn("[LOGIN] invalid params");
      logEnd(req, "GET /validate-login", '-> 400');
      return res.status(400).json({ ok: false, exists: false });
    }

    const customer = await findCustomerByEmail(email);
    if (!customer) {
      console.log("[LOGIN] customer not found");
      logEnd(req, "GET /validate-login", '-> 200 exists=false');
      return res.json({ ok: true, exists: false });
    }

    const metas = await api(`/customers/${customer.id}/metafields.json?namespace=custom`);
    const mfCnpjField = (metas.metafields || []).find(
      (m) => m.key?.toLowerCase() === "cnpj" || m.key?.toLowerCase() === "cjnpj"
    );
    const mfStatusField = (metas.metafields || []).find(
      (m) => m.key?.toLowerCase() === "cnpj_status"
    );
    const mfApproved = (metas.metafields || []).find(
      (m) => m.key?.toLowerCase() === "approved"
    );

    const mfCnpj = mfCnpjField ? String(mfCnpjField.value || "") : "";
    const cnpj_status = (mfStatusField ? String(mfStatusField.value || "") : "").toLowerCase();
    const cnpj_match = onlyDigits(mfCnpj) === cnpj;

    const hasApprovedTag = (customer.tags || "")
      .split(",")
      .map((t) => t.trim())
      .includes("b2b-approved");

    // aprovado se (tag + status) OU approved=true
    const approved = (hasApprovedTag && cnpj_status === "approved") || String(mfApproved?.value || "").toLowerCase() === "true";

    console.log(`[LOGIN] exists=true cnpj_match=${cnpj_match} cnpj_status=${cnpj_status} tagApproved=${hasApprovedTag} mf.approved=${mfApproved?.value} -> approved=${approved}`);

    logEnd(req, "GET /validate-login", '-> 200');
    res.json({ ok: true, exists: true, cnpj_match, approved, cnpj_status });
  } catch (e) {
    console.error("validate-login error:", e);
    logEnd(req, "GET /validate-login", '-> 500');
    res.status(500).json({ ok: false, exists: false });
  }
});

/* ======== Public: registrar CNPJ (valida e pode aprovar) ======== */
app.post("/register-cnpj", async (req, res) => {
  logStart(req, "POST /register-cnpj");
  res.set({
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Origin",
  });

  try {
    const { email, cnpj } = req.body || {};
    const mail = String(email || "").trim().toLowerCase();
    const num = onlyDigits(cnpj || "");
    console.log(`[REG]   payload email=${maskEmail(mail)} cnpj=${maskCNPJ(num)}`);

    if (!mail || num.length !== 14 || !isValidCNPJ(num)) {
      console.warn("[REG]   invalid_params");
      logEnd(req, "POST /register-cnpj", '-> 400');
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    // Espera o cliente existir (o cadastro acabou de acontecer na vitrine)
    const customer = await waitForCustomerByEmail(mail, 10, 700);
    if (!customer) {
      console.warn("[REG]   customer_not_found after wait");
      logEnd(req, "POST /register-cnpj", '-> 404');
      return res.status(404).json({ ok: false, error: "customer_not_found" });
    }

    // Grava metafields básicos
    await upsertCustomerMetafield(customer.id, "cnpj", num);
    await upsertCustomerMetafield(customer.id, "cnpj_status", "pending");
    await upsertCustomerMetafield(customer.id, "approved", "false", "boolean");

    // Garante tag de pendência
    const tags = (customer.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
    if (!tags.includes("b2b-pending")) {
      tags.push("b2b-pending");
      await setCustomerTags(customer.id, tags);
      console.log(`[REG]   tag "b2b-pending" set`);
    }

    // Valida no ReceitaWS e (se ATIVA) aprova automaticamente
    const { approved, result } = await validateAndMaybeApprove(customer, num);

    console.log(`[REG]   result found=${result.found} active=${result.active} autoApproved=${approved}`);
    logEnd(req, "POST /register-cnpj", '-> 200');

    res.json({
      ok: true,
      validated: true,
      autoApproved: approved,
      provider: result.provider,
      found: result.found,
      active: result.active,
      razao: result.razao || null,
      fantasia: result.fantasia || null,
    });
  } catch (e) {
    console.error("register-cnpj error:", e);
    logEnd(req, "POST /register-cnpj", '-> 500');
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

/* ======== Public: validar CNPJ isoladamente (também aprova se ATIVA) ======== */
app.post("/validate-cnpj", async (req, res) => {
  logStart(req, "POST /validate-cnpj");
  res.set({
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Origin",
  });

  try {
    const { email, cnpj } = req.body || {};
    const mail = String(email || "").trim().toLowerCase();
    const num = onlyDigits(cnpj || "");
    console.log(`[VCNPJ] payload email=${maskEmail(mail)} cnpj=${maskCNPJ(num)}`);

    if (!mail || num.length !== 14 || !isValidCNPJ(num)) {
      console.warn("[VCNPJ] invalid_params");
      logEnd(req, "POST /validate-cnpj", '-> 400');
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    const customer = await findCustomerByEmail(mail);
    if (!customer) {
      console.warn("[VCNPJ] customer_not_found");
      logEnd(req, "POST /validate-cnpj", '-> 404');
      return res.status(404).json({ ok: false, error: "customer_not_found" });
    }

    const { approved, result } = await validateAndMaybeApprove(customer, num);
    console.log(`[VCNPJ] found=${result.found} active=${result.active} autoApproved=${approved}`);
    logEnd(req, "POST /validate-cnpj", '-> 200');

    res.json({
      ok: true,
      autoApproved: approved,
      provider: result.provider,
      found: result.found,
      active: result.active,
      razao: result.razao || null,
      fantasia: result.fantasia || null,
    });
  } catch (e) {
    console.error("validate-cnpj error:", e);
    logEnd(req, "POST /validate-cnpj", '-> 500');
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

/* ======== Public: pré-validação de CNPJ (NÃO toca Shopify) ======== */
      app.post("/precheck-cnpj", async (req, res) => {
        const label = "POST /precheck-cnpj";
        try {
          req.__id = req.__id || `${Date.now()}`;
          console.log(`[START] ${label} reqId=${req.__id}`);
          res.set({
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
            "Vary": "Origin",
          });

          const { cnpj } = req.body || {};
          const num = onlyDigits(cnpj || "");
          console.log(`[PCHECK] cnpj=${num ? "************" + num.slice(-4) : "(empty)"}`);

          // dígitos/estrutura inválidos → já retorna como não encontrado/inativo
          if (!num || num.length !== 14 || !isValidCNPJ(num)) {
            console.warn("[PCHECK] invalid_digits");
            return res.json({ ok: true, found: false, active: false, reason: "invalid_digits" });
          }

          // consulta ReceitaWS, sem mexer em Shopify
          const result = await fetchCnpjReceitaWS(num);
          console.log(`[PCHECK] found=${result.found} active=${result.active} razao="${result.razao || ""}"`);

          return res.json({
            ok: true,
            found: !!result.found,
            active: !!result.active,
            razao: result.razao || null,
            fantasia: result.fantasia || null,
          });
        } catch (e) {
          console.error("precheck-cnpj error:", e);
          return res.status(500).json({ ok: false, error: "internal_error" });
        }
      });

/* ======== Admin: aprovar / reprovar ======== */
app.post("/admin/approve", async (req, res) => {
  logStart(req, "POST /admin/approve");
  if (!guard(req, res)) { logEnd(req, "POST /admin/approve", '-> 401'); return; }
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    console.log(`[ADMIN] approve email=${maskEmail(email)}`);
    if (!email) { logEnd(req, "POST /admin/approve", '-> 400'); return res.status(400).json({ ok: false, error: "missing email" }); }

    const c = await findCustomerByEmail(email);
    if (!c) { logEnd(req, "POST /admin/approve", '-> 200 notfound'); return res.json({ ok: true, found: false }); }

    const currentTags = (c.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
    if (!currentTags.includes("b2b-approved")) currentTags.push("b2b-approved");
    const tags = currentTags.filter((t) => t !== "b2b-pending");

    await setCustomerTags(c.id, tags);
    await upsertCustomerMetafield(c.id, "cnpj_status", "approved");
    await upsertCustomerMetafield(c.id, "approved", "true", "boolean");

    logEnd(req, "POST /admin/approve", '-> 200');
    res.json({ ok: true, found: true, tags, cnpj_status: "approved" });
  } catch (e) {
    console.error("approve error:", e);
    logEnd(req, "POST /admin/approve", '-> 500');
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});
app.get("/admin/approve", (req, res) => app._router.handle({ ...req, method: "POST" }, res));

app.post("/admin/reject", async (req, res) => {
  logStart(req, "POST /admin/reject");
  if (!guard(req, res)) { logEnd(req, "POST /admin/reject", '-> 401'); return; }
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    console.log(`[ADMIN] reject  email=${maskEmail(email)}`);
    if (!email) { logEnd(req, "POST /admin/reject", '-> 400'); return res.status(400).json({ ok: false, error: "missing email" }); }

    const c = await findCustomerByEmail(email);
    if (!c) { logEnd(req, "POST /admin/reject", '-> 200 notfound'); return res.json({ ok: true, found: false }); }

    const currentTags = (c.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
    const tags = currentTags.filter((t) => t !== "b2b-approved");

    await setCustomerTags(c.id, tags);
    await upsertCustomerMetafield(c.id, "cnpj_status", "rejected");
    await upsertCustomerMetafield(c.id, "approved", "false", "boolean");

    logEnd(req, "POST /admin/reject", '-> 200');
    res.json({ ok: true, found: true, tags, cnpj_status: "rejected" });
  } catch (e) {
    console.error("reject error:", e);
    logEnd(req, "POST /admin/reject", '-> 500');
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});
app.get("/admin/reject", (req, res) => app._router.handle({ ...req, method: "POST" }, res));

/* ======== Root ======== */
app.get("/", (req, res) => {
  logStart(req, "GET /");
  logEnd(req, "GET /", '-> 200');
  res.send("ok");
});

/* ======== Start ======== */
app.listen(process.env.PORT || 3000, () => console.log("B2B API up"));
