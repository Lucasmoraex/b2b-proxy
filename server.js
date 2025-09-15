import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();

/* ======== ENVs ======== */
// Shop/admin continuam no domínio myshopify (NÃO troque)
const SHOP   = process.env.SHOPIFY_SHOP || "elementsparaempresas.myshopify.com";
const TOKEN  = process.env.SHOPIFY_ADMIN_TOKEN || "";

// Agora aceitamos várias origens, separadas por vírgula.
// Ex.: B2B_ALLOWED_ORIGIN="https://corporativo.elements.com.br,https://elementsparaempresas.myshopify.com"
const ORIGINS_ENV = process.env.B2B_ALLOWED_ORIGIN
  || "https://corporativo.elements.com.br,https://elementsparaempresas.myshopify.com";

const ADMIN_SECRET = process.env.B2B_ADMIN_SECRET || ""; // secret para rotas /admin/*

// ReceitaWS + fallback BrasilAPI
const RECEITAWS_TOKEN = process.env.B2B_RECEITAWS_TOKEN || ""; // <<< coloque seu token aqui via ENV
const RECEITAWS_BASE  = process.env.B2B_RECEITAWS_BASE || "https://www.receitaws.com.br/v1"; // v1 por compatibilidade
// Modo de autenticação: "query" (ex: .../cnpj/XYZ?token=XXX) ou "bearer" (Authorization: Bearer XXX)
const RECEITAWS_TOKEN_MODE = (process.env.B2B_RECEITAWS_TOKEN_MODE || "query").toLowerCase();
// Ordem de provedores: "receitaws,brasilapi" ou o que preferir
const CNPJ_PROVIDER_ORDER = (process.env.B2B_CNPJ_PROVIDER_ORDER || "receitaws,brasilapi")
  .split(",").map(s => s.trim()).filter(Boolean);
// Cache TTL para consultas de CNPJ (ms)
const CNPJ_CACHE_TTL_MS = Number(process.env.B2B_CNPJ_CACHE_TTL_MS || 1000 * 60 * 60 * 24); // 24h
/* ====================== */

app.set("trust proxy", 1);
app.set("etag", false); // evita 304/ETag

app.use(rateLimit({ windowMs: 60_000, max: 60 }));
app.use(express.json());

// -------- CORS robusto (múltiplas origens + preview) --------
const ALLOWED_ORIGINS = ORIGINS_ENV.split(",")
  .map(s => s.trim())
  .filter(Boolean);

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
    origin: (origin, cb) => cb(null, isAllowedOrigin(origin)),
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
  const res = await fetch(`https://${SHOP}/admin/api/2024-07${path}`, {
    method: opts.method || "GET",
    headers: {
      "X-Shopify-Access-Token": TOKEN,
      "Content-Type": "application/json",
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) {
    console.error("REST API error:", res.status, text.slice(0, 400));
    throw new Error(`${res.status} ${text}`);
  }
  try { return JSON.parse(text); } catch { return {}; }
};

const onlyDigits = (s = "") => s.replace(/\D/g, "").slice(0, 14);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ======== Validador rápido de CNPJ ======== */
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
    return (mod < 2) ? 0 : 11 - mod;
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
  if (hit && hit.exp > Date.now()) return hit.data;
  if (hit) cnpjCache.delete(k);
  return null;
}
function saveToCache(cnpj, data) {
  cnpjCache.set(onlyDigits(cnpj), { exp: Date.now() + CNPJ_CACHE_TTL_MS, data });
}

/* ======== Fetchers de provedores ======== */
async function fetchCnpjReceitaWS(cnpj) {
  const num = onlyDigits(cnpj);
  let url = `${RECEITAWS_BASE.replace(/\/$/, "")}/cnpj/${num}`;
  const headers = {};
  if (RECEITAWS_TOKEN) {
    if (RECEITAWS_TOKEN_MODE === "bearer") {
      headers["Authorization"] = `Bearer ${RECEITAWS_TOKEN}`;
    } else {
      url += (url.includes("?") ? "&" : "?") + `token=${encodeURIComponent(RECEITAWS_TOKEN)}`;
    }
  }
  const res = await fetch(url, { headers, timeout: 12_000 });
  const json = await res.json().catch(() => ({}));

  // Formatos comuns vistos do ReceitaWS
  // { status: "OK"|"ERROR", message?: string, nome, fantasia, situacao, abertura, uf, ... }
  if (json && json.status === "OK") {
    return {
      provider: "receitaws",
      found: true,
      active: String(json.situacao || "").toUpperCase() === "ATIVA",
      razao: json.nome || "",
      fantasia: json.fantasia || "",
      abertura: json.abertura || "",
      uf: json.uf || "",
      raw: json,
    };
  }

  // Alguns planos retornam sem "status", mas com campos diretos
  if (json && (json.nome || json.razao || json.razao_social)) {
    return {
      provider: "receitaws",
      found: true,
      active: String(json.situacao || json.situacao_cadastral || "").toUpperCase().includes("ATIV"),
      razao: json.nome || json.razao || json.razao_social || "",
      fantasia: json.fantasia || json.nome_fantasia || "",
      abertura: json.abertura || json.data_abertura || "",
      uf: json.uf || (json.endereco && json.endereco.uf) || "",
      raw: json,
    };
  }

  // status ERROR ou não encontrado
  return {
    provider: "receitaws",
    found: false,
    active: false,
    err: json && (json.message || json.error || json.status) || "not_found",
    raw: json,
  };
}

async function fetchCnpjBrasilAPI(cnpj) {
  const num = onlyDigits(cnpj);
  const url = `https://brasilapi.com.br/api/cnpj/v1/${num}`;
  const res = await fetch(url, { timeout: 12_000 });
  const json = await res.json().catch(() => ({}));
  if (json && (json.razao_social || json.nome_fantasia)) {
    return {
      provider: "brasilapi",
      found: true,
      active: String(json.situacao_cadastral || "").toUpperCase().includes("ATIV"),
      razao: json.razao_social || "",
      fantasia: json.nome_fantasia || "",
      abertura: json.data_abertura || "",
      uf: (json.endereco && json.endereco.uf) || json.uf || "",
      raw: json,
    };
  }
  return {
    provider: "brasilapi",
    found: false,
    active: false,
    err: json && (json.message || json.type) || "not_found",
    raw: json,
  };
}

async function resolveCNPJ(cnpj) {
  const num = onlyDigits(cnpj);
  const cached = getFromCache(num);
  if (cached) return cached;

  let result = { provider: null, found: false, active: false };
  for (const prov of CNPJ_PROVIDER_ORDER) {
    try {
      if (prov === "receitaws") result = await fetchCnpjReceitaWS(num);
      else if (prov === "brasilapi") result = await fetchCnpjBrasilAPI(num);
      if (result && result.found) break;
    } catch (e) {
      console.warn(`Provider ${prov} error`, e.message);
    }
  }

  // guarda no cache mesmo que não encontrado para evitar martelar provedores
  saveToCache(num, result);
  return result;
}

/* ======== Helpers de cliente/metafield/tags ======== */
async function findCustomerByEmail(email) {
  const q = encodeURIComponent(`email:${email}`);
  const cs = await api(`/customers/search.json?query=${q}`);
  return (cs.customers || [])[0] || null;
}

// Aguarda o cliente “aparecer” após o cadastro na vitrine
async function waitForCustomerByEmail(email, retries = 8, delayMs = 800) {
  for (let i = 0; i < retries; i++) {
    const c = await findCustomerByEmail(email);
    if (c) return c;
    await sleep(delayMs);
  }
  return null;
}

async function setCustomerTags(customerId, tagsArray) {
  const tags = [...new Set(tagsArray.map((t) => t.trim()).filter(Boolean))].join(", ");
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
  const metas = await api(`/customers/${customerId}/metafields.json?namespace=${namespace}`);
  const existing = (metas.metafields || []).find(
    (m) => String(m.key).toLowerCase() === String(key).toLowerCase()
  );

  if (existing) {
    await api(`/metafields/${existing.id}.json`, {
      method: "PUT",
      body: { metafield: { id: existing.id, value, type } },
    });
  } else {
    await api(`/metafields.json`, {
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
  }
}

/* ======== Guard das rotas admin ======== */
function hasSecret(req) {
  const header = req.header("X-B2B-Admin-Secret");
  const qp = req.query.secret;
  return ADMIN_SECRET && (header === ADMIN_SECRET || qp === ADMIN_SECRET);
}
function guard(req, res) {
  if (!hasSecret(req)) {
    res.status(401).json({ ok: false, error: "unauthorized" });
    return false;
  }
  return true;
}

/* ======== Public: validação de login ======== */
app.get("/validate-login", async (req, res) => {
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

    if (!email || cnpj.length !== 14)
      return res.status(400).json({ ok: false, exists: false });

    const customer = await findCustomerByEmail(email);
    if (!customer) return res.json({ ok: true, exists: false });

    const metas = await api(`/customers/${customer.id}/metafields.json?namespace=custom`);
    const mfCnpjField = (metas.metafields || []).find(
      (m) => m.key?.toLowerCase() === "cnpj" || m.key?.toLowerCase() === "cjnpj"
    );
    const mfStatusField = (metas.metafields || []).find(
      (m) => m.key?.toLowerCase() === "cnpj_status"
    );

    const mfCnpj = mfCnpjField ? String(mfCnpjField.value || "") : "";
    const cnpj_status = (mfStatusField ? String(mfStatusField.value || "") : "").toLowerCase();
    const cnpj_match = onlyDigits(mfCnpj) === cnpj;

    const hasApprovedTag = (customer.tags || "")
      .split(",")
      .map((t) => t.trim())
      .includes("b2b-approved");
    const approved = hasApprovedTag && cnpj_status === "approved";

    res.json({ ok: true, exists: true, cnpj_match, approved, cnpj_status });
  } catch (e) {
    console.error("validate-login error:", e);
    res.status(500).json({ ok: false, exists: false });
  }
});

/* ======== Public: registrar CNPJ ======== */
app.post("/register-cnpj", async (req, res) => {
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

    if (!mail || num.length !== 14 || !isValidCNPJ(num)) {
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    // Espera o cliente existir (o cadastro acabou de acontecer na vitrine)
    const customer = await waitForCustomerByEmail(mail, 10, 700);
    if (!customer) {
      return res.status(404).json({ ok: false, error: "customer_not_found" });
    }

    // Grava metafields básicos
    await upsertCustomerMetafield(customer.id, "cnpj", num);
    await upsertCustomerMetafield(customer.id, "cnpj_status", "pending");

    // (Opcional) tag de pendência
    const tags = (customer.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
    if (!tags.includes("b2b-pending")) {
      tags.push("b2b-pending");
      await setCustomerTags(customer.id, tags);
    }

    res.json({ ok: true });
  } catch (e) {
    console.error("register-cnpj error:", e);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

/* ======== NEW: validar CNPJ via ReceitaWS (com fallback BrasilAPI) ======== */
app.post("/validate-cnpj", async (req, res) => {
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

    if (!mail || num.length !== 14 || !isValidCNPJ(num)) {
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    const customer = await findCustomerByEmail(mail);
    if (!customer) return res.status(404).json({ ok: false, error: "customer_not_found" });

    const result = await resolveCNPJ(num);

    // Atualiza metafields informativos (não aprova automaticamente)
    await upsertCustomerMetafield(customer.id, "cnpj_exists", String(!!result.found), "boolean");
    await upsertCustomerMetafield(customer.id, "cnpj_situacao", result.active ? "ATIVA" : "INATIVA");
    if (result.razao)    await upsertCustomerMetafield(customer.id, "cnpj_razao", result.razao);
    if (result.fantasia) await upsertCustomerMetafield(customer.id, "cnpj_fantasia", result.fantasia);

    res.json({ ok: true, provider: result.provider, found: result.found, active: result.active, razao: result.razao || null, fantasia: result.fantasia || null });
  } catch (e) {
    console.error("validate-cnpj error:", e);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

/* ======== Admin: aprovar / reprovar ======== */
app.post("/admin/approve", async (req, res) => {
  if (!guard(req, res)) return;
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: "missing email" });

    const c = await findCustomerByEmail(email);
    if (!c) return res.json({ ok: true, found: false });

    const currentTags = (c.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
    if (!currentTags.includes("b2b-approved")) currentTags.push("b2b-approved");
    const tags = currentTags.filter((t) => t !== "b2b-pending");

    await setCustomerTags(c.id, tags);
    await upsertCustomerMetafield(c.id, "cnpj_status", "approved");

    res.json({ ok: true, found: true, tags, cnpj_status: "approved" });
  } catch (e) {
    console.error("approve error:", e);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});
app.get("/admin/approve", (req, res) => app._router.handle({ ...req, method: "POST" }, res));

app.post("/admin/reject", async (req, res) => {
  if (!guard(req, res)) return;
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: "missing email" });

    const c = await findCustomerByEmail(email);
    if (!c) return res.json({ ok: true, found: false });

    const currentTags = (c.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
    const tags = currentTags.filter((t) => t !== "b2b-approved");

    await setCustomerTags(c.id, tags);
    await upsertCustomerMetafield(c.id, "cnpj_status", "rejected");

    res.json({ ok: true, found: true, tags, cnpj_status: "rejected" });
  } catch (e) {
    console.error("reject error:", e);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});
app.get("/admin/reject", (req, res) => app._router.handle({ ...req, method: "POST" }, res));

/* ======== Root ======== */
app.get("/", (_, res) => res.send("ok"));

/* ======== Start ======== */
app.listen(process.env.PORT || 3000, () => console.log("B2B API up"));
