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

const AUTO_APPROVE = String(process.env.B2B_AUTO_APPROVE || "true").toLowerCase() === "true";
const CNPJ_CACHE_TTL_MS = Number(process.env.B2B_CNPJ_CACHE_TTL_MS || 1000 * 60 * 60 * 24);
/* ====================== */

app.set("trust proxy", 1);
app.set("etag", false);

app.use(rateLimit({ windowMs: 60_000, max: 60 }));
app.use(express.json());

// -------- CORS --------
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

app.use(
  cors({
    origin: (origin, cb) => cb(null, isAllowedOrigin(origin)),
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-B2B-Admin-Secret"],
    credentials: false,
  })
);

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

/* ======== Validador rápido de CNPJ (apenas estrutura) ======== */
function isValidCNPJStructure(v) {
  return onlyDigits(v).length === 14;
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

/* ======== ReceitaWS ======== */
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

  const res = await fetch(url, { headers });
  const json = await res.json().catch(() => ({}));

  if (json && json.status === "OK") {
    const out = {
      provider: "receitaws",
      found: true,
      active: String(json.situacao || "").toUpperCase() === "ATIVA",
      razao: json.nome || "",
      fantasia: json.fantasia || "",
      abertura: json.abertura || "",
      uf: json.uf || "",
      raw: json,
    };
    saveToCache(num, out);
    return out;
  }

  if (json && (json.nome || json.razao || json.razao_social)) {
    const out = {
      provider: "receitaws",
      found: true,
      active: String(json.situacao || json.situacao_cadastral || "").toUpperCase().includes("ATIV"),
      razao: json.nome || json.razao || json.razao_social || "",
      fantasia: json.fantasia || json.nome_fantasia || "",
      abertura: json.abertura || json.data_abertura || "",
      uf: json.uf || (json.endereco && json.endereco.uf) || "",
      raw: json,
    };
    saveToCache(num, out);
    return out;
  }

  const notFound = {
    provider: "receitaws",
    found: false,
    active: false,
    err: (json && (json.message || json.error || json.status)) || "not_found",
    raw: json,
  };
  saveToCache(num, notFound);
  return notFound;
}

/* ======== Helpers de cliente/metafield/tags ======== */
async function findCustomerByEmail(email) {
  const q = encodeURIComponent(`email:${email}`);
  const cs = await api(`/customers/search.json?query=${q}`);
  return (cs.customers || [])[0] || null;
}

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

/* === Metafield type resolver (evita 422) === */
const defCache = new Map(); // key: `${namespace}|customer` -> array of defs

async function getCustomerDefs(namespace = "custom") {
  const k = `${namespace}|customer`;
  if (defCache.has(k)) return defCache.get(k);
  const defs = await api(`/metafield_definitions.json?owner_resource=customer&namespace=${encodeURIComponent(namespace)}`);
  const list = defs.metafield_definitions || [];
  defCache.set(k, list);
  return list;
}

async function resolveTypeForKey(key, fallback = "single_line_text_field", namespace = "custom") {
  const defs = await getCustomerDefs(namespace);
  const d = defs.find(m => (m.key || "").toLowerCase() === key.toLowerCase());
  return d ? d.type : fallback;
}

function coerceValueForType(type, value) {
  switch ((type || "").toLowerCase()) {
    case "number_integer":
      return String(value).replace(/[^\d-]/g, "");
    case "number_decimal":
      return String(value).replace(/[^0-9.-]/g, "");
    case "boolean":
      return String(value === true || value === "true" || value === 1);
    case "date_time":
      return new Date(value).toISOString();
    default:
      return String(value ?? "");
  }
}

async function upsertCustomerMetafield(
  customerId,
  key,
  value,
  typeHint = "single_line_text_field",
  namespace = "custom"
) {
  const metas = await api(`/customers/${customerId}/metafields.json?namespace=${namespace}`);
  const existing = (metas.metafields || []).find(
    (m) => String(m.key).toLowerCase() === String(key).toLowerCase()
  );

  if (existing) {
    // atualizar sem enviar "type" (deixa o existente vencer)
    const val = coerceValueForType(existing.type, value);
    await api(`/metafields/${existing.id}.json`, {
      method: "PUT",
      body: { metafield: { id: existing.id, value: val } },
    });
    return existing.id;
  } else {
    const finalType = await resolveTypeForKey(key, typeHint, namespace);
    const val = coerceValueForType(finalType, value);
    await api(`/metafields.json`, {
      method: "POST",
      body: {
        metafield: {
          namespace,
          key,
          owner_id: customerId,
          owner_resource: "customer",
          type: finalType,
          value: val,
        },
      },
    });
  }
}

/* ======== Helper: validar no ReceitaWS e aprovar se ATIVA ======== */
async function validateAndMaybeApprove(customer, cnpjNum) {
  const num = onlyDigits(cnpjNum);
  const result = await fetchCnpjReceitaWS(num);

  await upsertCustomerMetafield(customer.id, "cnpj_exists", !!result.found, "boolean");
  await upsertCustomerMetafield(customer.id, "cnpj_situacao", result.active ? "ATIVA" : "INATIVA");
  if (result.razao)    await upsertCustomerMetafield(customer.id, "cnpj_razao", result.razao);
  if (result.fantasia) await upsertCustomerMetafield(customer.id, "cnpj_fantasia", result.fantasia);
  await upsertCustomerMetafield(customer.id, "cnpj_checked_at", new Date().toISOString(), "date_time");

  let approved = false;
  if (AUTO_APPROVE && result.found && result.active) {
    const currentTags = (customer.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
    if (!currentTags.includes("b2b-approved")) currentTags.push("b2b-approved");
    const tags = currentTags.filter((t) => t !== "b2b-pending");
    await setCustomerTags(customer.id, tags);
    await upsertCustomerMetafield(customer.id, "cnpj_status", "approved");
    approved = true;
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

/* ======== Public: registrar CNPJ (grava sempre e valida; sem bloquear por dígito verif.) ======== */
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

    if (!mail || !isValidCNPJStructure(num)) {
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    const customer = await waitForCustomerByEmail(mail, 12, 800);
    if (!customer) {
      return res.status(404).json({ ok: false, error: "customer_not_found" });
    }

    // Grava base SEM forçar tipo (usa definitions/existente)
    await upsertCustomerMetafield(customer.id, "cnpj", num);
    await upsertCustomerMetafield(customer.id, "cnpj_status", "pending");

    // Tag pendente
    const tags = (customer.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
    if (!tags.includes("b2b-pending")) {
      tags.push("b2b-pending");
      await setCustomerTags(customer.id, tags);
    }

    // Valida e auto-aprova se ATIVA
    const { approved, result } = await validateAndMaybeApprove(customer, num);

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
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

/* ======== Public: validar CNPJ isoladamente ======== */
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

    if (!mail || !isValidCNPJStructure(num)) {
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    const customer = await findCustomerByEmail(mail);
    if (!customer) return res.status(404).json({ ok: false, error: "customer_not_found" });

    const { approved, result } = await validateAndMaybeApprove(customer, num);

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
