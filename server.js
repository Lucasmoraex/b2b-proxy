import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();

/* ======== ENVs ======== */
const SHOP   = process.env.SHOPIFY_SHOP || "elementsparaempresas.myshopify.com";
const TOKEN  = process.env.SHOPIFY_ADMIN_TOKEN || "";
const ORIGIN = process.env.B2B_ALLOWED_ORIGIN || "https://elementsparaempresas.myshopify.com";
const ADMIN_SECRET = process.env.B2B_ADMIN_SECRET || ""; // secret para rotas /admin/*
/* ====================== */

app.set("trust proxy", 1);
// evita 304 de ETag para respostas (especialmente /validate-login)
app.set("etag", false);

app.use(rateLimit({ windowMs: 60_000, max: 60 }));
app.use(cors({ origin: ORIGIN, methods: ["GET", "POST", "OPTIONS"] }));
app.use(express.json());
app.options("*", cors());

/* ======== Helper REST Admin ======== */
const api = async (path, opts = {}) => {
  const res = await fetch(`https://${SHOP}/admin/api/2024-07${path}`, {
    method: opts.method || "GET",
    headers: {
      "X-Shopify-Access-Token": TOKEN,
      "Content-Type": "application/json"
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  const text = await res.text();
  if (!res.ok) {
    console.error("REST API error:", res.status, text.slice(0, 400));
    throw new Error(`${res.status} ${text}`);
  }
  try { return JSON.parse(text); } catch { return {}; }
};

const onlyDigits = (s = "") => s.replace(/\D/g, "").slice(0, 14);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/* ======== Helpers de cliente/metafield/tags ======== */
async function findCustomerByEmail(email) {
  const q = encodeURIComponent(`email:${email}`);
  const cs = await api(`/customers/search.json?query=${q}`);
  return (cs.customers || [])[0] || null;
}

async function setCustomerTags(customerId, tagsArray) {
  const tags = [...new Set(tagsArray.map(t => t.trim()).filter(Boolean))].join(", ");
  await api(`/customers/${customerId}.json`, {
    method: "PUT",
    body: { customer: { id: customerId, tags } }
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
  const existing = (metas.metafields || []).find(m => m.key === key);

  if (existing) {
    await api(`/metafields/${existing.id}.json`, {
      method: "PUT",
      body: { metafield: { id: existing.id, value, type } }
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
          value
        }
      }
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
  // nunca deixar cachear
  res.set({
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Surrogate-Control": "no-store",
    "Vary": "Origin"
  });

  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    const cnpj  = onlyDigits(String(req.query.cnpj || ""));

    if (!email || cnpj.length !== 14)
      return res.status(400).json({ ok: false, exists: false });

    const customer = await findCustomerByEmail(email);
    if (!customer) return res.json({ ok: true, exists: false });

    const metas = await api(`/customers/${customer.id}/metafields.json?namespace=custom`);
    const mfCnpjField   = (metas.metafields || []).find(m => m.key?.toLowerCase() === "cnpj" || m.key?.toLowerCase() === "cjnpj");
    const mfStatusField = (metas.metafields || []).find(m => m.key?.toLowerCase() === "cnpj_status");

    const mfCnpj = mfCnpjField ? String(mfCnpjField.value || "") : "";
    const cnpj_status = (mfStatusField ? String(mfStatusField.value || "") : "").toLowerCase();
    const cnpj_match  = onlyDigits(mfCnpj) === cnpj;

    const hasApprovedTag = (customer.tags || "").split(",").map(t => t.trim()).includes("b2b-approved");
    const approved = hasApprovedTag && cnpj_status === "approved";

    res.json({ ok: true, exists: true, cnpj_match, approved, cnpj_status });
  } catch (e) {
    console.error("validate-login error:", e);
    res.status(500).json({ ok: false, exists: false });
  }
});

/* ======== Public: registrar CNPJ ======== */
app.post("/register-cnpj", async (req, res) => {
  // nunca deixar cachear
  res.set({
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Origin"
  });

  try {
    const { email, cnpj } = req.body || {};
    const mail = String(email || "").trim().toLowerCase();
    const num  = onlyDigits(cnpj || "");

    if (!mail || num.length !== 14) {
      return res.status(400).json({ ok: false, error: "invalid_params" });
    }

    // Pequenos retries porque o cliente acabou de ser criado na vitrine
    let customer = null;
    for (let i = 0; i < 6; i++) {
      customer = await findCustomerByEmail(mail);
      if (customer) break;
      await sleep(600);
    }
    if (!customer) return res.status(404).json({ ok: false, error: "customer_not_found" });

    // Grava metafields
    await upsertCustomerMetafield(customer.id, "cnpj", num);
    await upsertCustomerMetafield(customer.id, "cnpj_status", "pending");

    // (Opcional) marca tag de pendência
    const tags = (customer.tags || "").split(",").map(t => t.trim()).filter(Boolean);
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

/* ======== Admin: aprovar / reprovar ======== */
app.post("/admin/approve", async (req, res) => {
  if (!guard(req, res)) return;
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: "missing email" });

    const c = await findCustomerByEmail(email);
    if (!c) return res.json({ ok: true, found: false });

    const currentTags = (c.tags || "").split(",").map(t => t.trim()).filter(Boolean);
    if (!currentTags.includes("b2b-approved")) currentTags.push("b2b-approved");
    const tags = currentTags.filter(t => t !== "b2b-pending");

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

    const currentTags = (c.tags || "").split(",").map(t => t.trim()).filter(Boolean);
    const tags = currentTags.filter(t => t !== "b2b-approved");

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
app.listen(process.env.PORT || 3000, () =>
  console.log("B2B API up")
);
