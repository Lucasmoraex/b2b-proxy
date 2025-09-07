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

/* ======== Helpers de cliente/metafield/tags ======== */
async function findCustomerByEmail(email) {
  const q = encodeURIComponent(`email:${email}`);
  const cs = await api(`/customers/search.json?query=${q}`);
  return (cs.customers || [])[0] || null;
}

async function setCustomerTags(customerId, tagsArray) {
  // Shopify REST espera string separada por vírgula
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
// GET /validate-login?email=...&cnpj=...
app.get("/validate-login", async (req, res) => {
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    const cnpj  = onlyDigits(String(req.query.cnpj || ""));

    if (!email || cnpj.length !== 14)
      return res.status(400).json({ ok: false, exists: false });

    // 1) busca cliente por e-mail
    const customer = await findCustomerByEmail(email);
    if (!customer) return res.json({ ok: true, exists: false });

    // 2) compara metafield custom.cnpj
    const metas = await api(`/customers/${customer.id}/metafields.json?namespace=custom`);
    const mf = (metas.metafields || []).find(m => {
      const key = String(m.key || "").toLowerCase();
      const ns  = String(m.namespace || "").toLowerCase();
      return ns === "custom" && (key === "cnpj" || key === "cjnpj"); // aceita o antigo cjnpj também
    });
    const mfCnpj = mf ? String(mf.value || "") : "";
    const cnpj_match = onlyDigits(mfCnpj) === cnpj;

    // 3) tag de aprovação
    const approved = (customer.tags || "")
      .split(",")
      .map(t => t.trim())
      .includes("b2b-approved");

    res.json({ ok: true, exists: true, cnpj_match, approved });
  } catch (e) {
    console.error("validate-login error:", e);
    res.status(500).json({ ok: false, exists: false });
  }
});

/* ======== Admin: aprovar / reprovar ======== */
// POST /admin/approve?email=...
app.post("/admin/approve", async (req, res) => {
  if (!guard(req, res)) return;
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: "missing email" });

    const c = await findCustomerByEmail(email);
    if (!c) return res.json({ ok: true, found: false });

    const currentTags = (c.tags || "").split(",").map(t => t.trim()).filter(Boolean);
    if (!currentTags.includes("b2b-approved")) currentTags.push("b2b-approved");
    const tags = currentTags.filter(t => t !== "b2b-pending"); // remove pending se existir

    await setCustomerTags(c.id, tags);
    await upsertCustomerMetafield(c.id, "cnpj_status", "approved");

    res.json({ ok: true, found: true, tags, cnpj_status: "approved" });
  } catch (e) {
    console.error("approve error:", e);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

// GET helper para testar no navegador
app.get("/admin/approve", (req, res) => app._router.handle(
  { ...req, method: "POST" }, res
));

// POST /admin/reject?email=...
app.post("/admin/reject", async (req, res) => {
  if (!guard(req, res)) return;
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: "missing email" });

    const c = await findCustomerByEmail(email);
    if (!c) return res.json({ ok: true, found: false });

    const currentTags = (c.tags || "").split(",").map(t => t.trim()).filter(Boolean);
    const tags = currentTags.filter(t => t !== "b2b-approved"); // remove aprovação

    await setCustomerTags(c.id, tags);
    await upsertCustomerMetafield(c.id, "cnpj_status", "rejected");

    res.json({ ok: true, found: true, tags, cnpj_status: "rejected" });
  } catch (e) {
    console.error("reject error:", e);
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

// GET helper para testar no navegador
app.get("/admin/reject", (req, res) => app._router.handle(
  { ...req, method: "POST" }, res
));

/* ======== Root ======== */
app.get("/", (_, res) => res.send("ok"));

/* ======== Start ======== */
app.listen(process.env.PORT || 3000, () =>
  console.log("B2B API up")
);
