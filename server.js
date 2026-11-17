const express = require("express");
const path = require("path");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const COOKIE = "an_admin_session";
const ADMIN_PAGE = path.join(__dirname, "private", "admin.html");

// Railway injecte DATABASE_URL dans les variables du service applicatif.
// Ne jamais placer cette URL dans le frontend.
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: false,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    })
  : null;

if (pool) {
  pool.on("error", (error) => {
    console.error("Erreur PostgreSQL inattendue:", error.message);
  });
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
const smallJson = express.json({ limit: "20kb" });
const bigJson = express.json({ limit: "12mb" });
app.use((req, res, next) => {
  if (req.method === "POST" && req.path === "/api/admin/products") return bigJson(req, res, next);
  return smallJson(req, res, next);
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function safeEqual(a, b) {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function key() {
  return process.env.SESSION_SECRET || process.env.ADMIN_PASSWORD || "";
}
function signature(payload) {
  return crypto.createHmac("sha256", key()).update(payload).digest("base64url");
}
function newToken() {
  const payload = Buffer.from(JSON.stringify({
    role: "admin",
    exp: Date.now() + 8 * 60 * 60 * 1000,
    nonce: crypto.randomBytes(16).toString("hex")
  })).toString("base64url");
  return payload + "." + signature(payload);
}
function isAdmin(req) {
  const raw = req.headers.cookie || "";
  const item = raw.split(";").map(x => x.trim()).find(x => x.startsWith(COOKIE + "="));
  if (!item || !key()) return false;
  const token = decodeURIComponent(item.slice(COOKIE.length + 1));
  const parts = token.split(".");
  if (parts.length !== 2 || !safeEqual(parts[1], signature(parts[0]))) return false;
  try {
    const data = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    return data.role === "admin" && data.exp > Date.now();
  } catch {
    return false;
  }
}
function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(401).json({ error: "Accès administrateur requis." });
  next();
}

app.post("/api/admin/login", limiter, (req, res) => {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (!adminEmail || !adminPassword) {
    return res.status(503).json({ error: "Les identifiants admin ne sont pas configurés sur le serveur." });
  }
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!safeEqual(email, adminEmail.trim().toLowerCase()) || !safeEqual(password, adminPassword)) {
    return res.status(401).json({ error: "Adresse e-mail ou mot de passe incorrect." });
  }
  res.cookie(COOKIE, newToken(), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 8 * 60 * 60 * 1000
  });
  res.json({ ok: true, redirect: "/admin" });
});

app.get("/api/admin/session", requireAdmin, (_req, res) => {
  res.json({ authenticated: true, role: "admin" });
});
app.post("/api/admin/logout", requireAdmin, (_req, res) => {
  res.clearCookie(COOKIE, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/"
  });
  res.json({ ok: true });
});
// Endpoint de vérification PostgreSQL. Il ne révèle aucune information de connexion.
app.get("/api/health/database", async (_req, res) => {
  if (!pool) {
    return res.status(503).json({
      connected: false,
      error: "La variable DATABASE_URL n'est pas configurée."
    });
  }

  try {
    await pool.query("SELECT 1");
    return res.json({ connected: true, database: "PostgreSQL" });
  } catch (error) {
    console.error("Échec du test PostgreSQL:", error.message);
    return res.status(503).json({
      connected: false,
      error: "Impossible de joindre la base PostgreSQL."
    });
  }
});

let tableReady = null;
function ensureProducts() {
  if (!tableReady) {
    tableReady = pool.query(`CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      price NUMERIC(12,2) NOT NULL,
      sale_price NUMERIC(12,2),
      category TEXT NOT NULL DEFAULT '',
      stock INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      images JSONB NOT NULL DEFAULT '[]',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`).catch((e) => { tableReady = null; throw e; });
  }
  return tableReady;
}
function dbDown(res, error) {
  console.error("Erreur produits:", error.message);
  return res.status(503).json({ error: "La base de données n'est pas accessible." });
}

app.get("/api/admin/products", requireAdmin, async (_req, res) => {
  if (!pool) return res.status(503).json({ error: "La variable DATABASE_URL n'est pas configurée." });
  try {
    await ensureProducts();
    const r = await pool.query("SELECT * FROM products ORDER BY id DESC");
    res.json({ products: r.rows });
  } catch (e) { dbDown(res, e); }
});

app.post("/api/admin/products", requireAdmin, async (req, res) => {
  if (!pool) return res.status(503).json({ error: "La variable DATABASE_URL n'est pas configurée." });
  const b = req.body || {};
  const name = String(b.name || "").trim().slice(0, 200);
  const price = Number(b.price);
  const sale = b.sale_price === "" || b.sale_price == null ? null : Number(b.sale_price);
  const stock = Number.isInteger(Number(b.stock)) ? Number(b.stock) : 0;
  const images = Array.isArray(b.images) ? b.images.filter((x) => typeof x === "string" && x.startsWith("data:image/")).slice(0, 8) : [];
  if (!name) return res.status(400).json({ error: "Le nom du produit est obligatoire." });
  if (!Number.isFinite(price) || price < 0) return res.status(400).json({ error: "Prix invalide." });
  if (sale !== null && (!Number.isFinite(sale) || sale < 0)) return res.status(400).json({ error: "Prix promotionnel invalide." });
  try {
    await ensureProducts();
    const r = await pool.query(
      "INSERT INTO products (name, price, sale_price, category, stock, images) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
      [name, price, sale, String(b.category || "").trim().slice(0, 100), stock, JSON.stringify(images)]
    );
    res.status(201).json({ ok: true, id: r.rows[0].id });
  } catch (e) { dbDown(res, e); }
});

app.delete("/api/admin/products/:id", requireAdmin, async (req, res) => {
  if (!pool) return res.status(503).json({ error: "La variable DATABASE_URL n'est pas configurée." });
  try {
    await ensureProducts();
    await pool.query("DELETE FROM products WHERE id = $1", [parseInt(req.params.id, 10) || 0]);
    res.json({ ok: true });
  } catch (e) { dbDown(res, e); }
});

app.get("/api/admin/:section", requireAdmin, async (req, res) => {
  const allowed = ["overview", "orders", "products", "customers", "discounts"];
  if (!allowed.includes(req.params.section)) return res.sendStatus(404);

  if (!pool) {
    return res.status(503).json({
      ready: false,
      section: req.params.section,
      error: "La variable DATABASE_URL n'est pas configurée."
    });
  }

  try {
    await pool.query("SELECT 1");
    return res.status(501).json({
      ready: false,
      databaseConnected: true,
      section: req.params.section,
      error: "PostgreSQL est connecté. Les fonctions de données de cette section restent à développer."
    });
  } catch (error) {
    console.error("Erreur PostgreSQL dans la section admin:", error.message);
    return res.status(503).json({
      ready: false,
      databaseConnected: false,
      section: req.params.section,
      error: "La base PostgreSQL n'est pas accessible."
    });
  }
});

// The admin HTML is outside the public static directory and is served only to an authenticated admin.
app.get("/admin", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/?admin=login");
  res.set("Cache-Control", "no-store");
  res.sendFile(ADMIN_PAGE);
});
app.use("/private", (_req, res) => res.sendStatus(404));
app.use(express.static(__dirname, { index: "index.html", dotfiles: "ignore" }));

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log("A&N Boutique server listening on port " + PORT);
});

async function shutdown() {
  server.close(async () => {
    if (pool) await pool.end();
    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
