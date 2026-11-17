const express = require("express");
const path = require("path");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;
const COOKIE = "an_admin_session";
const ADMIN_PAGE = path.join(__dirname, "private", "admin.html");

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));

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
app.get("/api/admin/:section", requireAdmin, (req, res) => {
  const allowed = ["overview", "orders", "products", "customers", "discounts"];
  if (!allowed.includes(req.params.section)) return res.sendStatus(404);
  res.status(503).json({
    ready: false,
    section: req.params.section,
    error: "La connexion à Supabase reste à configurer."
  });
});

// The admin HTML is outside the public static directory and is served only to an authenticated admin.
app.get("/admin", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/?admin=login");
  res.set("Cache-Control", "no-store");
  res.sendFile(ADMIN_PAGE);
});
app.use("/private", (_req, res) => res.sendStatus(404));
app.use(express.static(__dirname, { index: "index.html", dotfiles: "ignore" }));

app.listen(PORT, "0.0.0.0", () => {
  console.log("A&N Boutique server listening on port " + PORT);
});
